//! The agent itself: identity bookkeeping, request handling and the unix
//! socket server.

use super::wire::{self, Request};
use crate::challenge::ChallengeSink;
use crate::device::{DeviceError, OnlyKey};
use crate::identity::KeySpec;
use crate::keys;
use crate::transport::HidTransport;
use nix::sys::stat::{Mode, umask};
use sha2::{Digest, Sha256};
use ssh_key::HashAlg;
use ssh_key::PublicKey;
use std::collections::HashMap;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use thiserror::Error;

/// A device the agent can open on demand.
pub type Device = OnlyKey<Box<dyn HidTransport>>;
/// How the agent obtains a device for each operation.
pub type Opener = Arc<dyn Fn() -> Result<Device, DeviceError> + Send + Sync>;

#[derive(Debug, Error)]
pub enum AgentError {
    #[error(transparent)]
    Device(#[from] DeviceError),
    #[error(transparent)]
    Key(#[from] keys::KeyError),
    #[error("requested key is not served by this agent")]
    UnknownKey,
    #[error(
        "client asked for an ssh-rsa (SHA-1) signature, which the OnlyKey cannot produce; it must request rsa-sha2-256 or rsa-sha2-512"
    )]
    Sha1Requested,
    #[error(transparent)]
    Wire(#[from] wire::WireError),
}

/// Agent state shared between connections. Each [`KeySpec`] it serves is
/// one identity in the SSH sense.
pub struct Agent {
    entries: Vec<KeySpec>,
    opener: Opener,
    sink: Arc<dyn ChallengeSink>,
    /// Serialises every device operation, including the wait for the user.
    device_lock: Mutex<()>,
    cache: Mutex<HashMap<KeySpec, PublicKey>>,
    /// `ssh-add -x` state: a salted hash of the passphrase while locked.
    passphrase_lock: Mutex<Option<PassphraseHash>>,
}

/// A salted SHA-256 of the lock passphrase, so the passphrase itself is not
/// kept in memory. Compared in constant time.
struct PassphraseHash {
    salt: [u8; 16],
    digest: [u8; 32],
}

impl PassphraseHash {
    fn new(passphrase: &[u8]) -> Self {
        let mut salt = [0u8; 16];
        let mut file = std::fs::File::open("/dev/urandom").expect("/dev/urandom");
        std::io::Read::read_exact(&mut file, &mut salt).expect("random salt");
        let digest = Self::digest(&salt, passphrase);
        PassphraseHash { salt, digest }
    }

    fn digest(salt: &[u8; 16], passphrase: &[u8]) -> [u8; 32] {
        Sha256::new()
            .chain_update(salt)
            .chain_update(passphrase)
            .finalize()
            .into()
    }

    fn matches(&self, passphrase: &[u8]) -> bool {
        let candidate = Self::digest(&self.salt, passphrase);
        self.digest
            .iter()
            .zip(candidate.iter())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0
    }
}

impl Agent {
    pub fn new(entries: Vec<KeySpec>, opener: Opener, sink: Arc<dyn ChallengeSink>) -> Self {
        Agent {
            entries,
            opener,
            sink,
            device_lock: Mutex::new(()),
            cache: Mutex::new(HashMap::new()),
            passphrase_lock: Mutex::new(None),
        }
    }

    /// Whether `ssh-add -x` has locked the agent.
    pub fn is_locked(&self) -> bool {
        self.passphrase_lock
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .is_some()
    }

    /// Lock with `passphrase`; fails if already locked, as in OpenSSH.
    pub fn lock(&self, passphrase: &[u8]) -> bool {
        let mut lock = self
            .passphrase_lock
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if lock.is_some() {
            return false;
        }
        *lock = Some(PassphraseHash::new(passphrase));
        true
    }

    /// Unlock if `passphrase` is the one the agent was locked with.
    pub fn unlock(&self, passphrase: &[u8]) -> bool {
        let mut lock = self
            .passphrase_lock
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        match lock.as_ref() {
            Some(hash) if hash.matches(passphrase) => {
                *lock = None;
                true
            }
            _ => false,
        }
    }

    pub fn entries(&self) -> &[KeySpec] {
        &self.entries
    }

    /// Seed the key cache from previously exported public keys, matched by
    /// their comment (see [`KeySpec::label`]). Returns how many matched.
    pub fn preload(&self, keys: impl IntoIterator<Item = PublicKey>) -> usize {
        let mut cache = self.cache.lock().unwrap_or_else(|p| p.into_inner());
        let mut matched = 0;
        for key in keys {
            if let Some(entry) = self.entries.iter().find(|e| e.label() == key.comment())
                && key.algorithm() == entry.kind.public_algorithm()
            {
                cache.insert(entry.clone(), key);
                matched += 1;
            }
        }
        matched
    }

    /// Public keys for every entry, fetching any that are not cached yet.
    ///
    /// Entries whose key cannot be fetched (device absent or locked, empty
    /// slot, wrong curve) are skipped with a warning so the client still sees
    /// the rest.
    pub fn public_keys(&self) -> Vec<PublicKey> {
        let missing: Vec<KeySpec> = {
            let cache = self.cache.lock().unwrap_or_else(|p| p.into_inner());
            self.entries
                .iter()
                .filter(|e| !cache.contains_key(*e))
                .cloned()
                .collect()
        };
        if !missing.is_empty() {
            let _guard = self.device_lock.lock().unwrap_or_else(|p| p.into_inner());
            match (self.opener)() {
                Ok(mut device) => {
                    for entry in &missing {
                        match self.derive(&mut device, entry) {
                            Ok(key) => {
                                self.cache
                                    .lock()
                                    .unwrap_or_else(|p| p.into_inner())
                                    .insert(entry.clone(), key);
                            }
                            Err(e) => {
                                tracing::warn!(identity = %entry.identity, key = %entry.kind, error = %e, "cannot get public key")
                            }
                        }
                    }
                }
                Err(e) => tracing::warn!(error = %e, "cannot open OnlyKey to get public keys"),
            }
        }
        let cache = self.cache.lock().unwrap_or_else(|p| p.into_inner());
        self.entries
            .iter()
            .filter_map(|e| cache.get(e).cloned())
            .collect()
    }

    /// Fetch every key now; fails on the first problem. Used by commands that
    /// need all keys up front.
    pub fn derive_all(&self) -> Result<Vec<PublicKey>, AgentError> {
        let _guard = self.device_lock.lock().unwrap_or_else(|p| p.into_inner());
        let mut device = None;
        let mut out = Vec::with_capacity(self.entries.len());
        for entry in &self.entries {
            let cached = self
                .cache
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .get(entry)
                .cloned();
            let key = match cached {
                Some(key) => key,
                None => {
                    if device.is_none() {
                        device = Some((self.opener)()?);
                    }
                    let key = self.derive(device.as_mut().expect("just opened"), entry)?;
                    self.cache
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .insert(entry.clone(), key.clone());
                    key
                }
            };
            out.push(key);
        }
        Ok(out)
    }

    /// Fetch one key now; fails if the device is unavailable. Used by
    /// commands that need a single key up front.
    pub fn derive_one(&self, entry: &KeySpec) -> Result<PublicKey, AgentError> {
        let cached = self
            .cache
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(entry)
            .cloned();
        if let Some(key) = cached {
            return Ok(key);
        }
        let _guard = self.device_lock.lock().unwrap_or_else(|p| p.into_inner());
        let mut device = (self.opener)()?;
        let key = self.derive(&mut device, entry)?;
        self.cache
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(entry.clone(), key.clone());
        Ok(key)
    }

    fn derive(&self, device: &mut Device, entry: &KeySpec) -> Result<PublicKey, AgentError> {
        Ok(device.ssh_public_key(entry)?)
    }

    /// Handle one request body and produce the reply body.
    pub fn handle(&self, body: &[u8]) -> Vec<u8> {
        match wire::parse_request(body) {
            Ok(Request::RequestIdentities) if self.is_locked() => {
                tracing::debug!("listing identities: agent is locked, none");
                wire::identities_answer(&[])
            }
            Ok(Request::RequestIdentities) => {
                let keys = self.public_keys();
                tracing::debug!(count = keys.len(), "listing identities");
                wire::identities_answer(&keys)
            }
            Ok(Request::Sign { .. }) if self.is_locked() => {
                tracing::warn!("sign request refused: agent is locked");
                wire::failure()
            }
            Ok(Request::Sign {
                key_blob,
                data,
                flags,
            }) => {
                tracing::debug!(len = data.len(), flags, "sign request");
                match self.sign(&key_blob, &data, flags) {
                    Ok(reply) => reply,
                    Err(e) => {
                        tracing::warn!(error = %e, "sign request failed");
                        wire::failure()
                    }
                }
            }
            Ok(Request::Lock(passphrase)) => {
                if self.lock(&passphrase) {
                    tracing::info!("agent locked");
                    wire::success()
                } else {
                    tracing::warn!("lock request refused: already locked");
                    wire::failure()
                }
            }
            Ok(Request::Unlock(passphrase)) => {
                if self.unlock(&passphrase) {
                    tracing::info!("agent unlocked");
                    wire::success()
                } else {
                    tracing::warn!("unlock request refused: not locked or wrong passphrase");
                    wire::failure()
                }
            }
            Ok(Request::RequestRsaIdentities) => {
                tracing::debug!("SSH v1 identities request: answering with none");
                wire::rsa_identities_answer()
            }
            Ok(Request::Extension) => {
                tracing::debug!("extension request: none supported");
                wire::extension_failure()
            }
            Ok(Request::Unsupported(kind)) => {
                tracing::debug!(kind, "unsupported request");
                wire::failure()
            }
            Err(e) => {
                tracing::warn!(error = %e, "bad request");
                wire::failure()
            }
        }
    }

    fn sign(&self, key_blob: &[u8], data: &[u8], flags: u32) -> Result<Vec<u8>, AgentError> {
        let (entry, key) = self.lookup(key_blob)?;
        let hash = match wire::rsa_hash(flags) {
            Some(hash) => hash,
            None if entry.kind.is_rsa() => return Err(AgentError::Sha1Requested),
            None => HashAlg::default(),
        };
        let subject = wire::describe_data(data);
        let _guard = self.device_lock.lock().unwrap_or_else(|p| p.into_inner());
        let mut device = (self.opener)()?;
        let raw = device.sign(&entry, data, hash, subject, self.sink.as_ref())?;
        drop(device);
        let sig = keys::signature(&entry.kind.signature_algorithm(hash), &raw)?;
        keys::verify(&key, data, &sig)?;
        tracing::info!(identity = %entry.identity, key = %entry.kind, algorithm = %sig.algorithm(), "signed");
        Ok(wire::sign_response(&sig))
    }

    fn lookup(&self, key_blob: &[u8]) -> Result<(KeySpec, PublicKey), AgentError> {
        let cache = self.cache.lock().unwrap_or_else(|p| p.into_inner());
        cache
            .iter()
            .find(|(_, key)| key.to_bytes().map(|b| b == key_blob).unwrap_or(false))
            .map(|(entry, key)| (entry.clone(), key.clone()))
            .ok_or(AgentError::UnknownKey)
    }
}

/// Serve one client connection until it closes.
pub fn handle_connection(agent: &Agent, mut stream: UnixStream) {
    let _ = stream.set_nonblocking(false);
    let mut reader = match stream.try_clone() {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "cannot clone stream");
            return;
        }
    };
    loop {
        let body = match wire::read_frame(&mut reader) {
            Ok(Some(body)) => body,
            Ok(None) => return,
            Err(e) => {
                tracing::debug!(error = %e, "connection closed");
                return;
            }
        };
        let reply = agent.handle(&body);
        if let Err(e) = wire::write_frame(&mut stream, &reply) {
            tracing::debug!(error = %e, "cannot write reply");
            return;
        }
    }
}

/// Accept connections until `shutdown` is set. Each connection runs on its
/// own thread.
pub fn serve(
    listener: UnixListener,
    agent: Arc<Agent>,
    shutdown: Arc<AtomicBool>,
) -> io::Result<()> {
    listener.set_nonblocking(true)?;
    while !shutdown.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _)) => {
                let agent = Arc::clone(&agent);
                std::thread::spawn(move || handle_connection(&agent, stream));
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum SocketError {
    #[error("an agent is already listening on {0}")]
    AlreadyRunning(PathBuf),
    #[error("cannot create socket directory {path}: {source}")]
    Directory { path: PathBuf, source: io::Error },
    #[error("cannot bind {path}: {source}")]
    Bind { path: PathBuf, source: io::Error },
}

/// Removes the socket file when dropped.
pub struct SocketGuard(PathBuf);

impl SocketGuard {
    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for SocketGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Create the listening socket with owner-only permissions.
///
/// A stale socket file is replaced; a live one is an error.
pub fn bind_socket(path: &Path) -> Result<(UnixListener, SocketGuard), SocketError> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|source| SocketError::Directory {
            path: dir.to_owned(),
            source,
        })?;
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    }
    if path.exists() {
        match UnixStream::connect(path) {
            Ok(_) => return Err(SocketError::AlreadyRunning(path.to_owned())),
            Err(_) => {
                let _ = std::fs::remove_file(path);
            }
        }
    }
    let previous = umask(Mode::from_bits_truncate(0o077));
    let bound = UnixListener::bind(path);
    umask(previous);
    let listener = bound.map_err(|source| SocketError::Bind {
        path: path.to_owned(),
        source,
    })?;
    Ok((listener, SocketGuard(path.to_owned())))
}

/// Where the agent listens by default: `$XDG_RUNTIME_DIR/okagent/agent.sock`,
/// else `$TMPDIR/okagent/agent.sock` on macOS, else
/// `/tmp/okagent-<uid>/agent.sock`.
pub fn default_socket_path() -> PathBuf {
    runtime_dir().join("agent.sock")
}

/// A fresh per-process socket path for `run`-style invocations.
pub fn ephemeral_socket_path() -> PathBuf {
    runtime_dir().join(format!("run-{}.sock", std::process::id()))
}

fn runtime_dir() -> PathBuf {
    let var = |name| std::env::var_os(name).filter(|dir| !dir.is_empty());
    if let Some(dir) = var("XDG_RUNTIME_DIR") {
        return PathBuf::from(dir).join("okagent");
    }
    // macOS gives each user a private $TMPDIR, while /tmp is shared.
    if cfg!(target_os = "macos")
        && let Some(dir) = var("TMPDIR")
    {
        return PathBuf::from(dir).join("okagent");
    }
    PathBuf::from(format!("/tmp/okagent-{}", nix::unistd::getuid()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::challenge::RecordingSink;
    use crate::device::Timeouts;
    use crate::identity::{Curve, EccSlot};
    use crate::protocol::{self, Report};
    use crate::transport::fake::{ScriptedTransport, Step};
    use ssh_encoding::Decode;

    fn text(s: &str) -> Report {
        let mut r = [0u8; 64];
        r[..s.len()].copy_from_slice(s.as_bytes());
        r
    }

    fn fast() -> Timeouts {
        Timeouts {
            connect: Duration::from_millis(10),
            connect_retry: Duration::from_millis(1),
            poll: Duration::from_millis(1),
            status: Duration::from_millis(50),
            pubkey: Duration::from_millis(50),
            sign: Duration::from_millis(50),
            gap: Duration::from_millis(20),
        }
    }

    fn opener_with(steps: Vec<Step>) -> Opener {
        let steps = Mutex::new(Some(steps));
        Arc::new(move || {
            let steps = steps.lock().unwrap().take().expect("device opened once");
            let transport: Box<dyn HidTransport> = Box::new(ScriptedTransport::new(steps));
            OnlyKey::handshake(transport, fast(), 1)
        })
    }

    fn entry() -> KeySpec {
        KeySpec::derived("james@example.com".parse().unwrap(), Curve::Ed25519)
    }

    fn stored_entry() -> KeySpec {
        KeySpec::stored(
            "james@example.com".parse().unwrap(),
            Curve::Ed25519,
            EccSlot::new(3).unwrap(),
        )
    }

    #[test]
    fn lists_identities_after_deriving_once() {
        let e = entry();
        let mut key_report = [0u8; 64];
        key_report[..32].copy_from_slice(&[0x11; 32]);
        let opener = opener_with(vec![
            Step::ExpectWrite(protocol::settime_report(1)),
            Step::Reply(text("UNLOCKEDv3.0.4-prodc")),
            Step::ExpectWrite(protocol::getpubkey_report(
                132,
                0x01,
                &e.identity.derivation_hash(),
            )),
            Step::Reply(key_report),
        ]);
        let agent = Agent::new(vec![e.clone()], opener, Arc::new(RecordingSink::default()));
        let reply = agent.handle(&[wire::SSH2_AGENTC_REQUEST_IDENTITIES]);
        assert_eq!(reply[0], wire::SSH2_AGENT_IDENTITIES_ANSWER);
        let mut r = &reply[5..];
        let blob = Vec::<u8>::decode(&mut r).unwrap();
        let key = PublicKey::from_bytes(&blob).unwrap();
        assert_eq!(key.key_data().ed25519().unwrap().0, [0x11; 32]);
        assert_eq!(String::decode(&mut r).unwrap(), e.label());
        // Second listing is served from the cache: the opener would panic otherwise.
        assert_eq!(agent.handle(&[wire::SSH2_AGENTC_REQUEST_IDENTITIES]), reply);
    }

    #[test]
    fn derive_one_uses_cache_after_first_fetch() {
        let e = entry();
        let mut key_report = [0u8; 64];
        key_report[..32].copy_from_slice(&[0x11; 32]);
        let opener = opener_with(vec![
            Step::ExpectWrite(protocol::settime_report(1)),
            Step::Reply(text("UNLOCKEDv3.0.4-prodc")),
            Step::ExpectWrite(protocol::getpubkey_report(
                132,
                0x01,
                &e.identity.derivation_hash(),
            )),
            Step::Reply(key_report),
        ]);
        let agent = Agent::new(vec![e.clone()], opener, Arc::new(RecordingSink::default()));
        let key = agent.derive_one(&e).unwrap();
        assert_eq!(key.key_data().ed25519().unwrap().0, [0x11; 32]);
        // The opener would panic on a second call.
        assert_eq!(agent.derive_one(&e).unwrap(), key);
    }

    #[test]
    fn missing_device_yields_empty_list_not_failure() {
        let opener: Opener = Arc::new(|| Err(DeviceError::Locked));
        let agent = Agent::new(vec![entry()], opener, Arc::new(RecordingSink::default()));
        assert_eq!(
            agent.handle(&[wire::SSH2_AGENTC_REQUEST_IDENTITIES]),
            vec![12, 0, 0, 0, 0]
        );
    }

    #[test]
    fn preload_matches_by_comment_and_curve() {
        let e = entry();
        let opener: Opener = Arc::new(|| panic!("device must not be opened"));
        let agent = Agent::new(vec![e.clone()], opener, Arc::new(RecordingSink::default()));
        let raw = protocol::RawPublicKey::Ed25519([0x22; 32]);
        let wrong = keys::public_key(&raw, "<ssh://other@example.com|ed25519>").unwrap();
        let right = keys::public_key(&raw, &e.label()).unwrap();
        assert_eq!(agent.preload([wrong, right]), 1);
        assert_eq!(agent.public_keys().len(), 1);
    }

    #[test]
    fn stored_and_derived_keys_for_one_identity_stay_apart() {
        let derived = entry();
        let stored = stored_entry();
        let mut derived_report = [0u8; 64];
        derived_report[..32].copy_from_slice(&[0x11; 32]);
        let mut stored_report = [0u8; 64];
        stored_report[..32].copy_from_slice(&[0x33; 32]);
        let hash = derived.identity.derivation_hash();
        let opener = opener_with(vec![
            Step::ExpectWrite(protocol::settime_report(1)),
            Step::Reply(text("UNLOCKEDv3.0.4-prodc")),
            Step::ExpectWrite(protocol::getpubkey_report(132, 0x01, &hash)),
            Step::Reply(derived_report),
            Step::ExpectWrite(protocol::getpubkey_report(103, 0x01, &hash)),
            Step::Reply(stored_report),
        ]);
        let agent = Agent::new(
            vec![derived.clone(), stored.clone()],
            opener,
            Arc::new(RecordingSink::default()),
        );
        let keys = agent.public_keys();
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0].comment(), "<ssh://james@example.com|ed25519>");
        assert_eq!(keys[0].key_data().ed25519().unwrap().0, [0x11; 32]);
        assert_eq!(keys[1].comment(), "<ssh://james@example.com|ed25519|ECC3>");
        assert_eq!(keys[1].key_data().ed25519().unwrap().0, [0x33; 32]);

        // Preloading from a file keeps the two apart by their comments.
        let opener: Opener = Arc::new(|| panic!("device must not be opened"));
        let agent = Agent::new(
            vec![derived, stored],
            opener,
            Arc::new(RecordingSink::default()),
        );
        assert_eq!(agent.preload(keys.clone()), 2);
        assert_eq!(agent.public_keys(), keys);
    }

    #[test]
    fn unknown_key_and_unsupported_requests_fail_cleanly() {
        let opener: Opener = Arc::new(|| panic!("device must not be opened"));
        let agent = Agent::new(vec![entry()], opener, Arc::new(RecordingSink::default()));
        let mut body = vec![wire::SSH2_AGENTC_SIGN_REQUEST];
        b"nokey".as_slice().encode(&mut body).unwrap();
        b"data".as_slice().encode(&mut body).unwrap();
        0u32.encode(&mut body).unwrap();
        assert_eq!(agent.handle(&body), wire::failure());
        assert_eq!(agent.handle(&[17]), wire::failure());
        assert_eq!(agent.handle(&[27]), wire::extension_failure());
        assert_eq!(agent.handle(&[1]), wire::rsa_identities_answer());
        assert_eq!(agent.handle(&[]), wire::failure());
    }

    #[test]
    fn lock_hides_keys_and_refuses_signing_until_unlocked() {
        let e = entry();
        let opener: Opener = Arc::new(|| panic!("device must not be opened"));
        let agent = Agent::new(vec![e.clone()], opener, Arc::new(RecordingSink::default()));
        let raw = protocol::RawPublicKey::Ed25519([0x22; 32]);
        let key = keys::public_key(&raw, &e.label()).unwrap();
        assert_eq!(agent.preload([key.clone()]), 1);

        let mut lock = vec![wire::SSH_AGENTC_LOCK];
        b"hunter2".as_slice().encode(&mut lock).unwrap();
        assert_eq!(agent.handle(&lock), wire::success());
        assert!(agent.is_locked());
        // Locking twice fails, as in OpenSSH.
        assert_eq!(agent.handle(&lock), wire::failure());
        assert_eq!(
            agent.handle(&[wire::SSH2_AGENTC_REQUEST_IDENTITIES]),
            vec![12, 0, 0, 0, 0]
        );
        let mut sign = vec![wire::SSH2_AGENTC_SIGN_REQUEST];
        key.to_bytes().unwrap().encode(&mut sign).unwrap();
        b"data".as_slice().encode(&mut sign).unwrap();
        0u32.encode(&mut sign).unwrap();
        assert_eq!(agent.handle(&sign), wire::failure());

        let mut wrong = vec![wire::SSH_AGENTC_UNLOCK];
        b"hunter3".as_slice().encode(&mut wrong).unwrap();
        assert_eq!(agent.handle(&wrong), wire::failure());
        assert!(agent.is_locked());
        let mut unlock = vec![wire::SSH_AGENTC_UNLOCK];
        b"hunter2".as_slice().encode(&mut unlock).unwrap();
        assert_eq!(agent.handle(&unlock), wire::success());
        assert!(!agent.is_locked());
        // Unlocking an unlocked agent fails.
        assert_eq!(agent.handle(&unlock), wire::failure());
        assert_eq!(agent.public_keys(), vec![key]);
    }

    #[test]
    fn socket_guard_creates_and_removes_socket() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub").join("agent.sock");
        let (listener, guard) = bind_socket(&path).unwrap();
        assert!(path.exists());
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0, "socket mode {mode:o} is not owner-only");
        assert!(matches!(
            bind_socket(&path),
            Err(SocketError::AlreadyRunning(_))
        ));
        drop(listener);
        drop(guard);
        assert!(!path.exists());
        // A stale file is replaced.
        std::fs::write(&path, b"").unwrap();
        let (_l, _g) = bind_socket(&path).unwrap();
    }

    use ssh_encoding::Encode;
}
