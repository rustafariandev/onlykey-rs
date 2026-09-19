//! The agent itself: identity bookkeeping, request handling and the unix
//! socket server.

use super::wire::{self, Request};
use crate::challenge::ChallengeSink;
use crate::device::{DeviceError, OnlyKey};
use crate::identity::{Curve, Identity};
use crate::keys;
use crate::transport::HidTransport;
use nix::sys::stat::{Mode, umask};
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

/// One key the agent serves.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Entry {
    pub identity: Identity,
    pub curve: Curve,
}

impl Entry {
    pub fn label(&self) -> String {
        self.identity.label(self.curve)
    }
}

#[derive(Debug, Error)]
pub enum AgentError {
    #[error(transparent)]
    Device(#[from] DeviceError),
    #[error(transparent)]
    Key(#[from] keys::KeyError),
    #[error("requested key is not served by this agent")]
    UnknownKey,
    #[error(transparent)]
    Wire(#[from] wire::WireError),
}

/// Agent state shared between connections.
pub struct Agent {
    entries: Vec<Entry>,
    opener: Opener,
    sink: Arc<dyn ChallengeSink>,
    /// Serialises every device operation, including the wait for the user.
    device_lock: Mutex<()>,
    cache: Mutex<HashMap<Entry, PublicKey>>,
}

impl Agent {
    pub fn new(entries: Vec<Entry>, opener: Opener, sink: Arc<dyn ChallengeSink>) -> Self {
        Agent {
            entries,
            opener,
            sink,
            device_lock: Mutex::new(()),
            cache: Mutex::new(HashMap::new()),
        }
    }

    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// Seed the key cache from previously exported public keys, matched by
    /// their comment (`<ssh://user@host|curve>`). Returns how many matched.
    pub fn preload(&self, keys: impl IntoIterator<Item = PublicKey>) -> usize {
        let mut cache = self.cache.lock().unwrap_or_else(|p| p.into_inner());
        let mut matched = 0;
        for key in keys {
            if let Some(entry) = self.entries.iter().find(|e| e.label() == key.comment())
                && keys::curve_of(&key) == Some(entry.curve)
            {
                cache.insert(entry.clone(), key);
                matched += 1;
            }
        }
        matched
    }

    /// Public keys for every entry, deriving any that are not cached yet.
    ///
    /// Entries whose key cannot be derived (device absent or locked) are
    /// skipped with a warning so the client still sees the rest.
    pub fn public_keys(&self) -> Vec<PublicKey> {
        let missing: Vec<Entry> = {
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
                                tracing::warn!(identity = %entry.identity, curve = %entry.curve, error = %e, "cannot derive public key")
                            }
                        }
                    }
                }
                Err(e) => tracing::warn!(error = %e, "cannot open OnlyKey to derive public keys"),
            }
        }
        let cache = self.cache.lock().unwrap_or_else(|p| p.into_inner());
        self.entries
            .iter()
            .filter_map(|e| cache.get(e).cloned())
            .collect()
    }

    /// Derive every key now; fails on the first problem. Used by commands that
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

    fn derive(&self, device: &mut Device, entry: &Entry) -> Result<PublicKey, AgentError> {
        let raw = device.derive_public_key(&entry.identity, entry.curve)?;
        Ok(keys::public_key(&raw, &entry.label())?)
    }

    /// Handle one request body and produce the reply body.
    pub fn handle(&self, body: &[u8]) -> Vec<u8> {
        match wire::parse_request(body) {
            Ok(Request::RequestIdentities) => {
                let keys = self.public_keys();
                tracing::debug!(count = keys.len(), "listing identities");
                wire::identities_answer(&keys)
            }
            Ok(Request::Sign {
                key_blob,
                data,
                flags,
            }) => {
                tracing::debug!(len = data.len(), flags, "sign request");
                match self.sign(&key_blob, &data) {
                    Ok(reply) => reply,
                    Err(e) => {
                        tracing::warn!(error = %e, "sign request failed");
                        wire::failure()
                    }
                }
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

    fn sign(&self, key_blob: &[u8], data: &[u8]) -> Result<Vec<u8>, AgentError> {
        let (entry, key) = self.lookup(key_blob)?;
        let subject = wire::describe_data(data);
        let _guard = self.device_lock.lock().unwrap_or_else(|p| p.into_inner());
        let mut device = (self.opener)()?;
        let raw = device.sign(
            &entry.identity,
            entry.curve,
            data,
            subject,
            self.sink.as_ref(),
        )?;
        drop(device);
        let sig = keys::signature(entry.curve, &raw)?;
        keys::verify(&key, data, &sig)?;
        tracing::info!(identity = %entry.identity, curve = %entry.curve, "signed");
        Ok(wire::sign_response(&sig))
    }

    fn lookup(&self, key_blob: &[u8]) -> Result<(Entry, PublicKey), AgentError> {
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
/// else `/tmp/okagent-<uid>/agent.sock`.
pub fn default_socket_path() -> PathBuf {
    runtime_dir().join("agent.sock")
}

/// A fresh per-process socket path for `run`-style invocations.
pub fn ephemeral_socket_path() -> PathBuf {
    runtime_dir().join(format!("run-{}.sock", std::process::id()))
}

fn runtime_dir() -> PathBuf {
    match std::env::var_os("XDG_RUNTIME_DIR") {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir).join("okagent"),
        _ => PathBuf::from(format!("/tmp/okagent-{}", nix::unistd::getuid())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::challenge::RecordingSink;
    use crate::device::Timeouts;
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

    fn entry() -> Entry {
        Entry {
            identity: "james@example.com".parse().unwrap(),
            curve: Curve::Ed25519,
        }
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
                Curve::Ed25519,
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
    fn unknown_key_and_unsupported_requests_fail_cleanly() {
        let opener: Opener = Arc::new(|| panic!("device must not be opened"));
        let agent = Agent::new(vec![entry()], opener, Arc::new(RecordingSink::default()));
        let mut body = vec![wire::SSH2_AGENTC_SIGN_REQUEST];
        b"nokey".as_slice().encode(&mut body).unwrap();
        b"data".as_slice().encode(&mut body).unwrap();
        0u32.encode(&mut body).unwrap();
        assert_eq!(agent.handle(&body), wire::failure());
        assert_eq!(agent.handle(&[27]), wire::failure());
        assert_eq!(agent.handle(&[]), wire::failure());
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
