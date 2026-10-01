//! The agent itself: identity bookkeeping, request handling and the unix
//! socket server.

use super::extension::{Extension, ExtensionContext};
use super::keytype::{HeldKey, KeyDecoder, KeyRegistry};
use super::local::{LocalKeyError, LocalKeyRef};
use super::sk::SkKey;
use super::wire::{self, Request};
use crate::challenge::{ChallengeSink, TouchRequest};
use crate::device::{DeviceError, OnlyKey};
use crate::fido::FidoError;
use crate::fido::ctaphid::CtapHid;
use crate::identity::KeySpec;
use crate::keys;
use crate::transport::{HidTransport, HidapiTransport};
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
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use thiserror::Error;

/// Lock `mutex`, carrying on if a thread panicked while holding it: each
/// value guarded here is left consistent between statements, so a poisoned
/// lock still holds usable state.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|p| p.into_inner())
}

/// A device the agent can open on demand.
pub type Device = OnlyKey<Box<dyn HidTransport>>;
/// How the agent obtains a device for each operation.
pub type Opener = Arc<dyn Fn() -> Result<Device, DeviceError> + Send + Sync>;
/// How the agent obtains the FIDO authenticators for each security-key
/// signature. With more than one, the agent asks each which holds the key.
pub type SkOpener = Arc<dyn Fn() -> Result<Vec<Box<dyn HidTransport>>, FidoError> + Send + Sync>;

/// The default: every attached FIDO security key, discovered over hidraw.
fn default_sk_opener() -> SkOpener {
    Arc::new(|| {
        Ok(HidapiTransport::open_all_fido(None)?
            .into_iter()
            .map(|t| Box::new(t) as Box<dyn HidTransport>)
            .collect())
    })
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
    Local(#[from] LocalKeyError),
    #[error(transparent)]
    Fido(#[from] FidoError),
    #[error(transparent)]
    Identity(#[from] crate::identity::IdentityError),
    #[error(
        "refusing to sign non-SSH data with security key for application {0:?}; only ssh: keys sign arbitrary data"
    )]
    NotWebSafe(String),
    #[error("provider string is not valid UTF-8")]
    BadProvider,
    #[error(
        "client asked for an ssh-rsa (SHA-1) signature, which is not supported; it must request rsa-sha2-256 or rsa-sha2-512"
    )]
    Sha1Requested,
    #[error(transparent)]
    Wire(#[from] wire::WireError),
}

/// Agent state shared between connections. Each [`KeySpec`] it serves is
/// one identity in the SSH sense.
pub struct Agent {
    entries: Mutex<Vec<Timed<KeySpec>>>,
    /// Keys added at runtime with `ssh-add FILE`: private keys held in memory
    /// and FIDO credentials signed by the authenticator.
    held: Mutex<Vec<Timed<Arc<HeldKey>>>>,
    /// Protocol extension handlers, matched by name.
    extensions: Mutex<Vec<Arc<dyn Extension>>>,
    /// Key-type decoders for `ssh-add FILE`, matched by the request's key type.
    key_types: Mutex<KeyRegistry>,
    opener: Opener,
    sk_opener: SkOpener,
    sink: Arc<dyn ChallengeSink>,
    /// Serialises every device operation, including the wait for the user.
    device_lock: Mutex<()>,
    /// Serialises FIDO operations, which also wait for a touch.
    sk_lock: Mutex<()>,
    cache: Mutex<HashMap<KeySpec, PublicKey>>,
    /// `ssh-add -x` state: a salted hash of the passphrase while locked.
    passphrase_lock: Mutex<Option<PassphraseHash>>,
}

/// A served identity with an optional expiry from the lifetime constraint of
/// an `ssh-add -t` request.
struct Timed<T> {
    item: T,
    expires: Option<Instant>,
}

impl<T> Timed<T> {
    /// `lifetime` is in seconds; `None` or zero never expires.
    fn new(item: T, lifetime: Option<u32>) -> Self {
        let expires = lifetime
            .filter(|secs| *secs > 0)
            .map(|secs| Instant::now() + Duration::from_secs(secs as u64));
        Timed { item, expires }
    }

    fn expired(&self) -> bool {
        self.expires.is_some_and(|at| Instant::now() >= at)
    }
}

/// What a sign request named, once looked up.
enum Target {
    /// A key the token holds.
    Device(KeySpec, Box<PublicKey>),
    /// A key added with `ssh-add FILE`.
    Held(Arc<HeldKey>),
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
            entries: Mutex::new(
                entries
                    .into_iter()
                    .map(|spec| Timed::new(spec, None))
                    .collect(),
            ),
            held: Mutex::new(Vec::new()),
            extensions: Mutex::new(Vec::new()),
            key_types: Mutex::new(KeyRegistry::builtin()),
            opener,
            sk_opener: default_sk_opener(),
            sink,
            device_lock: Mutex::new(()),
            sk_lock: Mutex::new(()),
            cache: Mutex::new(HashMap::new()),
            passphrase_lock: Mutex::new(None),
        }
    }

    /// Replace how FIDO authenticators are opened (for tests and for a fixed
    /// `--fido-device` path).
    pub fn with_sk_opener(mut self, opener: SkOpener) -> Self {
        self.sk_opener = opener;
        self
    }

    /// Register a protocol extension handler and return the agent, for the
    /// builder style of [`Self::new`]. A later registration under the same
    /// name wins.
    pub fn with_extension(self, extension: impl Extension + 'static) -> Self {
        self.register_extension(extension);
        self
    }

    /// Register a protocol extension handler, answering
    /// `SSH_AGENTC_EXTENSION` requests whose name it matches. A later
    /// registration under the same name wins.
    pub fn register_extension(&self, extension: impl Extension + 'static) {
        let name = extension.name().to_owned();
        let mut extensions = lock(&self.extensions);
        extensions.retain(|e| e.name() != name);
        extensions.push(Arc::new(extension));
    }

    /// Register a key-type decoder for `ssh-add FILE` and return the agent,
    /// for the builder style of [`Self::new`]. A later registration under a
    /// name wins, so a built-in key type can be replaced as well as extended.
    pub fn with_key_type(self, decoder: impl KeyDecoder + 'static) -> Self {
        self.register_key_type(decoder);
        self
    }

    /// Register a key-type decoder, consulted for `SSH2_AGENTC_ADD_IDENTITY`
    /// requests whose key type it answers. A later registration under a name
    /// wins.
    pub fn register_key_type(&self, decoder: impl KeyDecoder + 'static) {
        lock(&self.key_types).register(decoder);
    }

    /// Serve a key added with `ssh-add FILE` (a private key held in memory or
    /// a FIDO credential), with an optional lifetime from `ssh-add -t`. A key
    /// already served is replaced, so a fresh lifetime takes effect.
    pub fn add_key(&self, key: HeldKey, lifetime: Option<u32>) {
        self.purge_expired();
        let blob = key.key_blob();
        let comment = key.public_key().comment().to_owned();
        let mut held = lock(&self.held);
        held.retain(|e| e.item.key_blob() != blob);
        held.push(Timed::new(Arc::new(key), lifetime));
        drop(held);
        tracing::info!(comment, "serving added key");
    }

    /// Stop serving the key added with `ssh-add FILE` whose public key blob is
    /// `key_blob`. Returns whether anything was removed.
    pub fn remove_key(&self, key_blob: &[u8]) -> bool {
        let mut held = lock(&self.held);
        let before = held.len();
        held.retain(|e| e.item.key_blob() != key_blob);
        held.len() != before
    }

    /// Whether `ssh-add -x` has locked the agent.
    pub fn is_locked(&self) -> bool {
        lock(&self.passphrase_lock).is_some()
    }

    /// Lock with `passphrase`; fails if already locked, as in OpenSSH.
    pub fn lock(&self, passphrase: &[u8]) -> bool {
        let mut state = lock(&self.passphrase_lock);
        if state.is_some() {
            return false;
        }
        *state = Some(PassphraseHash::new(passphrase));
        true
    }

    /// Unlock if `passphrase` is the one the agent was locked with.
    pub fn unlock(&self, passphrase: &[u8]) -> bool {
        let mut state = lock(&self.passphrase_lock);
        match state.as_ref() {
            Some(hash) if hash.matches(passphrase) => {
                *state = None;
                true
            }
            _ => false,
        }
    }

    /// The identities currently served, in order. A snapshot, since the list
    /// can change at runtime through [`Self::add`] and [`Self::remove`].
    pub fn entries(&self) -> Vec<KeySpec> {
        self.purge_expired();
        lock(&self.entries).iter().map(|e| e.item.clone()).collect()
    }

    /// Add `spec` to the served identities. If its public key is already
    /// known (from [`Self::preload`] or an earlier fetch) it is served from
    /// the cache and the device is not touched; otherwise the key is fetched
    /// and verified against the device. Re-adding a listed key moves it to
    /// the end and restarts its lifetime. `lifetime` is the `ssh-add -t`
    /// constraint in seconds, if any.
    pub fn add(&self, spec: KeySpec, lifetime: Option<u32>) -> Result<PublicKey, AgentError> {
        self.purge_expired();
        let key = self.derive_one(&spec)?;
        self.remember(spec.clone(), lifetime);
        tracing::info!(identity = %spec.identity, key = %spec.kind, "serving key");
        Ok(key)
    }

    /// Remove every entry matching `spec` (from the config or added at
    /// runtime). Returns whether anything was removed.
    pub fn remove(&self, spec: &KeySpec) -> bool {
        let mut entries = lock(&self.entries);
        let before = entries.len();
        entries.retain(|e| &e.item != spec);
        let removed = entries.len() != before;
        drop(entries);
        if removed {
            lock(&self.cache).remove(spec);
        }
        removed
    }

    /// Record `spec` in the entry list, replacing any existing entry so a
    /// fresh lifetime takes effect.
    fn remember(&self, spec: KeySpec, lifetime: Option<u32>) {
        let mut entries = lock(&self.entries);
        entries.retain(|e| e.item != spec);
        entries.push(Timed::new(spec, lifetime));
    }

    /// Drop entries whose lifetime has elapsed, along with their cached keys.
    fn purge_expired(&self) {
        let mut entries = lock(&self.entries);
        let mut expired = Vec::new();
        entries.retain(|e| {
            let alive = !e.expired();
            if !alive {
                expired.push(e.item.clone());
            }
            alive
        });
        drop(entries);
        if !expired.is_empty() {
            let mut cache = lock(&self.cache);
            for spec in expired {
                cache.remove(&spec);
            }
        }
        lock(&self.held).retain(|e| !e.expired());
    }

    /// Seed the key cache from previously exported public keys, matched by
    /// their comment (see [`KeySpec::label`]). Returns how many matched.
    pub fn preload(&self, keys: impl IntoIterator<Item = PublicKey>) -> usize {
        let entries = self.entries();
        let mut cache = lock(&self.cache);
        let mut matched = 0;
        for key in keys {
            if let Some(entry) = entries.iter().find(|e| e.label() == key.comment())
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
        let entries = self.entries();
        let missing: Vec<KeySpec> = {
            let cache = lock(&self.cache);
            entries
                .iter()
                .filter(|e| !cache.contains_key(*e))
                .cloned()
                .collect()
        };
        if !missing.is_empty() {
            let _guard = lock(&self.device_lock);
            match (self.opener)() {
                Ok(mut device) => {
                    for entry in &missing {
                        match self.derive(&mut device, entry) {
                            Ok(key) => {
                                lock(&self.cache).insert(entry.clone(), key);
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
        let mut keys: Vec<PublicKey> = {
            let cache = lock(&self.cache);
            entries
                .iter()
                .filter_map(|e| cache.get(e).cloned())
                .collect()
        };
        keys.extend(lock(&self.held).iter().map(|e| e.item.public_key().clone()));
        keys
    }

    /// Fetch every key now; fails on the first problem. Used by commands that
    /// need all keys up front.
    pub fn derive_all(&self) -> Result<Vec<PublicKey>, AgentError> {
        let entries = self.entries();
        let _guard = lock(&self.device_lock);
        let mut device = None;
        let mut out = Vec::with_capacity(entries.len());
        for entry in &entries {
            let cached = lock(&self.cache).get(entry).cloned();
            let key = match cached {
                Some(key) => key,
                None => {
                    if device.is_none() {
                        device = Some((self.opener)()?);
                    }
                    let key = self.derive(device.as_mut().expect("just opened"), entry)?;
                    lock(&self.cache).insert(entry.clone(), key.clone());
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
        let cached = lock(&self.cache).get(entry).cloned();
        if let Some(key) = cached {
            return Ok(key);
        }
        let _guard = lock(&self.device_lock);
        let mut device = (self.opener)()?;
        let key = self.derive(&mut device, entry)?;
        lock(&self.cache).insert(entry.clone(), key.clone());
        Ok(key)
    }

    fn derive(&self, device: &mut Device, entry: &KeySpec) -> Result<PublicKey, AgentError> {
        Ok(device.ssh_public_key(entry)?)
    }

    /// Handle one request body and produce the reply body.
    ///
    /// The lock is checked once: a locked agent answers through
    /// [`Self::handle_locked`], an unlocked one through
    /// [`Self::handle_unlocked`].
    pub fn handle(&self, body: &[u8]) -> Vec<u8> {
        let request = {
            let key_types = lock(&self.key_types);
            wire::parse_request_with(&key_types, body)
        };
        let request = match request {
            Ok(request) => request,
            Err(e) => {
                tracing::warn!(error = %e, "bad request");
                return wire::failure();
            }
        };
        if self.is_locked() {
            self.handle_locked(request)
        } else {
            self.handle_unlocked(request)
        }
    }

    /// Answer a request while `ssh-add -x` has locked the agent: no keys are
    /// listed, unlock and protocol extensions are served, and everything
    /// else is refused, including request types added later.
    fn handle_locked(&self, request: Request) -> Vec<u8> {
        match request {
            Request::RequestIdentities => {
                tracing::debug!("listing identities: agent is locked, none");
                wire::identities_answer(&[])
            }
            Request::RequestRsaIdentities => {
                tracing::debug!("SSH v1 identities request: answering with none");
                wire::rsa_identities_answer()
            }
            Request::Unlock(passphrase) => self.handle_unlock(&passphrase),
            Request::Extension { name, data } => self.handle_extension(&name, &data),
            Request::Unsupported(kind) => {
                tracing::debug!(kind, "unsupported request");
                wire::failure()
            }
            other => {
                tracing::warn!(request = other.name(), "refused: agent is locked");
                wire::failure()
            }
        }
    }

    /// Answer a request while the agent is unlocked.
    fn handle_unlocked(&self, request: Request) -> Vec<u8> {
        match request {
            Request::RequestIdentities => {
                let keys = self.public_keys();
                tracing::debug!(count = keys.len(), "listing identities");
                wire::identities_answer(&keys)
            }
            Request::RequestRsaIdentities => {
                tracing::debug!("SSH v1 identities request: answering with none");
                wire::rsa_identities_answer()
            }
            Request::Sign {
                key_blob,
                data,
                flags,
            } => {
                tracing::debug!(len = data.len(), flags, "sign request");
                match self.sign(&key_blob, &data, flags) {
                    Ok(reply) => reply,
                    Err(e) => {
                        tracing::warn!(error = %e, "sign request failed");
                        wire::failure()
                    }
                }
            }
            Request::Lock(passphrase) => {
                if self.lock(&passphrase) {
                    tracing::info!("agent locked");
                    wire::success()
                } else {
                    tracing::warn!("lock request refused: already locked");
                    wire::failure()
                }
            }
            Request::Unlock(passphrase) => self.handle_unlock(&passphrase),
            Request::AddIdentity { key, lifetime } => {
                self.add_key(key, lifetime);
                wire::success()
            }
            Request::RemoveIdentity { key_blob } => {
                if self.remove_key(&key_blob) {
                    tracing::info!("removed added key");
                    wire::success()
                } else if let Some((spec, _)) = self.device_key(&key_blob)
                    && self.remove(&spec)
                {
                    tracing::info!(identity = %spec.identity, key = %spec.kind, "removed key");
                    wire::success()
                } else {
                    tracing::debug!("no such key to remove");
                    wire::failure()
                }
            }
            Request::RemoveAllIdentities => {
                self.remove_all();
                tracing::info!("removed every identity");
                wire::success()
            }
            Request::AddSmartcardKey {
                provider, lifetime, ..
            } => match self.provider_spec(&provider) {
                Ok(spec) => {
                    let identity = spec.identity.to_string();
                    match self.add(spec, lifetime) {
                        Ok(_) => wire::success(),
                        Err(e) => {
                            tracing::warn!(identity, error = %e, "cannot add key");
                            wire::failure()
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "cannot parse provider");
                    wire::failure()
                }
            },
            Request::RemoveSmartcardKey { provider } => match self.provider_spec(&provider) {
                Ok(spec) if self.remove(&spec) => {
                    tracing::info!(identity = %spec.identity, key = %spec.kind, "removed key");
                    wire::success()
                }
                Ok(spec) => {
                    tracing::debug!(identity = %spec.identity, "no such key to remove");
                    wire::failure()
                }
                Err(e) => {
                    tracing::warn!(error = %e, "cannot parse provider");
                    wire::failure()
                }
            },
            Request::Extension { name, data } => self.handle_extension(&name, &data),
            Request::Unsupported(kind) => {
                tracing::debug!(kind, "unsupported request");
                wire::failure()
            }
        }
    }

    /// `ssh-add -X`: unlock if the passphrase matches. Fails when the agent
    /// is not locked.
    fn handle_unlock(&self, passphrase: &[u8]) -> Vec<u8> {
        if self.unlock(passphrase) {
            tracing::info!("agent unlocked");
            wire::success()
        } else {
            tracing::warn!("unlock request refused: not locked or wrong passphrase");
            wire::failure()
        }
    }

    /// Answer an `SSH_AGENTC_EXTENSION` request with the handler registered
    /// under `name`, locked or not; the handler sees the lock state through
    /// [`ExtensionContext`] and decides for itself.
    fn handle_extension(&self, name: &str, data: &[u8]) -> Vec<u8> {
        let extension = lock(&self.extensions)
            .iter()
            .rev()
            .find(|e| e.name() == name)
            .cloned();
        match extension {
            Some(extension) => {
                tracing::debug!(extension = %name, "extension request");
                let ctx = ExtensionContext::new(self.is_locked());
                extension.handle(&ctx, data).into_body()
            }
            None => {
                tracing::debug!(extension = %name, "unsupported extension request");
                wire::extension_failure()
            }
        }
    }

    /// Drop every identity: token-backed entries, their cached keys, and the
    /// keys added with `ssh-add FILE`. Backs `ssh-add -D`.
    fn remove_all(&self) {
        lock(&self.entries).clear();
        lock(&self.cache).clear();
        lock(&self.held).clear();
    }

    fn sign(&self, key_blob: &[u8], data: &[u8], flags: u32) -> Result<Vec<u8>, AgentError> {
        let target = self.lookup(key_blob)?;
        let is_rsa = match &target {
            Target::Device(entry, _) => entry.kind.is_rsa(),
            Target::Held(key) => key.public_key().algorithm().is_rsa(),
        };
        let hash = match wire::rsa_hash(flags) {
            Some(hash) => hash,
            None if is_rsa => return Err(AgentError::Sha1Requested),
            None => HashAlg::default(),
        };
        match target {
            Target::Held(held) => match held.as_ref() {
                HeldKey::Local(key) => self.sign_local(key, data, hash),
                HeldKey::SecurityKey(key) => self.sign_security_key(key, data),
            },
            Target::Device(entry, key) => {
                let subject = wire::describe_data(data);
                let _guard = lock(&self.device_lock);
                let mut device = (self.opener)()?;
                let raw = device.sign(&entry, data, hash, subject, self.sink.as_ref())?;
                drop(device);
                let sig = keys::signature(&entry.kind.signature_algorithm(hash), &raw)?;
                keys::verify(&key, data, &sig)?;
                tracing::info!(identity = %entry.identity, key = %entry.kind, algorithm = %sig.algorithm(), "signed");
                Ok(wire::sign_response(&sig))
            }
        }
    }

    /// Sign in software with a private key held in memory.
    fn sign_local(
        &self,
        key: &LocalKeyRef,
        data: &[u8],
        hash: HashAlg,
    ) -> Result<Vec<u8>, AgentError> {
        let sig = key.sign(data, hash)?;
        key.verify(data, &sig)?;
        tracing::info!(
            comment = key.public_key().comment(),
            "signed with local key"
        );
        Ok(wire::sign_response(&sig))
    }

    /// Sign with a FIDO credential, waiting for the authenticator's touch.
    ///
    /// As in OpenSSH, a credential whose application is not `ssh:` signs only
    /// SSH userauth requests and SSHSIG blobs, so the agent cannot be used to
    /// mint assertions for the website such a credential may belong to.
    fn sign_security_key(&self, key: &SkKey, data: &[u8]) -> Result<Vec<u8>, AgentError> {
        if !key.is_ssh_application() && wire::classify_data(data) == wire::SignedData::Other {
            return Err(AgentError::NotWebSafe(key.application().to_owned()));
        }
        let _guard = lock(&self.sk_lock);
        let mut hid = self.authenticator_for(key)?;
        let request = TouchRequest {
            identity: key.public_key().comment().to_owned(),
            subject: wire::describe_data(data),
        };
        let sig = key.sign_with(&mut hid, data, &|| {
            tracing::info!("security key is waiting for a touch");
            self.sink.present_touch(&request);
        })?;
        keys::verify(key.public_key(), data, &sig)?;
        tracing::info!(
            comment = key.public_key().comment(),
            algorithm = %sig.algorithm(),
            "signed with security key"
        );
        Ok(wire::sign_response(&sig))
    }

    /// The attached authenticator to sign with `key`. A lone device is used
    /// as is; among several, the first that answers a silent probe for the
    /// credential is chosen, so no touch is asked of the others.
    fn authenticator_for(&self, key: &SkKey) -> Result<CtapHid<Box<dyn HidTransport>>, AgentError> {
        let mut devices: Vec<_> = (self.sk_opener)()?.into_iter().map(CtapHid::new).collect();
        if devices.len() <= 1 {
            return devices.pop().ok_or(AgentError::Fido(FidoError::NoDevice));
        }
        for (index, mut hid) in devices.into_iter().enumerate() {
            match key.is_held_by(&mut hid) {
                Ok(true) => return Ok(hid),
                Ok(false) => tracing::debug!(index, "security key does not hold the credential"),
                Err(e) => tracing::warn!(index, error = %e, "cannot probe security key"),
            }
        }
        Err(FidoError::NoCredential.into())
    }

    /// The served token key whose public key blob is `key_blob`, if its
    /// public key is known.
    fn device_key(&self, key_blob: &[u8]) -> Option<(KeySpec, PublicKey)> {
        let cache = lock(&self.cache);
        cache
            .iter()
            .find(|(_, key)| key.to_bytes().is_ok_and(|b| b == key_blob))
            .map(|(spec, key)| (spec.clone(), key.clone()))
    }

    fn lookup(&self, key_blob: &[u8]) -> Result<Target, AgentError> {
        self.purge_expired();
        if let Some((spec, key)) = self.device_key(key_blob) {
            return Ok(Target::Device(spec, Box::new(key)));
        }
        let held = lock(&self.held);
        held.iter()
            .find(|e| e.item.key_blob() == key_blob)
            .map(|e| Target::Held(Arc::clone(&e.item)))
            .ok_or(AgentError::UnknownKey)
    }

    /// Turn an `ssh-add -s`/`-e` provider string into a key: a full label
    /// (`<ssh://[user@]host|curve[|slot]>`) or a bare `[user@]host` for a
    /// derived ed25519 key.
    fn provider_spec(&self, provider: &[u8]) -> Result<KeySpec, AgentError> {
        let text = std::str::from_utf8(provider).map_err(|_| AgentError::BadProvider)?;
        Ok(KeySpec::parse_arg(text)?)
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

/// How often [`serve`] drops keys whose lifetime has run out.
const PURGE_INTERVAL: Duration = Duration::from_secs(1);

/// Accept connections until `shutdown` is set. Each connection runs on its
/// own thread. Keys whose lifetime has run out are dropped as it goes.
pub fn serve(
    listener: UnixListener,
    agent: Arc<Agent>,
    shutdown: Arc<AtomicBool>,
) -> io::Result<()> {
    listener.set_nonblocking(true)?;
    let mut last_purge = Instant::now();
    while !shutdown.load(Ordering::SeqCst) {
        // Drop keys whose `ssh-add -t` lifetime has run out even when no
        // client is talking to the agent, so their secrets do not linger.
        if last_purge.elapsed() >= PURGE_INTERVAL {
            agent.purge_expired();
            last_purge = Instant::now();
        }
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
    use crate::agent::ExtensionReply;
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
        KeySpec::derived("ferris@example.com".parse().unwrap(), Curve::Ed25519)
    }

    fn stored_entry() -> KeySpec {
        KeySpec::stored(
            "ferris@example.com".parse().unwrap(),
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
        assert_eq!(keys[0].comment(), "<ssh://ferris@example.com|ed25519>");
        assert_eq!(keys[0].key_data().ed25519().unwrap().0, [0x11; 32]);
        assert_eq!(keys[1].comment(), "<ssh://ferris@example.com|ed25519|ECC3>");
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
        // A named but unregistered extension is an extension failure; a
        // nameless one is malformed and gets the plain failure code.
        assert_eq!(agent.handle(&[27, 0, 0, 0, 0]), wire::extension_failure());
        assert_eq!(agent.handle(&[27]), wire::failure());
        assert_eq!(agent.handle(&[1]), wire::rsa_identities_answer());
        assert_eq!(agent.handle(&[]), wire::failure());
    }

    struct Ping;

    impl Extension for Ping {
        fn name(&self) -> &str {
            "ping@example.com"
        }

        fn handle(&self, ctx: &ExtensionContext, data: &[u8]) -> ExtensionReply {
            match (ctx.locked(), data) {
                (false, b"ping") => ExtensionReply::Success,
                (true, b"ping") => ExtensionReply::Failure,
                (_, b"raw") => ExtensionReply::Raw(vec![42, 1, 2]),
                _ => ExtensionReply::ExtensionFailure,
            }
        }
    }

    struct PingOverride;

    impl Extension for PingOverride {
        fn name(&self) -> &str {
            "ping@example.com"
        }

        fn handle(&self, _ctx: &ExtensionContext, _data: &[u8]) -> ExtensionReply {
            ExtensionReply::Raw(vec![7])
        }
    }

    #[test]
    fn registered_extensions_answer_by_name() {
        let opener: Opener = Arc::new(|| panic!("device must not be opened"));
        let agent =
            Agent::new(Vec::new(), opener, Arc::new(RecordingSink::default())).with_extension(Ping);

        let ext = |name: &str, data: &[u8]| {
            let mut body = vec![wire::SSH_AGENTC_EXTENSION];
            name.encode(&mut body).unwrap();
            body.extend_from_slice(data);
            agent.handle(&body)
        };

        assert_eq!(ext("ping@example.com", b"ping"), wire::success());
        assert_eq!(ext("ping@example.com", b"raw"), vec![42, 1, 2]);
        assert_eq!(ext("ping@example.com", b"nope"), wire::extension_failure());
        // An unknown name still gets the extension-failure code.
        assert_eq!(ext("other@example.com", b""), wire::extension_failure());

        // The handler decides what to do while the agent is locked.
        assert!(agent.lock(b"hunter2"));
        assert_eq!(ext("ping@example.com", b"ping"), wire::failure());
    }

    #[test]
    fn last_extension_registered_under_a_name_wins() {
        let opener: Opener = Arc::new(|| panic!("device must not be opened"));
        let agent =
            Agent::new(Vec::new(), opener, Arc::new(RecordingSink::default())).with_extension(Ping);
        agent.register_extension(PingOverride);
        let mut body = vec![wire::SSH_AGENTC_EXTENSION];
        "ping@example.com".encode(&mut body).unwrap();
        assert_eq!(agent.handle(&body), vec![7]);
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

    /// While locked, only listing, unlock and extensions are served: every
    /// request that would change the served keys is refused and changes
    /// nothing.
    #[test]
    fn a_locked_agent_refuses_every_change() {
        let e = entry();
        let opener: Opener = Arc::new(|| panic!("device must not be opened"));
        let agent = Agent::new(vec![e.clone()], opener, Arc::new(RecordingSink::default()));
        let raw = protocol::RawPublicKey::Ed25519([0x22; 32]);
        let key = keys::public_key(&raw, &e.label()).unwrap();
        assert_eq!(agent.preload([key.clone()]), 1);
        let (add, _) = local_key(0x11, "ferris@example.com");

        let mut lock = vec![wire::SSH_AGENTC_LOCK];
        b"hunter2".as_slice().encode(&mut lock).unwrap();
        assert_eq!(agent.handle(&lock), wire::success());

        let provider = |kind: u8| {
            let mut body = vec![kind];
            b"ferris@example.com".as_slice().encode(&mut body).unwrap();
            b"".as_slice().encode(&mut body).unwrap();
            body
        };
        let mut remove = vec![wire::SSH2_AGENTC_REMOVE_IDENTITY];
        key.to_bytes().unwrap().encode(&mut remove).unwrap();
        for request in [
            add,
            remove,
            vec![wire::SSH_AGENTC_REMOVE_ALL_IDENTITIES],
            provider(wire::SSH_AGENTC_ADD_SMARTCARD_KEY),
            provider(wire::SSH_AGENTC_REMOVE_SMARTCARD_KEY),
            vec![200],
        ] {
            assert_eq!(agent.handle(&request), wire::failure(), "{:?}", request[0]);
        }
        assert_eq!(agent.handle(&[1]), wire::rsa_identities_answer());

        let mut unlock = vec![wire::SSH_AGENTC_UNLOCK];
        b"hunter2".as_slice().encode(&mut unlock).unwrap();
        assert_eq!(agent.handle(&unlock), wire::success());
        assert_eq!(agent.entries(), vec![e]);
        assert_eq!(agent.public_keys(), vec![key]);
    }

    #[test]
    fn add_smartcard_key_derives_lists_and_removes() {
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
        let agent = Agent::new(Vec::new(), opener, Arc::new(RecordingSink::default()));

        let mut add = vec![wire::SSH_AGENTC_ADD_SMARTCARD_KEY];
        b"ferris@example.com".as_slice().encode(&mut add).unwrap();
        b"".as_slice().encode(&mut add).unwrap();
        assert_eq!(agent.handle(&add), wire::success());
        // The second add is served from the cache: the opener would panic.
        assert_eq!(agent.handle(&add), wire::success());
        assert_eq!(agent.entries(), vec![e.clone()]);

        let reply = agent.handle(&[wire::SSH2_AGENTC_REQUEST_IDENTITIES]);
        assert_eq!(reply[0], wire::SSH2_AGENT_IDENTITIES_ANSWER);
        let mut r = &reply[5..];
        let blob = Vec::<u8>::decode(&mut r).unwrap();
        let key = PublicKey::from_bytes(&blob).unwrap();
        assert_eq!(key.key_data().ed25519().unwrap().0, [0x11; 32]);
        assert_eq!(String::decode(&mut r).unwrap(), e.label());

        let mut remove = vec![wire::SSH_AGENTC_REMOVE_SMARTCARD_KEY];
        b"ferris@example.com"
            .as_slice()
            .encode(&mut remove)
            .unwrap();
        b"".as_slice().encode(&mut remove).unwrap();
        assert_eq!(agent.handle(&remove), wire::success());
        assert!(agent.entries().is_empty());
        assert_eq!(
            agent.handle(&[wire::SSH2_AGENTC_REQUEST_IDENTITIES]),
            vec![12, 0, 0, 0, 0]
        );
        // Removing a key that is not served fails.
        assert_eq!(agent.handle(&remove), wire::failure());
    }

    #[test]
    fn add_smartcard_key_accepts_a_full_label() {
        let e = stored_entry();
        let mut key_report = [0u8; 64];
        key_report[..32].copy_from_slice(&[0x33; 32]);
        let opener = opener_with(vec![
            Step::ExpectWrite(protocol::settime_report(1)),
            Step::Reply(text("UNLOCKEDv3.0.4-prodc")),
            Step::ExpectWrite(protocol::getpubkey_report(
                103,
                0x01,
                &e.identity.derivation_hash(),
            )),
            Step::Reply(key_report),
        ]);
        let agent = Agent::new(Vec::new(), opener, Arc::new(RecordingSink::default()));
        let mut add = vec![wire::SSH_AGENTC_ADD_SMARTCARD_KEY];
        e.label().as_str().encode(&mut add).unwrap();
        b"".as_slice().encode(&mut add).unwrap();
        assert_eq!(agent.handle(&add), wire::success());
        assert_eq!(agent.entries(), vec![e]);
    }

    #[test]
    fn add_and_constrained_add_failures() {
        let opener: Opener = Arc::new(|| Err(DeviceError::Locked));
        let agent = Agent::new(Vec::new(), opener, Arc::new(RecordingSink::default()));
        let add = |kind: u8, provider: &str| {
            let mut body = vec![kind];
            provider.as_bytes().encode(&mut body).unwrap();
            b"".as_slice().encode(&mut body).unwrap();
            body
        };
        // Device unavailable, and a provider that does not name a key.
        assert_eq!(
            agent.handle(&add(
                wire::SSH_AGENTC_ADD_SMARTCARD_KEY,
                "ferris@example.com"
            )),
            wire::failure()
        );
        assert_eq!(
            agent.handle(&add(wire::SSH_AGENTC_ADD_SMARTCARD_KEY, "<not a label>")),
            wire::failure()
        );
        // An extension constraint (destination/certificate) is refused.
        let mut constrained = add(
            wire::SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED,
            "ferris@example.com",
        );
        wire::SSH_AGENT_CONSTRAIN_EXTENSION
            .encode(&mut constrained)
            .unwrap();
        "restrict-destination-v00@openssh.com"
            .encode(&mut constrained)
            .unwrap();
        assert_eq!(agent.handle(&constrained), wire::failure());
        assert!(agent.entries().is_empty());
    }

    #[test]
    fn add_smartcard_key_uses_a_preloaded_key_without_the_device() {
        let e = entry();
        // The device is unplugged: preloading is the only source of the key.
        let opener: Opener = Arc::new(|| Err(DeviceError::Locked));
        let agent = Agent::new(vec![e.clone()], opener, Arc::new(RecordingSink::default()));
        let raw = protocol::RawPublicKey::Ed25519([0x22; 32]);
        let key = keys::public_key(&raw, &e.label()).unwrap();
        assert_eq!(agent.preload([key.clone()]), 1);

        let add_body = |kind: u8| {
            let mut add = vec![kind];
            b"ferris@example.com".as_slice().encode(&mut add).unwrap();
            b"".as_slice().encode(&mut add).unwrap();
            add
        };
        // A plain add and a constrained add both succeed from the cache,
        // without ever opening the device.
        assert_eq!(
            agent.handle(&add_body(wire::SSH_AGENTC_ADD_SMARTCARD_KEY)),
            wire::success()
        );
        let mut constrained = add_body(wire::SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED);
        wire::SSH_AGENT_CONSTRAIN_LIFETIME
            .encode(&mut constrained)
            .unwrap();
        60u32.encode(&mut constrained).unwrap();
        assert_eq!(agent.handle(&constrained), wire::success());
        assert_eq!(agent.public_keys(), vec![key]);
        assert_eq!(agent.entries(), vec![e]);
    }

    #[test]
    fn add_of_an_unknown_key_fails_when_the_device_is_absent() {
        let opener: Opener = Arc::new(|| Err(DeviceError::Locked));
        let agent = Agent::new(Vec::new(), opener, Arc::new(RecordingSink::default()));
        let mut add = vec![wire::SSH_AGENTC_ADD_SMARTCARD_KEY];
        b"ferris@example.com".as_slice().encode(&mut add).unwrap();
        b"".as_slice().encode(&mut add).unwrap();
        assert_eq!(agent.handle(&add), wire::failure());
        assert!(agent.entries().is_empty());
    }

    #[test]
    fn add_smartcard_key_is_refused_while_locked() {
        let opener: Opener = Arc::new(|| panic!("device must not be opened"));
        let agent = Agent::new(Vec::new(), opener, Arc::new(RecordingSink::default()));
        let mut lock = vec![wire::SSH_AGENTC_LOCK];
        b"hunter2".as_slice().encode(&mut lock).unwrap();
        assert_eq!(agent.handle(&lock), wire::success());

        let mut add = vec![wire::SSH_AGENTC_ADD_SMARTCARD_KEY];
        b"ferris@example.com".as_slice().encode(&mut add).unwrap();
        b"".as_slice().encode(&mut add).unwrap();
        assert_eq!(agent.handle(&add), wire::failure());
        assert!(agent.entries().is_empty());
    }

    #[test]
    fn remove_smartcard_key_is_refused_while_locked() {
        let e = entry();
        let opener: Opener = Arc::new(|| panic!("device must not be opened"));
        let agent = Agent::new(vec![e.clone()], opener, Arc::new(RecordingSink::default()));
        let mut lock = vec![wire::SSH_AGENTC_LOCK];
        b"hunter2".as_slice().encode(&mut lock).unwrap();
        assert_eq!(agent.handle(&lock), wire::success());

        let mut remove = vec![wire::SSH_AGENTC_REMOVE_SMARTCARD_KEY];
        b"ferris@example.com"
            .as_slice()
            .encode(&mut remove)
            .unwrap();
        b"".as_slice().encode(&mut remove).unwrap();
        assert_eq!(agent.handle(&remove), wire::failure());
        assert_eq!(agent.entries(), vec![e]);

        let mut unlock = vec![wire::SSH_AGENTC_UNLOCK];
        b"hunter2".as_slice().encode(&mut unlock).unwrap();
        assert_eq!(agent.handle(&unlock), wire::success());
        assert_eq!(agent.handle(&remove), wire::success());
        assert!(agent.entries().is_empty());
    }

    /// `ssh-add -d` of a token key's public key removes it, as it does for
    /// an in-memory key.
    #[test]
    fn remove_identity_removes_a_token_key_by_blob() {
        let e = entry();
        let opener: Opener = Arc::new(|| panic!("device must not be opened"));
        let agent = Agent::new(vec![e.clone()], opener, Arc::new(RecordingSink::default()));
        let raw = protocol::RawPublicKey::Ed25519([0x22; 32]);
        let key = keys::public_key(&raw, &e.label()).unwrap();
        assert_eq!(agent.preload([key.clone()]), 1);

        let mut remove = vec![wire::SSH2_AGENTC_REMOVE_IDENTITY];
        key.to_bytes().unwrap().encode(&mut remove).unwrap();
        assert_eq!(agent.handle(&remove), wire::success());
        assert!(agent.entries().is_empty());
        assert!(agent.public_keys().is_empty());
        assert_eq!(agent.handle(&remove), wire::failure());
    }

    #[test]
    fn expired_keys_drop_out_of_the_listing() {
        let e = entry();
        let opener: Opener = Arc::new(|| panic!("device must not be opened"));
        let agent = Agent::new(vec![e.clone()], opener, Arc::new(RecordingSink::default()));
        let raw = protocol::RawPublicKey::Ed25519([0x22; 32]);
        let key = keys::public_key(&raw, &e.label()).unwrap();
        assert_eq!(agent.preload([key]), 1);
        // Pretend the lifetime elapsed.
        agent.entries.lock().unwrap()[0].expires = Some(Instant::now());

        assert!(agent.public_keys().is_empty());
        assert!(agent.entries().is_empty());
        assert_eq!(
            agent.handle(&[wire::SSH2_AGENTC_REQUEST_IDENTITIES]),
            vec![12, 0, 0, 0, 0]
        );
    }

    fn local_key(seed: u8, comment: &str) -> (Vec<u8>, PublicKey) {
        use ssh_key::private::Ed25519Keypair;
        let pair = Ed25519Keypair::from_seed(&[seed; 32]);
        let public = PublicKey::new(ssh_key::public::KeyData::Ed25519(pair.public), comment);
        let mut body = vec![wire::SSH2_AGENTC_ADD_IDENTITY];
        "ssh-ed25519".encode(&mut body).unwrap();
        pair.encode(&mut body).unwrap();
        comment.encode(&mut body).unwrap();
        (body, public)
    }

    #[test]
    fn add_identity_signs_locally_without_the_device() {
        let opener: Opener = Arc::new(|| panic!("device must not be opened"));
        let agent = Agent::new(Vec::new(), opener, Arc::new(RecordingSink::default()));
        let (add, public) = local_key(0x11, "ferris@example.com");
        let blob = public.to_bytes().unwrap();

        assert_eq!(agent.handle(&add), wire::success());
        // Re-adding the same key is a successful no-op.
        assert_eq!(agent.handle(&add), wire::success());

        let reply = agent.handle(&[wire::SSH2_AGENTC_REQUEST_IDENTITIES]);
        assert_eq!(reply[0], wire::SSH2_AGENT_IDENTITIES_ANSWER);
        let mut r = &reply[5..];
        assert_eq!(Vec::<u8>::decode(&mut r).unwrap(), blob);
        assert_eq!(String::decode(&mut r).unwrap(), "ferris@example.com");
        assert!(r.is_empty());

        // Signing works with no device and no challenge, and verifies.
        let mut sign = vec![wire::SSH2_AGENTC_SIGN_REQUEST];
        blob.encode(&mut sign).unwrap();
        b"data".as_slice().encode(&mut sign).unwrap();
        0u32.encode(&mut sign).unwrap();
        let reply = agent.handle(&sign);
        assert_eq!(reply[0], wire::SSH2_AGENT_SIGN_RESPONSE);
        let mut r = &reply[1..];
        let sig_blob = Vec::<u8>::decode(&mut r).unwrap();
        let mut b = sig_blob.as_slice();
        assert_eq!(String::decode(&mut b).unwrap(), "ssh-ed25519");
        let sig = ssh_key::Signature::new(
            ssh_key::Algorithm::Ed25519,
            Vec::<u8>::decode(&mut b).unwrap(),
        )
        .unwrap();
        keys::verify(&public, b"data", &sig).unwrap();

        // Removing by public key blob takes it away.
        let mut remove = vec![wire::SSH2_AGENTC_REMOVE_IDENTITY];
        blob.encode(&mut remove).unwrap();
        assert_eq!(agent.handle(&remove), wire::success());
        assert_eq!(agent.handle(&remove), wire::failure());
        assert_eq!(
            agent.handle(&[wire::SSH2_AGENTC_REQUEST_IDENTITIES]),
            vec![12, 0, 0, 0, 0]
        );
    }

    /// Build an `ADD_IDENTITY` body for a made-up key type, `ssh-custom`,
    /// carrying the same body as an ed25519 key.
    fn custom_key(seed: u8, comment: &str) -> (Vec<u8>, PublicKey) {
        use ssh_key::private::Ed25519Keypair;
        let pair = Ed25519Keypair::from_seed(&[seed; 32]);
        let public = PublicKey::new(ssh_key::public::KeyData::Ed25519(pair.public), comment);
        let mut body = vec![wire::SSH2_AGENTC_ADD_IDENTITY];
        "ssh-custom@example.com".encode(&mut body).unwrap();
        pair.encode(&mut body).unwrap();
        comment.encode(&mut body).unwrap();
        (body, public)
    }

    /// A key type registered with `register_key_type` is served end to end:
    /// the agent decodes, lists and signs with it through the registry.
    #[test]
    fn a_registered_key_type_is_served_end_to_end() {
        struct CustomDecoder;

        impl KeyDecoder for CustomDecoder {
            fn key_types(&self) -> &[&str] {
                &["ssh-custom@example.com"]
            }

            fn decode(
                &self,
                _key_type: &str,
                reader: &mut &[u8],
            ) -> Result<crate::agent::HeldKey, crate::agent::KeyDecodeError> {
                crate::agent::local::decode("ssh-ed25519", reader).map(crate::agent::HeldKey::Local)
            }
        }

        let opener: Opener = Arc::new(|| panic!("device must not be opened"));
        let (add, public) = custom_key(0x21, "custom@example.com");
        let blob = public.to_bytes().unwrap();

        // Without the decoder the key type is unknown and the add fails...
        let plain = Agent::new(
            Vec::new(),
            Arc::clone(&opener),
            Arc::new(RecordingSink::default()),
        );
        assert_eq!(plain.handle(&add), wire::failure());

        // ...but registering it makes the agent decode and serve it.
        let agent = Agent::new(Vec::new(), opener, Arc::new(RecordingSink::default()))
            .with_key_type(CustomDecoder);
        assert_eq!(agent.handle(&add), wire::success());

        let reply = agent.handle(&[wire::SSH2_AGENTC_REQUEST_IDENTITIES]);
        let mut r = &reply[5..];
        assert_eq!(Vec::<u8>::decode(&mut r).unwrap(), blob);
        assert_eq!(String::decode(&mut r).unwrap(), "custom@example.com");

        let mut sign = vec![wire::SSH2_AGENTC_SIGN_REQUEST];
        blob.encode(&mut sign).unwrap();
        b"data".as_slice().encode(&mut sign).unwrap();
        0u32.encode(&mut sign).unwrap();
        let reply = agent.handle(&sign);
        assert_eq!(reply[0], wire::SSH2_AGENT_SIGN_RESPONSE);
        let mut r = &reply[1..];
        let sig_blob = Vec::<u8>::decode(&mut r).unwrap();
        let sig = ssh_key::Signature::try_from(sig_blob.as_slice()).unwrap();
        keys::verify(&public, b"data", &sig).unwrap();
    }

    fn local_rsa_key(comment: &str) -> (Vec<u8>, PublicKey) {
        local_rsa_key_from(include_str!("../../tests/common/rsa2048.pem"), comment)
    }

    fn local_rsa_key_from(pem: &str, comment: &str) -> (Vec<u8>, PublicKey) {
        use rsa::pkcs1::DecodeRsaPrivateKey;
        let sk = rsa::RsaPrivateKey::from_pkcs1_pem(pem).unwrap();
        let pair = ssh_key::private::RsaKeypair::try_from(&sk).unwrap();
        let public = PublicKey::new(ssh_key::public::KeyData::Rsa(pair.public.clone()), comment);
        let mut body = vec![wire::SSH2_AGENTC_ADD_IDENTITY];
        "ssh-rsa".encode(&mut body).unwrap();
        pair.encode(&mut body).unwrap();
        comment.encode(&mut body).unwrap();
        (body, public)
    }

    #[test]
    fn local_rsa_key_signs_with_the_requested_digest() {
        let opener: Opener = Arc::new(|| panic!("device must not be opened"));
        let agent = Agent::new(Vec::new(), opener, Arc::new(RecordingSink::default()));
        let (add, public) = local_rsa_key("old@example.com");
        let blob = public.to_bytes().unwrap();
        assert_eq!(agent.handle(&add), wire::success());

        let sign_request = |flags: u32| {
            let mut body = vec![wire::SSH2_AGENTC_SIGN_REQUEST];
            blob.encode(&mut body).unwrap();
            b"data".as_slice().encode(&mut body).unwrap();
            flags.encode(&mut body).unwrap();
            body
        };
        // The legacy SHA-1 `ssh-rsa` request is refused, like the token.
        assert_eq!(agent.handle(&sign_request(0)), wire::failure());

        for (flags, hash) in [
            (wire::SSH_AGENT_RSA_SHA2_256, HashAlg::Sha256),
            (wire::SSH_AGENT_RSA_SHA2_512, HashAlg::Sha512),
        ] {
            let reply = agent.handle(&sign_request(flags));
            assert_eq!(reply[0], wire::SSH2_AGENT_SIGN_RESPONSE);
            let mut r = &reply[1..];
            let sig_blob = Vec::<u8>::decode(&mut r).unwrap();
            let sig = ssh_key::Signature::try_from(sig_blob.as_slice()).unwrap();
            assert_eq!(
                sig.algorithm(),
                ssh_key::Algorithm::Rsa { hash: Some(hash) }
            );
            keys::verify(&public, b"data", &sig).unwrap();
        }
    }

    /// A 1024-bit and an 8192-bit RSA key both sign once added, though
    /// `ssh-key`'s own verifier only takes 2048 to 4096 bits.
    #[test]
    fn local_rsa_keys_of_any_accepted_size_sign() {
        let opener: Opener = Arc::new(|| panic!("device must not be opened"));
        let agent = Agent::new(Vec::new(), opener, Arc::new(RecordingSink::default()));
        for pem in [
            include_str!("../../tests/common/rsa1024.pem"),
            include_str!("../../tests/common/rsa8192.pem"),
        ] {
            let (add, public) = local_rsa_key_from(pem, "old@example.com");
            assert_eq!(agent.handle(&add), wire::success());
            let mut sign = vec![wire::SSH2_AGENTC_SIGN_REQUEST];
            public.to_bytes().unwrap().encode(&mut sign).unwrap();
            b"data".as_slice().encode(&mut sign).unwrap();
            wire::SSH_AGENT_RSA_SHA2_256.encode(&mut sign).unwrap();
            assert_eq!(agent.handle(&sign)[0], wire::SSH2_AGENT_SIGN_RESPONSE);
        }
    }

    fn local_ecdsa_key(curve: ssh_key::EcdsaCurve, comment: &str) -> (Vec<u8>, PublicKey) {
        let pair = ssh_key::private::EcdsaKeypair::random(&mut rand_core::OsRng, curve).unwrap();
        let public = PublicKey::new(
            ssh_key::public::KeyData::Ecdsa(ssh_key::public::EcdsaPublicKey::from(&pair)),
            comment,
        );
        let mut body = vec![wire::SSH2_AGENTC_ADD_IDENTITY];
        ssh_key::Algorithm::Ecdsa { curve }
            .as_str()
            .encode(&mut body)
            .unwrap();
        pair.encode(&mut body).unwrap();
        comment.encode(&mut body).unwrap();
        (body, public)
    }

    #[cfg(feature = "dsa")]
    fn local_dsa_key(comment: &str) -> (Vec<u8>, PublicKey) {
        let pair = ssh_key::private::DsaKeypair::random(&mut rand_core::OsRng).unwrap();
        let public = PublicKey::new(
            ssh_key::public::KeyData::Dsa(ssh_key::public::DsaPublicKey::from(&pair)),
            comment,
        );
        let mut body = vec![wire::SSH2_AGENTC_ADD_IDENTITY];
        "ssh-dss".encode(&mut body).unwrap();
        pair.encode(&mut body).unwrap();
        comment.encode(&mut body).unwrap();
        (body, public)
    }

    /// The ECDSA and DSA local keys are added and sign through the agent with
    /// no device and no challenge, as ed25519 and RSA do.
    #[test]
    fn local_ecdsa_and_dsa_keys_sign_without_the_device() {
        let opener: Opener = Arc::new(|| panic!("device must not be opened"));
        let agent = Agent::new(Vec::new(), opener, Arc::new(RecordingSink::default()));
        #[allow(unused_mut)]
        let mut cases = vec![
            local_ecdsa_key(ssh_key::EcdsaCurve::NistP256, "p256@example.com"),
            local_ecdsa_key(ssh_key::EcdsaCurve::NistP384, "p384@example.com"),
            local_ecdsa_key(ssh_key::EcdsaCurve::NistP521, "p521@example.com"),
        ];
        #[cfg(feature = "dsa")]
        cases.push(local_dsa_key("dsa@example.com"));
        for (add, public) in cases {
            let blob = public.to_bytes().unwrap();
            assert_eq!(agent.handle(&add), wire::success());
            let mut sign = vec![wire::SSH2_AGENTC_SIGN_REQUEST];
            blob.encode(&mut sign).unwrap();
            b"data".as_slice().encode(&mut sign).unwrap();
            0u32.encode(&mut sign).unwrap();
            let reply = agent.handle(&sign);
            assert_eq!(
                reply[0],
                wire::SSH2_AGENT_SIGN_RESPONSE,
                "{}",
                public.algorithm()
            );
            let mut r = &reply[1..];
            let sig_blob = Vec::<u8>::decode(&mut r).unwrap();
            let sig = ssh_key::Signature::try_from(sig_blob.as_slice()).unwrap();
            assert_eq!(sig.algorithm(), public.algorithm());
            keys::verify(&public, b"data", &sig).unwrap();

            let mut remove = vec![wire::SSH2_AGENTC_REMOVE_IDENTITY];
            blob.encode(&mut remove).unwrap();
            assert_eq!(agent.handle(&remove), wire::success());
        }
        assert!(agent.public_keys().is_empty());
    }

    #[test]
    fn remove_all_clears_token_and_local_keys() {
        let e = entry();
        let opener: Opener = Arc::new(|| panic!("device must not be opened"));
        let agent = Agent::new(vec![e.clone()], opener, Arc::new(RecordingSink::default()));
        let raw = protocol::RawPublicKey::Ed25519([0x22; 32]);
        assert_eq!(
            agent.preload([keys::public_key(&raw, &e.label()).unwrap()]),
            1
        );

        let (add, _) = local_key(0x11, "ferris@example.com");
        assert_eq!(agent.handle(&add), wire::success());
        assert_eq!(agent.public_keys().len(), 2);

        assert_eq!(
            agent.handle(&[wire::SSH_AGENTC_REMOVE_ALL_IDENTITIES]),
            wire::success()
        );
        assert!(agent.public_keys().is_empty());
        assert!(agent.entries().is_empty());
    }

    #[test]
    fn local_add_and_remove_all_are_refused_while_locked() {
        let opener: Opener = Arc::new(|| panic!("device must not be opened"));
        let agent = Agent::new(Vec::new(), opener, Arc::new(RecordingSink::default()));
        let mut lock = vec![wire::SSH_AGENTC_LOCK];
        b"hunter2".as_slice().encode(&mut lock).unwrap();
        assert_eq!(agent.handle(&lock), wire::success());

        let (add, public) = local_key(0x11, "ferris@example.com");
        assert_eq!(agent.handle(&add), wire::failure());
        assert!(agent.public_keys().is_empty());
        assert_eq!(
            agent.handle(&[wire::SSH_AGENTC_REMOVE_ALL_IDENTITIES]),
            wire::failure()
        );

        let mut remove = vec![wire::SSH2_AGENTC_REMOVE_IDENTITY];
        public.to_bytes().unwrap().encode(&mut remove).unwrap();
        assert_eq!(agent.handle(&remove), wire::failure());
    }

    #[test]
    fn local_key_lifetime_expires() {
        let opener: Opener = Arc::new(|| panic!("device must not be opened"));
        let agent = Agent::new(Vec::new(), opener, Arc::new(RecordingSink::default()));
        let (add, _) = local_key(0x11, "ferris@example.com");
        // A constrained add with a one-second lifetime.
        let mut constrained = add;
        constrained[0] = wire::SSH2_AGENTC_ADD_ID_CONSTRAINED;
        wire::SSH_AGENT_CONSTRAIN_LIFETIME
            .encode(&mut constrained)
            .unwrap();
        1u32.encode(&mut constrained).unwrap();
        assert_eq!(agent.handle(&constrained), wire::success());
        assert_eq!(agent.public_keys().len(), 1);

        // Pretend the lifetime elapsed.
        agent.held.lock().unwrap()[0].expires = Some(Instant::now());
        assert!(agent.public_keys().is_empty());
    }

    /// A security key enrolled for a website, not `ssh:`, signs SSH data only:
    /// arbitrary data is refused before the authenticator is even opened.
    #[test]
    fn a_non_ssh_security_key_signs_only_ssh_data() {
        use crate::agent::sk::SK_SSH_ED25519;
        use crate::fido::fake::FakeFido;
        use ssh_key::private::SkEd25519;
        use ssh_key::public::{Ed25519PublicKey, KeyData, SkEd25519 as SkEd25519Public};
        use std::sync::atomic::AtomicUsize;

        let seed = [0x24u8; 32];
        let handle = [1u8, 2, 3];
        let app = "https://example.com";
        let probe = FakeFido::new(&seed, app, &handle, 0x01);
        let public = SkEd25519Public::new(Ed25519PublicKey(probe.public()), app);
        let key_blob = PublicKey::new(KeyData::SkEd25519(public.clone()), "web")
            .to_bytes()
            .unwrap();
        let pair = SkEd25519::new(public, 0x01, handle).unwrap();
        let mut add = vec![wire::SSH2_AGENTC_ADD_IDENTITY];
        SK_SSH_ED25519.encode(&mut add).unwrap();
        pair.encode(&mut add).unwrap();
        "web".encode(&mut add).unwrap();

        let opens = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&opens);
        let opener: Opener = Arc::new(|| panic!("OnlyKey must not be opened"));
        let sk_opener: SkOpener = Arc::new(move || {
            counter.fetch_add(1, Ordering::SeqCst);
            let device = FakeFido::new(&seed, app, &handle, 0x01).with_touch();
            Ok(vec![Box::new(device) as Box<dyn HidTransport>])
        });
        let agent = Agent::new(Vec::new(), opener, Arc::new(RecordingSink::default()))
            .with_sk_opener(sk_opener);
        assert_eq!(agent.handle(&add), wire::success());

        let sign = |data: &[u8]| {
            let mut body = vec![wire::SSH2_AGENTC_SIGN_REQUEST];
            key_blob.encode(&mut body).unwrap();
            data.encode(&mut body).unwrap();
            0u32.encode(&mut body).unwrap();
            agent.handle(&body)
        };
        assert_eq!(sign(b"a webauthn challenge"), wire::failure());
        assert_eq!(opens.load(Ordering::SeqCst), 0);

        let mut sshsig = b"SSHSIG".to_vec();
        "file".encode(&mut sshsig).unwrap();
        assert_eq!(sign(&sshsig)[0], wire::SSH2_AGENT_SIGN_RESPONSE);
        assert_eq!(opens.load(Ordering::SeqCst), 1);
    }

    /// With two authenticators attached, the one holding the credential is
    /// found by a silent probe and signs; the other is never asked to.
    #[test]
    fn the_authenticator_holding_the_credential_signs() {
        use crate::agent::sk::SK_SSH_ED25519;
        use crate::fido::fake::FakeFido;
        use ssh_key::private::SkEd25519;
        use ssh_key::public::{Ed25519PublicKey, KeyData, SkEd25519 as SkEd25519Public};

        let seed = [0x42u8; 32];
        let handle = [9u8, 8, 7];
        let probe = FakeFido::new(&seed, "ssh:", &handle, 0x01);
        let public = SkEd25519Public::new(Ed25519PublicKey(probe.public()), "ssh:");
        let key_blob = PublicKey::new(KeyData::SkEd25519(public.clone()), "two")
            .to_bytes()
            .unwrap();
        let pair = SkEd25519::new(public, 0x01, handle).unwrap();
        let mut add = vec![wire::SSH2_AGENTC_ADD_IDENTITY];
        SK_SSH_ED25519.encode(&mut add).unwrap();
        pair.encode(&mut add).unwrap();
        "two".encode(&mut add).unwrap();

        let opener: Opener = Arc::new(|| panic!("OnlyKey must not be opened"));
        let sk_opener: SkOpener = Arc::new(move || {
            // Another key, holding another credential, enumerates first.
            let other = FakeFido::new(&[0x07; 32], "ssh:", &[1, 1, 1], 0x01).with_touch();
            let holder = FakeFido::new(&seed, "ssh:", &handle, 0x01).with_touch();
            Ok(vec![
                Box::new(other) as Box<dyn HidTransport>,
                Box::new(holder) as Box<dyn HidTransport>,
            ])
        });
        let sink = Arc::new(RecordingSink::default());
        let agent = Agent::new(
            Vec::new(),
            opener,
            Arc::clone(&sink) as Arc<dyn ChallengeSink>,
        )
        .with_sk_opener(sk_opener);
        assert_eq!(agent.handle(&add), wire::success());

        let mut sign = vec![wire::SSH2_AGENTC_SIGN_REQUEST];
        key_blob.encode(&mut sign).unwrap();
        b"data".as_slice().encode(&mut sign).unwrap();
        0u32.encode(&mut sign).unwrap();
        let reply = agent.handle(&sign);
        assert_eq!(reply[0], wire::SSH2_AGENT_SIGN_RESPONSE);
        // Only the real signature asked for a touch, not the probes.
        assert_eq!(sink.1.lock().unwrap().len(), 1);
    }

    /// An `sk-ssh-ed25519` key added with `ssh-add FILE` is listed, signs
    /// through the (fake) authenticator, and is removed by public key.
    #[test]
    fn security_key_adds_lists_signs_and_removes() {
        use crate::agent::sk::SK_SSH_ED25519;
        use crate::fido::fake::FakeFido;
        use ssh_key::private::SkEd25519;
        use ssh_key::public::{Ed25519PublicKey, KeyData, SkEd25519 as SkEd25519Public};

        let seed = [0x42u8; 32];
        let handle = [9u8, 8, 7];

        // The key file body, as `ssh-add id_ed25519_sk` would send it.
        let probe = FakeFido::new(&seed, "ssh:", &handle, 0x01);
        let public = SkEd25519Public::new(Ed25519PublicKey(probe.public()), "ssh:");
        let key_blob = PublicKey::new(KeyData::SkEd25519(public.clone()), "ferris@example.com")
            .to_bytes()
            .unwrap();
        let pair = SkEd25519::new(public, 0x01, handle).unwrap();
        let mut add = vec![wire::SSH2_AGENTC_ADD_IDENTITY];
        SK_SSH_ED25519.encode(&mut add).unwrap();
        pair.encode(&mut add).unwrap();
        "ferris@example.com".encode(&mut add).unwrap();

        let opener: Opener = Arc::new(|| panic!("OnlyKey must not be opened"));
        let sk_opener: SkOpener = Arc::new(move || {
            let device = FakeFido::new(&seed, "ssh:", &handle, 0x01).with_touch();
            Ok(vec![Box::new(device) as Box<dyn HidTransport>])
        });
        let sink = Arc::new(RecordingSink::default());
        let agent = Agent::new(
            Vec::new(),
            opener,
            Arc::clone(&sink) as Arc<dyn ChallengeSink>,
        )
        .with_sk_opener(sk_opener);

        assert_eq!(agent.handle(&add), wire::success());

        // It is listed with its comment.
        let reply = agent.handle(&[wire::SSH2_AGENTC_REQUEST_IDENTITIES]);
        assert_eq!(reply[0], wire::SSH2_AGENT_IDENTITIES_ANSWER);
        let mut r = &reply[5..];
        assert_eq!(Vec::<u8>::decode(&mut r).unwrap(), key_blob);
        assert_eq!(String::decode(&mut r).unwrap(), "ferris@example.com");

        // Signing drives the authenticator and verifies.
        let mut sign = vec![wire::SSH2_AGENTC_SIGN_REQUEST];
        key_blob.encode(&mut sign).unwrap();
        b"data".as_slice().encode(&mut sign).unwrap();
        0u32.encode(&mut sign).unwrap();
        let reply = agent.handle(&sign);
        assert_eq!(reply[0], wire::SSH2_AGENT_SIGN_RESPONSE);
        let mut r = &reply[1..];
        let sig_blob = Vec::<u8>::decode(&mut r).unwrap();
        let sig = ssh_key::Signature::try_from(sig_blob.as_slice()).unwrap();
        assert_eq!(sig.algorithm(), ssh_key::Algorithm::SkEd25519);
        let public_key = PublicKey::from_bytes(&key_blob).unwrap();
        keys::verify(&public_key, b"data", &sig).unwrap();

        // The touch request reached the sink, naming the key.
        let touches = sink.1.lock().unwrap();
        assert_eq!(touches.len(), 1);
        assert_eq!(touches[0].identity, "ferris@example.com");
        drop(touches);

        // Removing by public key takes it away.
        let mut remove = vec![wire::SSH2_AGENTC_REMOVE_IDENTITY];
        key_blob.encode(&mut remove).unwrap();
        assert_eq!(agent.handle(&remove), wire::success());
        assert_eq!(agent.handle(&remove), wire::failure());
        assert!(agent.public_keys().is_empty());
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
