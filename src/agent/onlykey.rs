//! The OnlyKey as an [`ssh_agent_kit`] backend: the keys from the config and
//! `--identity`, plus those `ssh-add -s LABEL` adds, each signed on the
//! token after the user enters its challenge.

use super::server::AgentError;
use crate::challenge::ChallengeSink;
use crate::device::{DeviceError, OnlyKey};
use crate::identity::KeySpec;
use crate::keys;
use crate::transport::HidTransport;
use ssh_agent_kit::backend::{Backend, Expiring, Removed, SmartcardProvider};
use ssh_agent_kit::signer::{BoxError, Signer, SignerRef};
use ssh_agent_kit::wire;
use ssh_key::{HashAlg, PublicKey, Signature};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use zeroize::Zeroizing;

/// A device the agent can open on demand.
pub type Device = OnlyKey<Box<dyn HidTransport>>;
/// How the agent obtains a device for each operation.
pub type Opener = Arc<dyn Fn() -> Result<Device, DeviceError> + Send + Sync>;

/// Lock `mutex`, carrying on if a thread panicked while holding it: each
/// value guarded here is left consistent between statements, so a poisoned
/// lock still holds usable state.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|p| p.into_inner())
}

/// What signing on the token needs, shared with each key's [`Signer`].
struct Token {
    opener: Opener,
    sink: Arc<dyn ChallengeSink>,
    /// Serialises every device operation, including the wait for the user.
    device_lock: Mutex<()>,
}

/// The OnlyKey keys the agent serves. Each [`KeySpec`] is one identity in
/// the SSH sense.
pub struct OnlyKeyBackend {
    token: Arc<Token>,
    entries: Mutex<Vec<Expiring<KeySpec>>>,
    cache: Mutex<HashMap<KeySpec, PublicKey>>,
}

impl OnlyKeyBackend {
    /// Serve `entries`, opening the token with `opener` and showing its
    /// challenges through `sink`.
    pub fn new(entries: Vec<KeySpec>, opener: Opener, sink: Arc<dyn ChallengeSink>) -> Self {
        OnlyKeyBackend {
            token: Arc::new(Token {
                opener,
                sink,
                device_lock: Mutex::new(()),
            }),
            entries: Mutex::new(
                entries
                    .into_iter()
                    .map(|spec| Expiring::new(spec, None))
                    .collect(),
            ),
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// The identities currently served, in order. A snapshot, since the list
    /// can change at runtime through [`Self::add`] and [`Self::remove`].
    pub fn entries(&self) -> Vec<KeySpec> {
        self.purge_entries();
        lock(&self.entries).iter().map(|e| e.item.clone()).collect()
    }

    /// Add `spec` to the served identities. If its public key is already
    /// known (from [`Self::preload`] or an earlier fetch) it is served from
    /// the cache and the device is not touched; otherwise the key is fetched
    /// and verified against the device. Re-adding a listed key moves it to
    /// the end and restarts its lifetime. `lifetime` is the `ssh-add -t`
    /// constraint in seconds, if any.
    pub fn add(&self, spec: KeySpec, lifetime: Option<u32>) -> Result<PublicKey, AgentError> {
        self.purge_entries();
        let key = self.derive_one(&spec)?;
        let mut entries = lock(&self.entries);
        entries.retain(|e| e.item != spec);
        entries.push(Expiring::new(spec.clone(), lifetime));
        drop(entries);
        tracing::info!(identity = %spec.identity, key = %spec.kind, "serving key");
        Ok(key)
    }

    /// Remove every entry matching `spec` (from the config or added at
    /// runtime) and forget its key. Returns whether it was served, and the
    /// key's blob if it was known.
    pub fn remove(&self, spec: &KeySpec) -> Removed {
        let mut entries = lock(&self.entries);
        let before = entries.len();
        entries.retain(|e| &e.item != spec);
        let served = entries.len() != before;
        drop(entries);
        let key_blob = lock(&self.cache)
            .remove(spec)
            .and_then(|key| key.to_bytes().ok());
        Removed { served, key_blob }
    }

    /// Drop entries whose lifetime has elapsed, along with their cached keys.
    fn purge_entries(&self) {
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
    pub fn public_keys(&self) -> Vec<(KeySpec, PublicKey)> {
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
            let _guard = lock(&self.token.device_lock);
            match (self.token.opener)() {
                Ok(mut device) => {
                    for entry in &missing {
                        match device.ssh_public_key(entry) {
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
        self.cached(entries)
    }

    /// The cached keys of `entries`, in order.
    fn cached(&self, entries: Vec<KeySpec>) -> Vec<(KeySpec, PublicKey)> {
        let cache = lock(&self.cache);
        entries
            .into_iter()
            .filter_map(|e| cache.get(&e).cloned().map(|key| (e, key)))
            .collect()
    }

    /// Fetch every key now; fails on the first problem. Used by commands that
    /// need all keys up front.
    pub fn derive_all(&self) -> Result<Vec<PublicKey>, AgentError> {
        let entries = self.entries();
        let _guard = lock(&self.token.device_lock);
        let mut device = None;
        let mut out = Vec::with_capacity(entries.len());
        for entry in &entries {
            let cached = lock(&self.cache).get(entry).cloned();
            let key = match cached {
                Some(key) => key,
                None => {
                    if device.is_none() {
                        device = Some((self.token.opener)()?);
                    }
                    let device = device.as_mut().expect("just opened");
                    let key = device.ssh_public_key(entry)?;
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
        let _guard = lock(&self.token.device_lock);
        let mut device = (self.token.opener)()?;
        let key = device.ssh_public_key(entry)?;
        lock(&self.cache).insert(entry.clone(), key.clone());
        Ok(key)
    }

    /// Put `key` in the cache for `spec`, as a fetch would.
    #[cfg(test)]
    pub(crate) fn cache_key(&self, spec: KeySpec, key: PublicKey) {
        lock(&self.cache).insert(spec, key);
    }

    /// End every entry's lifetime now, as if it had run out.
    #[cfg(test)]
    pub(crate) fn expire_now(&self) {
        for entry in lock(&self.entries).iter_mut() {
            entry.expires = Some(std::time::Instant::now());
        }
    }

    fn signer(&self, spec: KeySpec, public: PublicKey) -> SignerRef {
        SignerRef::new(TokenKey {
            spec,
            public,
            token: Arc::clone(&self.token),
        })
    }

    /// Turn an `ssh-add -s`/`-e` provider string into a key: a full label
    /// (`<ssh://[user@]host|curve[|slot]>`) or a bare `[user@]host` for a
    /// derived ed25519 key.
    fn provider_spec(provider: &[u8]) -> Result<KeySpec, AgentError> {
        let text = std::str::from_utf8(provider).map_err(|_| AgentError::BadProvider)?;
        let spec = KeySpec::parse_arg(text)?;
        if spec.identity.is_transliterated() {
            tracing::warn!(identity = %spec.identity, ascii = spec.identity.derivation_input(), "identity was transliterated to ASCII before hashing: it derives the same key as the ASCII identity, and as any other that transliterates to it");
        }
        Ok(spec)
    }
}

impl Backend for OnlyKeyBackend {
    fn identities(&self) -> Vec<SignerRef> {
        self.public_keys()
            .into_iter()
            .map(|(spec, key)| self.signer(spec, key))
            .collect()
    }

    /// The served keys whose public key is known: a sign request never
    /// waits for a key to be fetched.
    fn known(&self) -> Vec<SignerRef> {
        self.cached(self.entries())
            .into_iter()
            .map(|(spec, key)| self.signer(spec, key))
            .collect()
    }

    fn remove(&self, key_blob: &[u8]) -> bool {
        let spec = self
            .cached(self.entries())
            .into_iter()
            .find(|(_, key)| key.to_bytes().is_ok_and(|b| b == key_blob))
            .map(|(spec, _)| spec);
        match spec {
            Some(spec) => {
                tracing::info!(identity = %spec.identity, key = %spec.kind, "removing key");
                OnlyKeyBackend::remove(self, &spec).served
            }
            None => false,
        }
    }

    fn remove_all(&self) {
        lock(&self.entries).clear();
        lock(&self.cache).clear();
    }

    fn purge_expired(&self) {
        self.purge_entries();
    }
}

impl SmartcardProvider for OnlyKeyBackend {
    fn resolve(&self, provider: &[u8], _pin: &Zeroizing<Vec<u8>>) -> Result<SignerRef, BoxError> {
        let spec = Self::provider_spec(provider)?;
        let key = self.derive_one(&spec)?;
        Ok(self.signer(spec, key))
    }

    fn add(
        &self,
        provider: &[u8],
        _pin: &Zeroizing<Vec<u8>>,
        lifetime: Option<u32>,
    ) -> Result<(), BoxError> {
        let spec = Self::provider_spec(provider)?;
        OnlyKeyBackend::add(self, spec, lifetime)?;
        Ok(())
    }

    fn remove(&self, provider: &[u8]) -> Result<Removed, BoxError> {
        let spec = Self::provider_spec(provider)?;
        let removed = OnlyKeyBackend::remove(self, &spec);
        if removed.served {
            tracing::info!(identity = %spec.identity, key = %spec.kind, "removed key");
        }
        Ok(removed)
    }
}

/// One OnlyKey key, signed on the token.
struct TokenKey {
    spec: KeySpec,
    public: PublicKey,
    token: Arc<Token>,
}

impl Signer for TokenKey {
    fn public_key(&self) -> &PublicKey {
        &self.public
    }

    fn sign(&self, data: &[u8], hash: HashAlg) -> Result<Signature, BoxError> {
        let entry = &self.spec;
        let subject = wire::describe_data(data);
        let _guard = lock(&self.token.device_lock);
        let mut device = (self.token.opener)().map_err(AgentError::from)?;
        let raw = device
            .sign(entry, data, hash, subject, self.token.sink.as_ref())
            .map_err(AgentError::from)?;
        drop(device);
        let sig = keys::signature(&entry.kind.signature_algorithm(hash), &raw)
            .map_err(AgentError::from)?;
        tracing::info!(identity = %entry.identity, key = %entry.kind, algorithm = %sig.algorithm(), "signed");
        Ok(sig)
    }
}
