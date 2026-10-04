//! okagent's agent: an [`ssh_agent_kit::Agent`] serving the OnlyKey's keys
//! and FIDO security keys, with the token's challenge as the prompt.

use super::onlykey::{OnlyKeyBackend, Opener};
use super::sk::{SkBackend, SkDecoder, SkOpener};
use crate::challenge::{ChallengeSink, ConfirmRequest, PinPrompt};
use crate::device::DeviceError;
use crate::fido::FidoError;
use crate::identity::KeySpec;
use crate::keys;
use ssh_agent_kit::destination::Connection;
use ssh_agent_kit::policy::Confirm;
use ssh_agent_kit::server::Handler;
use ssh_agent_kit::{CertKey, Extension, KeyDecoder};
use ssh_key::PublicKey;
use std::ops::Deref;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;

/// What the OnlyKey and security-key backends report when they cannot
/// fetch a key or sign. The agent sees these as
/// [`ssh_agent_kit::AgentError::Backend`].
#[derive(Debug, Error)]
pub enum AgentError {
    #[error(transparent)]
    Device(#[from] DeviceError),
    #[error(transparent)]
    Key(#[from] keys::KeyError),
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
}

/// The agent okagent serves: the kit's agent with the OnlyKey as its
/// backend and smartcard provider, FIDO `sk-` keys decodable with
/// `ssh-add FILE`, and `ssh-add -c` confirmations shown through the same
/// [`ChallengeSink`] as the token's challenges.
///
/// Everything the kit's agent does is reached through `Deref`.
pub struct Agent {
    kit: ssh_agent_kit::Agent,
    onlykey: Arc<OnlyKeyBackend>,
    sk: Arc<SkBackend>,
}

/// `ssh-add -c` asks through the challenge sink.
struct SinkConfirm(Arc<dyn ChallengeSink>);

impl Confirm for SinkConfirm {
    fn confirm(&self, request: &ConfirmRequest) -> Option<bool> {
        self.0.confirm(request)
    }
}

impl Agent {
    pub fn new(entries: Vec<KeySpec>, opener: Opener, sink: Arc<dyn ChallengeSink>) -> Self {
        let onlykey = Arc::new(OnlyKeyBackend::new(entries, opener, Arc::clone(&sink)));
        let sk = Arc::new(SkBackend::new(Arc::clone(&sink)));
        let kit = ssh_agent_kit::Agent::new()
            .with_backend(Arc::clone(&onlykey) as _)
            .with_smartcard(Arc::clone(&onlykey) as _)
            .with_key_type(SkDecoder(Arc::clone(&sk)))
            .with_lifecycle(Arc::clone(&sk) as _)
            .with_confirm(Arc::new(SinkConfirm(sink)));
        Agent { kit, onlykey, sk }
    }

    /// The OnlyKey backend.
    pub fn onlykey(&self) -> &OnlyKeyBackend {
        &self.onlykey
    }

    /// The security-key backend.
    pub fn security_keys(&self) -> &SkBackend {
        &self.sk
    }

    /// Replace how FIDO authenticators are opened (for tests and for a fixed
    /// `--fido-device` path).
    pub fn with_sk_opener(self, opener: SkOpener) -> Self {
        self.sk.set_opener(opener);
        self
    }

    /// Ask for security key PINs with `prompt`, so keys enrolled with user
    /// verification required (`ssh-keygen -O verify-required`) can sign.
    pub fn with_pin_prompt(self, prompt: Arc<dyn PinPrompt>) -> Self {
        self.sk.set_pin_prompt(prompt);
        self
    }

    /// Keep a security key's PIN token for `duration` after the PIN is
    /// entered, so signatures within that time ask only for a touch. Zero
    /// keeps nothing, which is the default. The tokens are dropped when the
    /// agent is locked or every identity is removed.
    pub fn with_pin_cache(self, duration: Duration) -> Self {
        self.sk.set_pin_cache(duration);
        self
    }

    /// Give keys added without an `ssh-add -t` constraint a lifetime of
    /// `seconds`, as `ssh-agent -t` does. Zero or `None` means no default.
    pub fn with_default_lifetime(mut self, seconds: Option<u32>) -> Self {
        self.kit = self.kit.with_default_lifetime(seconds);
        self
    }

    /// Wait `backoff` longer after each wrong unlock passphrase.
    pub fn with_unlock_backoff(mut self, backoff: Duration) -> Self {
        self.kit = self.kit.with_unlock_backoff(backoff);
        self
    }

    /// Register a protocol extension handler. A later registration under the
    /// same name wins.
    pub fn with_extension(self, extension: impl Extension + 'static) -> Self {
        self.kit.register_extension(extension);
        self
    }

    /// Register a key-type decoder for `ssh-add FILE`. A later registration
    /// under a name wins.
    pub fn with_key_type(self, decoder: impl KeyDecoder + 'static) -> Self {
        self.kit.register_key_type(decoder);
        self
    }

    /// Serve certificates for token keys, loaded with `--cert-file`. Each is
    /// listed, under its file's comment (else its key id), while a served key
    /// it certifies is known and it has not expired.
    pub fn with_certificates(mut self, certs: impl IntoIterator<Item = CertKey>) -> Self {
        self.kit = self.kit.with_certificates(certs);
        self
    }

    /// The token identities currently served, in order.
    pub fn entries(&self) -> Vec<KeySpec> {
        self.onlykey.entries()
    }

    /// Serve the token key `spec`, fetching its public key unless it is
    /// cached. `lifetime` is the `ssh-add -t` constraint in seconds, if any.
    pub fn add(&self, spec: KeySpec, lifetime: Option<u32>) -> Result<PublicKey, AgentError> {
        self.onlykey.add(spec, lifetime)
    }

    /// Stop serving the token key `spec`, along with the certificates
    /// `ssh-add -s` attached to it. Returns whether anything was removed.
    pub fn remove(&self, spec: &KeySpec) -> bool {
        let removed = self.onlykey.remove(spec);
        let mut any = removed.served;
        if let Some(blob) = removed.key_blob {
            any |= self.kit.release(&blob, removed.served);
        }
        any
    }

    /// Seed the token key cache from previously exported public keys,
    /// matched by their comment. Returns how many matched.
    pub fn preload(&self, keys: impl IntoIterator<Item = PublicKey>) -> usize {
        self.onlykey.preload(keys)
    }

    /// Fetch every token key now; fails on the first problem.
    pub fn derive_all(&self) -> Result<Vec<PublicKey>, AgentError> {
        self.onlykey.derive_all()
    }

    /// Fetch one token key now; fails if the device is unavailable.
    pub fn derive_one(&self, entry: &KeySpec) -> Result<PublicKey, AgentError> {
        self.onlykey.derive_one(entry)
    }
}

impl Deref for Agent {
    type Target = ssh_agent_kit::Agent;

    fn deref(&self) -> &ssh_agent_kit::Agent {
        &self.kit
    }
}

impl Handler for Agent {
    fn handle_in(&self, body: &[u8], connection: &mut Connection) -> Vec<u8> {
        self.kit.handle_in(body, connection)
    }

    fn tick(&self) {
        self.kit.purge_expired();
    }
}

/// Where the agent listens by default: `$XDG_RUNTIME_DIR/okagent/agent.sock`,
/// else `$TMPDIR/okagent/agent.sock` on macOS, else
/// `/tmp/okagent-<uid>/agent.sock`.
pub fn default_socket_path() -> PathBuf {
    ssh_agent_kit::default_socket_path("okagent")
}

/// A fresh per-process socket path for `run`-style invocations.
pub fn ephemeral_socket_path() -> PathBuf {
    ssh_agent_kit::ephemeral_socket_path("okagent")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::{ExtensionContext, ExtensionReply};
    use crate::challenge::RecordingSink;
    use crate::device::OnlyKey;
    use crate::device::Timeouts;
    use crate::identity::{Curve, EccSlot};
    use crate::protocol::{self, Report};
    use crate::transport::HidTransport;
    use crate::transport::fake::{ScriptedTransport, Step};
    use ssh_agent_kit::wire;
    use ssh_encoding::Decode;
    use ssh_key::HashAlg;
    use std::sync::Mutex;
    use std::sync::atomic::Ordering;

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
        agent.onlykey().expire_now();

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
            ) -> Result<crate::agent::SignerRef, crate::agent::KeyDecodeError> {
                crate::agent::local::decode("ssh-ed25519", reader).map(crate::agent::SignerRef::new)
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

    /// The identities a listing reply carries, as (blob, comment).
    fn listing(agent: &Agent) -> Vec<wire::Listed> {
        let reply = agent.handle(&[wire::SSH2_AGENTC_REQUEST_IDENTITIES]);
        assert_eq!(reply[0], wire::SSH2_AGENT_IDENTITIES_ANSWER);
        let mut r = &reply[1..];
        let count = u32::decode(&mut r).unwrap();
        let out = (0..count)
            .map(|_| {
                (
                    Vec::<u8>::decode(&mut r).unwrap(),
                    String::decode(&mut r).unwrap(),
                )
            })
            .collect();
        assert!(r.is_empty());
        out
    }

    fn sign_body(blob: &[u8], data: &[u8]) -> Vec<u8> {
        let mut sign = vec![wire::SSH2_AGENTC_SIGN_REQUEST];
        blob.encode(&mut sign).unwrap();
        data.encode(&mut sign).unwrap();
        0u32.encode(&mut sign).unwrap();
        sign
    }

    #[test]
    fn an_added_certificate_is_listed_signs_and_is_removed() {
        use ssh_agent_kit::testing::{cert_body, certify};
        use ssh_key::private::Ed25519Keypair;
        let opener: Opener = Arc::new(|| panic!("device must not be opened"));
        let agent = Agent::new(Vec::new(), opener, Arc::new(RecordingSink::default()));
        let (add, public) = local_key(0x11, "ferris@example.com");
        let cert = certify(public.key_data());
        let mut private = Vec::new();
        Ed25519Keypair::from_seed(&[0x11; 32])
            .encode(&mut private)
            .unwrap();
        let mut add_cert = vec![wire::SSH2_AGENTC_ADD_IDENTITY];
        "ssh-ed25519-cert-v01@openssh.com"
            .encode(&mut add_cert)
            .unwrap();
        add_cert.extend(cert_body(&cert, &private, "ferris@example.com"));

        // ssh-add sends the key, then its certificate: both are listed.
        assert_eq!(agent.handle(&add), wire::success());
        assert_eq!(agent.handle(&add_cert), wire::success());
        assert_eq!(agent.handle(&add_cert), wire::success());
        let key_blob = public.to_bytes().unwrap();
        assert_eq!(
            listing(&agent),
            vec![
                (key_blob.clone(), "ferris@example.com".to_owned()),
                (cert.blob().to_vec(), "ferris@example.com".to_owned()),
            ]
        );
        assert_eq!(agent.certificates_for(&public), vec![cert.clone()]);

        // Signing for the certificate signs with the certified key.
        let reply = agent.handle(&sign_body(cert.blob(), b"data"));
        assert_eq!(reply[0], wire::SSH2_AGENT_SIGN_RESPONSE);
        let mut r = &reply[1..];
        let sig =
            ssh_key::Signature::try_from(Vec::<u8>::decode(&mut r).unwrap().as_slice()).unwrap();
        keys::verify(&public, b"data", &sig).unwrap();

        // Removing the plain key leaves the certificate, which still signs.
        let mut remove = vec![wire::SSH2_AGENTC_REMOVE_IDENTITY];
        key_blob.encode(&mut remove).unwrap();
        assert_eq!(agent.handle(&remove), wire::success());
        assert_eq!(listing(&agent).len(), 1);
        assert_eq!(agent.handle(&sign_body(cert.blob(), b"data"))[0], 14);
        let mut remove = vec![wire::SSH2_AGENTC_REMOVE_IDENTITY];
        cert.blob().encode(&mut remove).unwrap();
        assert_eq!(agent.handle(&remove), wire::success());
        assert_eq!(agent.handle(&remove), wire::failure());
        assert!(listing(&agent).is_empty());
        assert_eq!(
            agent.handle(&sign_body(cert.blob(), b"data")),
            wire::failure()
        );

        // `ssh-add -D` takes certificates too.
        assert_eq!(agent.handle(&add_cert), wire::success());
        assert_eq!(
            agent.handle(&[wire::SSH_AGENTC_REMOVE_ALL_IDENTITIES]),
            wire::success()
        );
        assert!(listing(&agent).is_empty());
    }

    /// A token key whose public key is known without the device.
    fn preloaded_agent(entries: Vec<KeySpec>) -> (Agent, PublicKey) {
        let opener: Opener = Arc::new(|| panic!("device must not be opened"));
        let agent = Agent::new(entries, opener, Arc::new(RecordingSink::default()));
        let raw = protocol::RawPublicKey::Ed25519([0x22; 32]);
        let key = keys::public_key(&raw, &entry().label()).unwrap();
        (agent, key)
    }

    /// `ssh-add -s PROVIDER [-C] CERT…` with `certs`.
    fn add_card_with_certs(certs_only: bool, certs: &[&CertKey]) -> Vec<u8> {
        let mut add = vec![wire::SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED];
        b"ferris@example.com".as_slice().encode(&mut add).unwrap();
        b"".as_slice().encode(&mut add).unwrap();
        wire::SSH_AGENT_CONSTRAIN_EXTENSION
            .encode(&mut add)
            .unwrap();
        crate::agent::cert::ASSOCIATED_CERTS
            .encode(&mut add)
            .unwrap();
        u8::from(certs_only).encode(&mut add).unwrap();
        let mut list = Vec::new();
        for cert in certs {
            cert.blob().encode(&mut list).unwrap();
        }
        list.encode(&mut add).unwrap();
        add
    }

    #[test]
    fn smartcard_certificates_attach_to_the_token_key() {
        use ssh_agent_kit::testing::certify;
        let (agent, key) = preloaded_agent(Vec::new());
        // Seed the cache as an earlier fetch would.
        agent.onlykey().cache_key(entry(), key.clone());
        let cert = certify(key.key_data());
        let other = certify(&ssh_key::public::KeyData::Ed25519(
            ssh_key::public::Ed25519PublicKey([0x99; 32]),
        ));

        // `-C`: only the certificate is served, and it resolves to the token.
        assert_eq!(
            agent.handle(&add_card_with_certs(true, &[&cert, &other])),
            wire::success()
        );
        assert_eq!(
            listing(&agent),
            vec![(cert.blob().to_vec(), entry().label())]
        );
        assert!(matches!(
            agent.signer_for(cert.blob()),
            Ok(signer) if signer.public_key() == &key
        ));
        // The plain key, fetched only for its certificate, does not sign.
        assert!(matches!(
            agent.signer_for(&key.to_bytes().unwrap()),
            Err(ssh_agent_kit::AgentError::UnknownKey)
        ));
        // Only certificates for another key: nothing to serve.
        assert_eq!(
            agent.handle(&add_card_with_certs(true, &[&other])),
            wire::failure()
        );

        // Without `-C` the key is served too.
        assert_eq!(
            agent.handle(&add_card_with_certs(false, &[&cert])),
            wire::success()
        );
        assert_eq!(listing(&agent).len(), 2);

        // `ssh-add -e` takes the key and its certificate away.
        let mut remove = vec![wire::SSH_AGENTC_REMOVE_SMARTCARD_KEY];
        b"ferris@example.com"
            .as_slice()
            .encode(&mut remove)
            .unwrap();
        assert_eq!(agent.handle(&remove), wire::success());
        assert!(listing(&agent).is_empty());
    }

    #[test]
    fn certificate_files_match_served_keys() {
        use ssh_agent_kit::testing::{certify, certify_until};
        let (agent, key) = preloaded_agent(vec![entry()]);
        let cert = certify(key.key_data());
        let line = cert.to_openssh("ferris-cert");
        let from_file = CertKey::from_openssh_line(&line).unwrap();
        let expired = certify_until(key.key_data(), 1);
        let unserved = certify(&ssh_key::public::KeyData::Ed25519(
            ssh_key::public::Ed25519PublicKey([0x99; 32]),
        ));
        let agent = agent.with_certificates([from_file, expired.clone(), unserved.clone()]);
        assert_eq!(agent.preload([key.clone()]), 1);
        assert_eq!(
            listing(&agent),
            vec![
                wire::listed(&key),
                (cert.blob().to_vec(), "ferris-cert".to_owned())
            ]
        );
        assert!(matches!(
            agent.signer_for(cert.blob()),
            Ok(signer) if signer.public_key() == &key
        ));
        assert!(agent.signer_for(expired.blob()).is_err());
        assert!(agent.signer_for(unserved.blob()).is_err());
        assert_eq!(agent.certificates_for(&key).len(), 1);

        // Once the key is no longer served, neither is its certificate.
        assert!(agent.remove(&entry()));
        assert!(listing(&agent).is_empty());
        assert!(agent.signer_for(cert.blob()).is_err());
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

    /// An agent serving one `sk-ssh-ed25519` key enrolled with user
    /// verification required, backed by `device`, plus a sign request for
    /// it and a count of device openings.
    struct UvSetup {
        agent: Agent,
        key_blob: Vec<u8>,
        device: Arc<Mutex<crate::fido::fake::FakeFido>>,
        opens: Arc<std::sync::atomic::AtomicUsize>,
        sink: Arc<RecordingSink>,
    }

    impl UvSetup {
        fn new(prompt: Option<Arc<crate::challenge::RecordingPin>>, cache: Duration) -> Self {
            use crate::agent::sk::SK_SSH_ED25519;
            use crate::fido::fake::FakeFido;
            use ssh_key::private::SkEd25519;
            use ssh_key::public::{Ed25519PublicKey, KeyData, SkEd25519 as SkEd25519Public};

            let device = FakeFido::new(&[0x42; 32], "ssh:", &[9, 8, 7], 0x01)
                .with_pin("1234", 8, &[1, 2])
                .with_id("/dev/hidraw9")
                .with_touch();
            let public = SkEd25519Public::new(Ed25519PublicKey(device.public()), "ssh:");
            let key_blob = PublicKey::new(KeyData::SkEd25519(public.clone()), "uv@example.com")
                .to_bytes()
                .unwrap();
            // User presence and user verification required.
            let pair = SkEd25519::new(public, 0x05, [9u8, 8, 7]).unwrap();
            let mut add = vec![wire::SSH2_AGENTC_ADD_IDENTITY];
            SK_SSH_ED25519.encode(&mut add).unwrap();
            pair.encode(&mut add).unwrap();
            "uv@example.com".encode(&mut add).unwrap();

            let device = Arc::new(Mutex::new(device));
            let opens = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let sk_opener: SkOpener = {
                let device = Arc::clone(&device);
                let opens = Arc::clone(&opens);
                Arc::new(move || {
                    opens.fetch_add(1, Ordering::SeqCst);
                    Ok(vec![Box::new(Arc::clone(&device)) as Box<dyn HidTransport>])
                })
            };
            let opener: Opener = Arc::new(|| panic!("OnlyKey must not be opened"));
            let sink = Arc::new(RecordingSink::default());
            let mut agent = Agent::new(
                Vec::new(),
                opener,
                Arc::clone(&sink) as Arc<dyn ChallengeSink>,
            )
            .with_sk_opener(sk_opener)
            .with_pin_cache(cache);
            if let Some(prompt) = prompt {
                agent = agent.with_pin_prompt(prompt);
            }
            assert_eq!(agent.handle(&add), wire::success());
            UvSetup {
                agent,
                key_blob,
                device,
                opens,
                sink,
            }
        }

        fn sign(&self) -> Result<ssh_key::Signature, AgentError> {
            let reply = self
                .agent
                .sign(&self.key_blob, b"data", 0, &Connection::default())
                .map_err(backend_error)?;
            let mut r = &reply[1..];
            let blob = Vec::<u8>::decode(&mut r).unwrap();
            Ok(ssh_key::Signature::try_from(blob.as_slice()).unwrap())
        }
    }

    /// The OnlyKey or security-key error inside the kit's.
    fn backend_error(e: ssh_agent_kit::AgentError) -> AgentError {
        match e {
            ssh_agent_kit::AgentError::Backend(e) => *e.downcast::<AgentError>().unwrap(),
            other => panic!("not a backend error: {other}"),
        }
    }

    fn pins(pins: &[&str]) -> Arc<crate::challenge::RecordingPin> {
        Arc::new(crate::challenge::RecordingPin::new(pins))
    }

    /// The PIN is asked for, naming the key and the tries left, and the
    /// signature reports the user verified.
    #[test]
    fn verification_required_key_signs_after_the_pin() {
        let prompt = pins(&["1234"]);
        let setup = UvSetup::new(Some(Arc::clone(&prompt)), Duration::ZERO);
        let sig = setup.sign().unwrap();
        let public = PublicKey::from_bytes(&setup.key_blob).unwrap();
        keys::verify(&public, b"data", &sig).unwrap();
        assert_eq!(
            sig.as_bytes()[64],
            0x01 | 0x04,
            "flags: presence and verification"
        );
        let requests = prompt.requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(
            requests[0].action,
            "sign as uv@example.com with /dev/hidraw9"
        );
        assert_eq!(requests[0].retries, Some(8));
        assert_eq!(requests[0].problem, None);
        assert_eq!(setup.sink.1.lock().unwrap().len(), 1);
    }

    /// A wrong PIN is asked for again with one try fewer.
    #[test]
    fn a_wrong_pin_is_asked_again() {
        let prompt = pins(&["0000", "1234"]);
        let setup = UvSetup::new(Some(Arc::clone(&prompt)), Duration::ZERO);
        setup.sign().unwrap();
        let requests = prompt.requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[1].problem.as_deref(), Some("Wrong PIN"));
        assert_eq!(requests[1].retries, Some(7));
        assert_eq!(setup.device.lock().unwrap().pin_retries(), Some(8));
    }

    /// Three wrong PINs stop at the device's own lockout, with no touch asked.
    #[test]
    fn three_wrong_pins_end_in_the_replug_lockout() {
        let prompt = pins(&["0000", "1111", "2222", "1234"]);
        let setup = UvSetup::new(Some(Arc::clone(&prompt)), Duration::ZERO);
        let result = setup.sign();
        assert!(
            matches!(result, Err(AgentError::Fido(FidoError::PinAuthBlocked))),
            "{result:?}"
        );
        assert_eq!(prompt.requests.lock().unwrap().len(), 3);
        assert!(setup.sink.1.lock().unwrap().is_empty());
    }

    #[test]
    fn a_cancelled_pin_fails_without_a_touch() {
        let prompt = Arc::new(crate::challenge::RecordingPin::answering(vec![
            crate::challenge::PinAnswer::Cancelled,
        ]));
        let setup = UvSetup::new(Some(prompt), Duration::ZERO);
        let result = setup.sign();
        assert!(
            matches!(result, Err(AgentError::Fido(FidoError::PinCancelled))),
            "{result:?}"
        );
        assert!(setup.sink.1.lock().unwrap().is_empty());
        assert_eq!(setup.device.lock().unwrap().pin_token_requests(), 0);
    }

    /// With no way to ask for a PIN, the key is refused before any device
    /// is opened.
    #[test]
    fn without_a_pin_prompt_the_device_is_not_opened() {
        let setup = UvSetup::new(None, Duration::ZERO);
        let result = setup.sign();
        assert!(
            matches!(result, Err(AgentError::Fido(FidoError::UvRequired))),
            "{result:?}"
        );
        assert_eq!(setup.opens.load(Ordering::SeqCst), 0);
    }

    /// A prompt that exists but cannot be shown (no askpass, no terminal)
    /// is refused before any device is opened, too.
    #[test]
    fn an_unavailable_pin_prompt_does_not_open_the_device() {
        let setup = UvSetup::new(None, Duration::ZERO);
        let agent = setup
            .agent
            .with_pin_prompt(Arc::new(crate::challenge::ChainPin::default()));
        let result = agent
            .sign(&setup.key_blob, b"data", 0, &Connection::default())
            .map_err(backend_error);
        assert!(
            matches!(result, Err(AgentError::Fido(FidoError::UvRequired))),
            "{result:?}"
        );
        assert_eq!(setup.opens.load(Ordering::SeqCst), 0);
    }

    /// A verify-required resident key, added as `okagent load-resident`
    /// adds it, signs after the PIN. Added without the flag, as `ssh-add -K`
    /// adds it, the device hides it and signing fails.
    #[test]
    fn a_resident_key_signs_only_with_its_verify_flag() {
        use crate::fido::credman::{CRED_PROTECT_UV_REQUIRED, ResidentCredential};
        use crate::fido::fake::FakeFido;
        use crate::fido::pin::CosePublicKey;

        for verify in [true, false] {
            let device = FakeFido::new(&[0x42; 32], "ssh:okagent-test-uv", &[9, 8, 7], 0x01)
                .with_pin("1234", 8, &[1])
                .resident("openssh", CRED_PROTECT_UV_REQUIRED);
            let credential = ResidentCredential {
                rp_id: "ssh:okagent-test-uv".into(),
                user_name: Some("openssh".into()),
                credential_id: vec![9, 8, 7],
                public_key: CosePublicKey::Ed25519(device.public()),
                cred_protect: Some(CRED_PROTECT_UV_REQUIRED),
            };
            let (public, body) = crate::agent::sk::resident_key(&credential, verify).unwrap();
            let device = Arc::new(Mutex::new(device));
            let sk_opener: SkOpener = {
                let device = Arc::clone(&device);
                Arc::new(move || Ok(vec![Box::new(Arc::clone(&device)) as Box<dyn HidTransport>]))
            };
            let opener: Opener = Arc::new(|| panic!("OnlyKey must not be opened"));
            let prompt = pins(&["1234"]);
            let agent = Agent::new(Vec::new(), opener, Arc::new(RecordingSink::default()))
                .with_sk_opener(sk_opener)
                .with_pin_prompt(Arc::clone(&prompt) as Arc<dyn PinPrompt>);
            let mut add = vec![wire::SSH2_AGENTC_ADD_IDENTITY];
            add.extend_from_slice(&body);
            assert_eq!(agent.handle(&add), wire::success());

            let result = agent
                .sign(
                    &public.to_bytes().unwrap(),
                    b"data",
                    0,
                    &Connection::default(),
                )
                .map_err(backend_error);
            if verify {
                let reply = result.unwrap();
                let mut r = &reply[1..];
                let blob = Vec::<u8>::decode(&mut r).unwrap();
                let sig = ssh_key::Signature::try_from(blob.as_slice()).unwrap();
                keys::verify(&public, b"data", &sig).unwrap();
                assert_eq!(sig.as_bytes()[64], 0x05);
                assert_eq!(prompt.requests.lock().unwrap().len(), 1);
            } else {
                assert!(
                    matches!(result, Err(AgentError::Fido(FidoError::NoCredential))),
                    "{result:?}"
                );
                assert!(prompt.requests.lock().unwrap().is_empty());
            }
        }
    }

    #[test]
    fn without_the_cache_every_signature_asks() {
        let prompt = pins(&["1234", "1234"]);
        let setup = UvSetup::new(Some(Arc::clone(&prompt)), Duration::ZERO);
        setup.sign().unwrap();
        setup.sign().unwrap();
        assert_eq!(prompt.requests.lock().unwrap().len(), 2);
        assert_eq!(setup.device.lock().unwrap().pin_token_requests(), 2);
    }

    /// With the cache on, the second signature reuses the token; locking
    /// the agent drops it.
    #[test]
    fn the_cache_reuses_the_token_until_the_agent_is_locked() {
        let prompt = pins(&["1234", "1234"]);
        let setup = UvSetup::new(Some(Arc::clone(&prompt)), Duration::from_secs(60));
        setup.sign().unwrap();
        let sig = setup.sign().unwrap();
        assert_eq!(sig.as_bytes()[64] & 0x04, 0x04);
        assert_eq!(prompt.requests.lock().unwrap().len(), 1);
        assert_eq!(setup.device.lock().unwrap().pin_token_requests(), 1);
        // Each signature still asks for a touch.
        assert_eq!(setup.sink.1.lock().unwrap().len(), 2);

        assert!(setup.agent.lock(b"pass"));
        assert!(setup.agent.unlock(b"pass"));
        setup.sign().unwrap();
        assert_eq!(prompt.requests.lock().unwrap().len(), 2);
    }

    /// A cached token the device no longer honours (it was replugged) is
    /// replaced by asking for the PIN once more.
    #[test]
    fn a_stale_cached_token_is_replaced() {
        let prompt = pins(&["1234", "1234"]);
        let setup = UvSetup::new(Some(Arc::clone(&prompt)), Duration::from_secs(60));
        setup.sign().unwrap();
        setup.device.lock().unwrap().power_cycle();
        setup.sign().unwrap();
        assert_eq!(prompt.requests.lock().unwrap().len(), 2);
        assert_eq!(setup.device.lock().unwrap().pin_token_requests(), 2);
    }

    use ssh_encoding::Encode;
}
