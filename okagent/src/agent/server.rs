//! okagent's agent: an [`ssh_agent_kit::Agent`] serving the OnlyKey's keys
//! and FIDO security keys, with the token's challenge as the prompt.

use super::onlykey::{OnlyKeyBackend, Opener};
use super::sk::{SkBackend, SkDecoder, SkOpener};
use onlykey_agent::challenge::{ChallengeSink, ConfirmRequest, PinPrompt};
use onlykey_agent::device::DeviceError;
use onlykey_agent::fido::FidoError;
use onlykey_agent::identity::KeySpec;
use onlykey_agent::keys;
use ssh_agent_kit::destination::Connection;
use ssh_agent_kit::policy::Confirm;
use ssh_agent_kit::server::Handler;
use ssh_agent_kit::{Extension, KeyDecoder};
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
    Identity(#[from] onlykey_agent::identity::IdentityError),
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
    #[cfg(test)]
    pub(crate) fn onlykey(&self) -> &OnlyKeyBackend {
        &self.onlykey
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

    /// Register a protocol extension handler. A later registration under the
    /// same name wins.
    pub fn with_extension(mut self, extension: impl Extension + 'static) -> Self {
        self.kit = self.kit.with_extension(extension);
        self
    }

    /// Register a key-type decoder for `ssh-add FILE`. A later registration
    /// under a name wins.
    pub fn with_key_type(mut self, decoder: impl KeyDecoder + 'static) -> Self {
        self.kit = self.kit.with_key_type(decoder);
        self
    }

    /// The token identities currently served, in order.
    pub fn entries(&self) -> Vec<KeySpec> {
        self.onlykey.entries()
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
    use crate::agent::CertKey;
    use onlykey_agent::challenge::RecordingSink;
    use onlykey_agent::device::OnlyKey;
    use onlykey_agent::device::Timeouts;
    use onlykey_agent::identity::{Curve, EccSlot};
    use onlykey_agent::protocol::{self, Report};
    use onlykey_agent::transport::HidTransport;
    use onlykey_agent::transport::fake::{ScriptedTransport, Step};
    use ssh_agent_kit::wire;
    use ssh_encoding::Decode;
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
        // Unlocked, the same removal goes through.
        assert_eq!(
            agent.handle(&provider(wire::SSH_AGENTC_REMOVE_SMARTCARD_KEY)),
            wire::success()
        );
        assert!(agent.entries().is_empty());
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

    /// A security key enrolled for a website, not `ssh:`, signs SSH data only:
    /// arbitrary data is refused before the authenticator is even opened.
    #[test]
    fn a_non_ssh_security_key_signs_only_ssh_data() {
        use crate::agent::sk::SK_SSH_ED25519;
        use onlykey_agent::fido::fake::FakeFido;
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
        use onlykey_agent::fido::fake::FakeFido;
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
        use onlykey_agent::fido::fake::FakeFido;
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
        device: Arc<Mutex<onlykey_agent::fido::fake::FakeFido>>,
        opens: Arc<std::sync::atomic::AtomicUsize>,
        sink: Arc<RecordingSink>,
    }

    impl UvSetup {
        fn new(
            prompt: Option<Arc<onlykey_agent::challenge::RecordingPin>>,
            cache: Duration,
        ) -> Self {
            use crate::agent::sk::SK_SSH_ED25519;
            use onlykey_agent::fido::fake::FakeFido;
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

    fn pins(pins: &[&str]) -> Arc<onlykey_agent::challenge::RecordingPin> {
        Arc::new(onlykey_agent::challenge::RecordingPin::new(pins))
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
        let prompt = Arc::new(onlykey_agent::challenge::RecordingPin::answering(vec![
            onlykey_agent::challenge::PinAnswer::Cancelled,
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
            .with_pin_prompt(Arc::new(onlykey_agent::challenge::ChainPin::default()));
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
        use onlykey_agent::fido::credman::{CRED_PROTECT_UV_REQUIRED, ResidentCredential};
        use onlykey_agent::fido::fake::FakeFido;
        use onlykey_agent::fido::pin::CosePublicKey;

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
