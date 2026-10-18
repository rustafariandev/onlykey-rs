//! FIDO security keys the agent serves by driving the authenticator.
//!
//! An `sk-` private key holds no secret: it carries the credential's public
//! key, application and key handle, and every signature is produced by the
//! attached FIDO device. `ssh-add FILE` loads one through
//! `SSH2_AGENTC_ADD_IDENTITY`, decoded here by [`SkDecoder`]; signing goes
//! through [`onlykey_agent::fido`], with the authenticators, PIN prompt and PIN-token
//! cache of an [`SkBackend`].

use super::lock;
use super::server::AgentError;
use onlykey_agent::challenge::{ChallengeSink, PinPrompt, PinRequest, TouchRequest};
use onlykey_agent::fido;
use onlykey_agent::fido::ctaphid::CtapHid;
use onlykey_agent::fido::{FidoError, PinAuth, PinProtocol, pin};
use onlykey_agent::transport::{HidTransport, HidapiTransport};
use sha2::{Digest, Sha256};
use ssh_agent_kit::backend::Lifecycle;
use ssh_agent_kit::keytype::{KeyDecodeError, KeyDecoder};
use ssh_agent_kit::signer::{BoxError, Signer, SignerRef};
use ssh_agent_kit::wire;
use ssh_encoding::{Decode, Encode, Reader};
use ssh_key::HashAlg;
use ssh_key::private::{SkEcdsaSha2NistP256, SkEd25519};
use ssh_key::public::KeyData;
use ssh_key::{Algorithm, Mpint, PublicKey, Signature};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

/// `sk-ssh-ed25519@openssh.com`, from OpenSSH's `PROTOCOL.u2f`.
pub const SK_SSH_ED25519: &str = "sk-ssh-ed25519@openssh.com";
/// `sk-ecdsa-sha2-nistp256@openssh.com`, from OpenSSH's `PROTOCOL.u2f`.
pub const SK_ECDSA_P256: &str = "sk-ecdsa-sha2-nistp256@openssh.com";

/// `SSH_SK_USER_PRESENCE_REQD`: the key must be touched to sign.
const USER_PRESENCE: u8 = 0x01;
/// `SSH_SK_USER_VERIFICATION_REQD`: the key needs a PIN as well. The
/// assertion reports a verified user with the same bit of its flags.
const USER_VERIFICATION: u8 = 0x04;
/// `SSH_SK_RESIDENT_KEY`: the credential is stored on the authenticator.
const RESIDENT: u8 = 0x20;

/// A FIDO security key credential held by the agent.
///
/// All fields are public data; signing needs the physical authenticator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkKey {
    algorithm: Algorithm,
    application: String,
    key_handle: Vec<u8>,
    flags: u8,
    public: PublicKey,
}

/// A resident credential as an SSH key: its public key, commented with its
/// application, and the `SSH2_AGENTC_ADD_IDENTITY` body (key type, key,
/// comment) that adds it to an agent.
///
/// The flags are user presence and resident, as `ssh-add -K` gives them,
/// plus user verification when `verify` says the credential needs it.
pub fn resident_key(
    credential: &fido::credman::ResidentCredential,
    verify: bool,
) -> Result<(PublicKey, Vec<u8>), fido::FidoError> {
    use fido::pin::CosePublicKey;
    use ssh_key::public::{EcdsaPublicKey, Ed25519PublicKey};

    let flags = USER_PRESENCE | RESIDENT | if verify { USER_VERIFICATION } else { 0 };
    let application = credential.rp_id.as_str();
    let handle = credential.credential_id.as_slice();
    let comment = application;
    let bad_key = |_| fido::FidoError::Protocol("cannot encode the resident key");
    let mut body = Vec::new();
    let public = match &credential.public_key {
        CosePublicKey::Ed25519(x) => {
            let public = ssh_key::public::SkEd25519::new(Ed25519PublicKey(*x), application);
            let key = SkEd25519::new(public.clone(), flags, handle).map_err(bad_key)?;
            SK_SSH_ED25519
                .encode(&mut body)
                .map_err(|_| fido::FidoError::Signature)?;
            key.encode(&mut body)
                .map_err(|_| fido::FidoError::Signature)?;
            KeyData::SkEd25519(public)
        }
        CosePublicKey::P256(point) => {
            use p256::elliptic_curve::sec1::ToEncodedPoint;
            let sec1 = point.to_encoded_point(false);
            let EcdsaPublicKey::NistP256(point) =
                EcdsaPublicKey::from_sec1_bytes(sec1.as_bytes()).map_err(bad_key)?
            else {
                return Err(fido::FidoError::Protocol("P-256 key of the wrong size"));
            };
            let public = ssh_key::public::SkEcdsaSha2NistP256::new(point, application);
            let key = SkEcdsaSha2NistP256::new(public.clone(), flags, handle).map_err(bad_key)?;
            SK_ECDSA_P256
                .encode(&mut body)
                .map_err(|_| fido::FidoError::Signature)?;
            key.encode(&mut body)
                .map_err(|_| fido::FidoError::Signature)?;
            KeyData::SkEcdsaSha2NistP256(public)
        }
    };
    comment
        .encode(&mut body)
        .map_err(|_| fido::FidoError::Signature)?;
    Ok((PublicKey::new(public, comment), body))
}

/// Decode the type-specific fields of an `ADD_IDENTITY` request body for a
/// security key, plus the trailing comment.
pub fn decode(key_type: &str, reader: &mut impl Reader) -> Result<SkKey, KeyDecodeError> {
    match key_type {
        SK_SSH_ED25519 => {
            let key = SkEd25519::decode(reader).map_err(|_| malformed(SK_SSH_ED25519))?;
            let comment = String::decode(reader).map_err(|_| malformed(SK_SSH_ED25519))?;
            let public = PublicKey::new(KeyData::SkEd25519(key.public().clone()), comment);
            Ok(SkKey {
                algorithm: Algorithm::SkEd25519,
                application: key.public().application().to_owned(),
                key_handle: key.key_handle().to_vec(),
                flags: key.flags(),
                public,
            })
        }
        SK_ECDSA_P256 => {
            let key = SkEcdsaSha2NistP256::decode(reader).map_err(|_| malformed(SK_ECDSA_P256))?;
            let comment = String::decode(reader).map_err(|_| malformed(SK_ECDSA_P256))?;
            let public =
                PublicKey::new(KeyData::SkEcdsaSha2NistP256(key.public().clone()), comment);
            Ok(SkKey {
                algorithm: Algorithm::SkEcdsaSha2NistP256,
                application: key.public().application().to_owned(),
                key_handle: key.key_handle().to_vec(),
                flags: key.flags(),
                public,
            })
        }
        other => Err(KeyDecodeError::UnsupportedType(other.to_owned())),
    }
}

fn malformed(key_type: &'static str) -> KeyDecodeError {
    KeyDecodeError::Malformed(key_type)
}

impl SkKey {
    /// The matching public key, whose comment is the identity it is listed as.
    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }

    /// The FIDO relying party the credential was enrolled for; `ssh:` and
    /// `ssh:<suffix>` for keys made by `ssh-keygen`.
    pub fn application(&self) -> &str {
        &self.application
    }

    /// How prompts name the key: its comment, or, for a key loaded with
    /// `ssh-add -K` (which sends none), its application and fingerprint.
    pub fn display_name(&self) -> String {
        match self.public.comment() {
            "" => format!(
                "{} {}",
                self.application,
                self.public.fingerprint(ssh_key::HashAlg::Sha256)
            ),
            comment => comment.to_owned(),
        }
    }

    /// Whether the credential belongs to SSH. Any other application may be a
    /// web credential, so the agent only signs SSH data with it.
    pub fn is_ssh_application(&self) -> bool {
        self.application.starts_with("ssh:")
    }

    /// Whether the credential was enrolled with user verification required.
    pub fn needs_verification(&self) -> bool {
        self.flags & USER_VERIFICATION != 0
    }

    /// Whether the authenticator behind `hid` holds this credential, asked
    /// with a silent (`up: false`) assertion that needs no touch. Used to pick
    /// the right device when several are attached, as OpenSSH does.
    pub fn is_held_by<T: HidTransport>(
        &self,
        hid: &mut CtapHid<T>,
    ) -> Result<bool, fido::FidoError> {
        match fido::get_assertion(
            hid,
            &self.application,
            &[0; 32],
            &self.key_handle,
            false,
            &|| {},
        ) {
            Ok(_) => Ok(true),
            Err(fido::FidoError::NoCredential) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Sign `data` with the authenticator behind `transport`.
    ///
    /// The FIDO assertion signs `SHA256(application) || flags || counter ||
    /// SHA256(data)`, which is the SSH `sk-` signature. `on_presence` is
    /// called once if the device waits for a touch.
    pub fn sign<T: HidTransport>(
        &self,
        transport: T,
        data: &[u8],
        on_presence: &dyn Fn(),
    ) -> Result<Signature, fido::FidoError> {
        self.sign_with(&mut CtapHid::new(transport), data, None, on_presence)
    }

    /// [`Self::sign`] over a CTAPHID channel already in use, such as one
    /// [`Self::is_held_by`] just probed.
    ///
    /// A key that [needs verification](Self::needs_verification) signs only
    /// with a PIN token in `pin`, and only if the authenticator reports the
    /// user verified; without one it fails with
    /// [`FidoError::UvRequired`](fido::FidoError::UvRequired) before the
    /// device is asked.
    pub fn sign_with<T: HidTransport>(
        &self,
        hid: &mut CtapHid<T>,
        data: &[u8],
        pin: Option<fido::PinAuth>,
        on_presence: &dyn Fn(),
    ) -> Result<Signature, fido::FidoError> {
        if self.needs_verification() && pin.is_none() {
            return Err(fido::FidoError::UvRequired);
        }
        let client_data_hash: [u8; 32] = Sha256::digest(data).into();
        let up = self.flags & USER_PRESENCE != 0;
        let assertion = fido::get_assertion_with_pin(
            hid,
            &self.application,
            &client_data_hash,
            &self.key_handle,
            up,
            pin,
            on_presence,
        )?;
        // The authenticator data's presence bit is the same bit as the
        // key's. sshd checks it too; this catches a device that skipped the
        // touch before its signature goes anywhere.
        if up && assertion.flags & USER_PRESENCE == 0 {
            return Err(fido::FidoError::Protocol(
                "the security key signed without the user's touch",
            ));
        }
        if self.needs_verification() && assertion.flags & USER_VERIFICATION == 0 {
            return Err(fido::FidoError::Protocol(
                "the security key signed without verifying the user",
            ));
        }

        let mut payload = match self.algorithm {
            Algorithm::SkEd25519 => {
                if assertion.signature.len() != 64 {
                    return Err(fido::FidoError::Protocol("bad Ed25519 assertion length"));
                }
                assertion.signature.clone()
            }
            Algorithm::SkEcdsaSha2NistP256 => {
                let (r, s) = fido::der::parse_ecdsa(&assertion.signature)?;
                let mut encoded = Vec::with_capacity(2 + 33 + 33);
                for scalar in [&r, &s] {
                    Mpint::from_positive_bytes(scalar)
                        .map_err(|_| fido::FidoError::Signature)?
                        .encode(&mut encoded)
                        .map_err(|_| fido::FidoError::Signature)?;
                }
                encoded
            }
            _ => return Err(fido::FidoError::Unsupported),
        };
        payload.push(assertion.flags);
        payload.extend_from_slice(&assertion.counter.to_be_bytes());
        Signature::new(self.algorithm.clone(), payload)
            .map_err(|_| fido::FidoError::Protocol("cannot encode signature"))
    }
}

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

/// What signing with security keys needs: the authenticators, a way to ask
/// for the PIN, and the PIN tokens kept for reuse. Shared by every
/// [`SkKey`] the agent serves; its settings can change while it serves.
pub struct SkBackend {
    settings: RwLock<SkSettings>,
    sink: Arc<dyn ChallengeSink>,
    /// Serialises FIDO operations, which also wait for a touch.
    sk_lock: Mutex<()>,
    /// PIN tokens kept by device id while `pin_cache` allows.
    pin_tokens: Mutex<HashMap<String, CachedPin>>,
}

#[derive(Clone)]
struct SkSettings {
    opener: SkOpener,
    /// Asks for a security key's PIN; without one, keys enrolled with user
    /// verification required cannot sign.
    pin_prompt: Option<Arc<dyn PinPrompt>>,
    /// How long a PIN token is kept for reuse; `None` asks every time.
    pin_cache: Option<Duration>,
}

/// A PIN token kept for reuse on one device.
struct CachedPin {
    protocol: PinProtocol,
    token: Zeroizing<Vec<u8>>,
    expires: Instant,
}

impl SkBackend {
    /// Sign with every attached security key, telling the user to touch it
    /// through `sink`. No PIN prompt and no PIN cache until set.
    pub fn new(sink: Arc<dyn ChallengeSink>) -> Self {
        SkBackend {
            settings: RwLock::new(SkSettings {
                opener: default_sk_opener(),
                pin_prompt: None,
                pin_cache: None,
            }),
            sink,
            sk_lock: Mutex::new(()),
            pin_tokens: Mutex::new(HashMap::new()),
        }
    }

    fn settings(&self) -> SkSettings {
        self.settings
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    fn update(&self, change: impl FnOnce(&mut SkSettings)) {
        change(&mut self.settings.write().unwrap_or_else(|p| p.into_inner()));
    }

    /// Replace how FIDO authenticators are opened (for tests and for a fixed
    /// `--fido-device` path).
    pub fn set_opener(&self, opener: SkOpener) {
        self.update(|s| s.opener = opener);
    }

    /// Ask for security key PINs with `prompt`, so keys enrolled with user
    /// verification required (`ssh-keygen -O verify-required`) can sign.
    pub fn set_pin_prompt(&self, prompt: Arc<dyn PinPrompt>) {
        self.update(|s| s.pin_prompt = Some(prompt));
    }

    /// Keep a security key's PIN token for `duration` after the PIN is
    /// entered, so signatures within that time ask only for a touch. Zero
    /// keeps nothing, which is the default. The tokens are dropped when the
    /// agent is locked or every identity is removed.
    pub fn set_pin_cache(&self, duration: Duration) {
        self.update(|s| s.pin_cache = (!duration.is_zero()).then_some(duration));
    }

    /// Drop every kept PIN token.
    fn forget_pins(&self) {
        lock(&self.pin_tokens).clear();
    }

    /// Sign with a FIDO credential, waiting for the authenticator's touch.
    ///
    /// As in OpenSSH, a credential whose application is not `ssh:` signs only
    /// SSH userauth requests and SSHSIG blobs, so the agent cannot be used to
    /// mint assertions for the website such a credential may belong to.
    pub fn sign(&self, key: &SkKey, data: &[u8]) -> Result<Signature, AgentError> {
        if !key.is_ssh_application() && wire::classify_data(data) == wire::SignedData::Other {
            return Err(AgentError::NotWebSafe(key.application().to_owned()));
        }
        let settings = self.settings();
        let _guard = lock(&self.sk_lock);
        // Refuse before opening the device when no prompt can ask for the PIN.
        if key.needs_verification() && !settings.pin_prompt.as_ref().is_some_and(|p| p.available())
        {
            return Err(FidoError::UvRequired.into());
        }
        let mut hid = self.authenticator_for(&settings, key)?;
        let request = TouchRequest {
            identity: key.display_name(),
            subject: wire::describe_data(data),
        };
        let on_presence = || {
            tracing::info!("security key is waiting for a touch");
            self.sink.present_touch(&request);
        };
        let sig = if key.needs_verification() {
            self.sign_verified(&settings, key, &mut hid, data, &request, &on_presence)?
        } else {
            key.sign_with(&mut hid, data, None, &on_presence)?
        };
        tracing::info!(
            comment = key.public_key().comment(),
            algorithm = %sig.algorithm(),
            "signed with security key"
        );
        Ok(sig)
    }

    /// Sign with a key that needs the user verified: with a cached PIN token
    /// if one is kept for the device, else with one from the user's PIN. A
    /// cached token the device refuses (it was replugged) is dropped and the
    /// PIN asked for instead.
    fn sign_verified(
        &self,
        settings: &SkSettings,
        key: &SkKey,
        hid: &mut CtapHid<Box<dyn HidTransport>>,
        data: &[u8],
        touch: &TouchRequest,
        on_presence: &dyn Fn(),
    ) -> Result<Signature, AgentError> {
        let device = hid.transport().id();
        if let Some((protocol, token)) = self.cached_pin(settings, device.as_deref()) {
            let auth = PinAuth {
                protocol,
                token: &token,
            };
            match key.sign_with(hid, data, Some(auth), on_presence) {
                Err(FidoError::PinAuthInvalid) => {
                    tracing::info!("cached PIN token was refused; asking for the PIN");
                    self.forget_pin(device.as_deref());
                }
                result => return Ok(result?),
            }
        }
        let (protocol, token) = self.pin_token(settings, hid, key, touch)?;
        let auth = PinAuth {
            protocol,
            token: &token,
        };
        let sig = key.sign_with(hid, data, Some(auth), on_presence)?;
        self.keep_pin(settings, device, protocol, token);
        Ok(sig)
    }

    /// Ask the user for the PIN and exchange it for a PIN token allowed to
    /// sign for `key`'s application.
    fn pin_token(
        &self,
        settings: &SkSettings,
        hid: &mut CtapHid<Box<dyn HidTransport>>,
        key: &SkKey,
        touch: &TouchRequest,
    ) -> Result<(PinProtocol, Zeroizing<Vec<u8>>), AgentError> {
        let prompt = settings.pin_prompt.as_ref().ok_or(FidoError::UvRequired)?;
        // Name the device: with several attached, the one that answered the
        // probe gets the PIN, and only the user can tell if it is theirs.
        let action = match hid.transport().id() {
            Some(device) => format!("sign as {} with {device}", touch.identity),
            None => format!("sign as {}", touch.identity),
        };
        let request = PinRequest {
            action,
            subject: touch.subject.clone(),
            retries: None,
            problem: None,
        };
        let permissions = pin::Permissions {
            bits: pin::PERMISSION_GET_ASSERTION,
            rp_id: Some(key.application()),
        };
        Ok(pin::pin_token_interactive(
            hid,
            prompt.as_ref(),
            &request,
            permissions,
        )?)
    }

    /// The PIN token kept for `device`, if the cache is on and it is fresh.
    fn cached_pin(
        &self,
        settings: &SkSettings,
        device: Option<&str>,
    ) -> Option<(PinProtocol, Zeroizing<Vec<u8>>)> {
        settings.pin_cache?;
        let mut tokens = lock(&self.pin_tokens);
        let now = Instant::now();
        tokens.retain(|_, cached| cached.expires > now);
        tokens
            .get(device?)
            .map(|cached| (cached.protocol, cached.token.clone()))
    }

    fn keep_pin(
        &self,
        settings: &SkSettings,
        device: Option<String>,
        protocol: PinProtocol,
        token: Zeroizing<Vec<u8>>,
    ) {
        let (Some(ttl), Some(device)) = (settings.pin_cache, device) else {
            return;
        };
        let cached = CachedPin {
            protocol,
            token,
            expires: Instant::now() + ttl,
        };
        lock(&self.pin_tokens).insert(device, cached);
    }

    fn forget_pin(&self, device: Option<&str>) {
        if let Some(device) = device {
            lock(&self.pin_tokens).remove(device);
        }
    }

    /// The attached authenticator to sign with `key`. A lone device is used
    /// as is; among several, the first that answers a silent probe for the
    /// credential is chosen, so no touch is asked of the others.
    fn authenticator_for(
        &self,
        settings: &SkSettings,
        key: &SkKey,
    ) -> Result<CtapHid<Box<dyn HidTransport>>, AgentError> {
        let mut devices: Vec<_> = (settings.opener)()?.into_iter().map(CtapHid::new).collect();
        if devices.len() <= 1 {
            return devices.pop().ok_or(AgentError::Fido(FidoError::NoDevice));
        }
        for (index, mut hid) in devices.into_iter().enumerate() {
            match key.is_held_by(&mut hid) {
                Ok(true) => {
                    tracing::info!(device = hid.transport().id(), "security key chosen");
                    return Ok(hid);
                }
                Ok(false) => tracing::debug!(index, "security key does not hold the credential"),
                Err(e) => tracing::warn!(index, error = %e, "cannot probe security key"),
            }
        }
        Err(FidoError::NoCredential.into())
    }
}

/// PIN tokens do not outlive a lock or an `ssh-add -D`.
impl Lifecycle for SkBackend {
    fn locked(&self) {
        self.forget_pins();
    }

    fn cleared(&self) {
        self.forget_pins();
    }
}

/// Decodes the FIDO `sk-` key types of `ssh-add FILE` into keys that sign
/// through an [`SkBackend`].
pub struct SkDecoder(pub Arc<SkBackend>);

impl KeyDecoder for SkDecoder {
    fn key_types(&self) -> &[&str] {
        &[SK_SSH_ED25519, SK_ECDSA_P256]
    }

    fn decode(&self, key_type: &str, reader: &mut &[u8]) -> Result<SignerRef, KeyDecodeError> {
        let key = decode(key_type, reader)?;
        Ok(SignerRef::new(SkSigner {
            key,
            backend: Arc::clone(&self.0),
        }))
    }
}

/// A security key the agent serves, signed through its backend.
struct SkSigner {
    key: SkKey,
    backend: Arc<SkBackend>,
}

impl Signer for SkSigner {
    fn public_key(&self) -> &PublicKey {
        self.key.public_key()
    }

    fn sign(&self, data: &[u8], _hash: HashAlg) -> Result<Signature, BoxError> {
        Ok(self.backend.sign(&self.key, data)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use onlykey_agent::fido::fake::FakeFido;
    use onlykey_agent::keys;

    /// Build the `ADD_IDENTITY` body for an Ed25519 security key backed by
    /// `device`, as `ssh-add` would send it.
    fn add_body(device: &FakeFido, comment: &str) -> Vec<u8> {
        let public = ssh_key::public::SkEd25519::new(
            ssh_key::public::Ed25519PublicKey(device.public()),
            device.application(),
        );
        let key = SkEd25519::new(public, 0x01, device.key_handle()).expect("valid key");
        let mut body = Vec::new();
        key.encode(&mut body).unwrap();
        comment.encode(&mut body).unwrap();
        body
    }

    #[test]
    fn decodes_an_sk_ed25519_key_and_signs_with_the_device() {
        let device = FakeFido::new(&[0x42; 32], "ssh:", &[9, 8, 7], 0x01);
        let body = add_body(&device, "ferris@example.com");
        let key = decode(SK_SSH_ED25519, &mut body.as_slice()).unwrap();
        assert_eq!(key.public_key().comment(), "ferris@example.com");
        assert_eq!(key.public_key().algorithm(), Algorithm::SkEd25519);
        assert!(!key.needs_verification());

        let sig = key.sign(device, b"hello", &|| {}).unwrap();
        assert_eq!(sig.algorithm(), Algorithm::SkEd25519);
        keys::verify(key.public_key(), b"hello", &sig).unwrap();
        assert!(keys::verify(key.public_key(), b"other", &sig).is_err());
    }

    /// A key that requires a touch refuses an assertion that reports none.
    #[test]
    fn an_assertion_without_presence_is_refused() {
        let reference = FakeFido::new(&[0x42; 32], "ssh:", &[9, 8, 7], 0x01);
        let body = add_body(&reference, "ferris@example.com");
        let key = decode(SK_SSH_ED25519, &mut body.as_slice()).unwrap();
        let untouched = FakeFido::new(&[0x42; 32], "ssh:", &[9, 8, 7], 0x00);
        assert!(matches!(
            key.sign(untouched, b"hello", &|| {}),
            Err(fido::FidoError::Protocol(_))
        ));
    }

    /// A resident credential becomes an `ADD_IDENTITY` body that decodes to
    /// the same key, with the verify-required flag only when asked for.
    #[test]
    fn resident_credentials_become_keys_with_their_flags() {
        use fido::credman::ResidentCredential;
        use fido::pin::CosePublicKey;

        let device = FakeFido::new(&[0x42; 32], "ssh:okagent-test-uv", &[9, 8, 7], 0x01);
        let credential = ResidentCredential {
            rp_id: "ssh:okagent-test-uv".into(),
            user_name: Some("openssh".into()),
            credential_id: vec![9, 8, 7],
            public_key: CosePublicKey::Ed25519(device.public()),
            cred_protect: Some(3),
        };
        for (verify, flags) in [(true, 0x25), (false, 0x21)] {
            let (public, body) = resident_key(&credential, verify).unwrap();
            assert_eq!(public.comment(), "ssh:okagent-test-uv");
            let mut r = body.as_slice();
            let key_type = String::decode(&mut r).unwrap();
            let key = decode(&key_type, &mut r).unwrap();
            assert_eq!(key.flags, flags);
            assert_eq!(key.needs_verification(), verify);
            assert_eq!(key.application(), "ssh:okagent-test-uv");
            assert_eq!(key.key_handle, [9, 8, 7]);
            assert_eq!(key.public_key().key_data(), public.key_data());
            assert_eq!(key.display_name(), "ssh:okagent-test-uv");
        }

        let point = p256::SecretKey::from_slice(&[0x22; 32])
            .unwrap()
            .public_key();
        let ecdsa = ResidentCredential {
            public_key: CosePublicKey::P256(point),
            ..credential
        };
        let (public, body) = resident_key(&ecdsa, false).unwrap();
        assert_eq!(public.algorithm(), Algorithm::SkEcdsaSha2NistP256);
        let mut r = body.as_slice();
        assert_eq!(String::decode(&mut r).unwrap(), SK_ECDSA_P256);
        assert_eq!(
            decode(SK_ECDSA_P256, &mut r)
                .unwrap()
                .public_key()
                .key_data(),
            public.key_data()
        );
    }

    /// A key loaded with `ssh-add -K` has no comment, so prompts name it by
    /// application and fingerprint instead.
    #[test]
    fn a_key_without_a_comment_is_named_by_application_and_fingerprint() {
        let device = FakeFido::new(&[0x42; 32], "ssh:okagent-test", &[9, 8, 7], 0x01);
        let key = decode(SK_SSH_ED25519, &mut add_body(&device, "").as_slice()).unwrap();
        let fingerprint = key.public_key().fingerprint(ssh_key::HashAlg::Sha256);
        assert_eq!(
            key.display_name(),
            format!("ssh:okagent-test {fingerprint}")
        );
        assert!(key.display_name().contains(" SHA256:"));
        let key = decode(
            SK_SSH_ED25519,
            &mut add_body(&device, "ferris@laptop").as_slice(),
        )
        .unwrap();
        assert_eq!(key.display_name(), "ferris@laptop");
    }

    /// An `sk-ecdsa-sha2-nistp256` key decodes, keeping its application and
    /// handle, and is listed under the right algorithm.
    #[test]
    fn decodes_an_sk_ecdsa_key() {
        use ssh_key::EcdsaCurve;
        use ssh_key::public::{EcdsaPublicKey, SkEcdsaSha2NistP256 as SkEcdsaPublic};

        let pair =
            ssh_key::private::EcdsaKeypair::random(&mut rand_core::OsRng, EcdsaCurve::NistP256)
                .unwrap();
        let point = match EcdsaPublicKey::from(&pair) {
            EcdsaPublicKey::NistP256(point) => point,
            other => panic!("unexpected curve {other:?}"),
        };
        let public = SkEcdsaPublic::new(point, "ssh:");
        let key = SkEcdsaSha2NistP256::new(public, 0x01, [4u8, 5, 6]).unwrap();
        let mut body = Vec::new();
        key.encode(&mut body).unwrap();
        "ecdsa@example.com".encode(&mut body).unwrap();

        let decoded = decode(SK_ECDSA_P256, &mut body.as_slice()).unwrap();
        assert_eq!(decoded.public_key().comment(), "ecdsa@example.com");
        assert_eq!(
            decoded.public_key().algorithm(),
            Algorithm::SkEcdsaSha2NistP256
        );
        assert!(!decoded.needs_verification());
    }

    #[test]
    fn verification_required_keys_need_a_pin_token() {
        let device = FakeFido::new(&[0x43; 32], "ssh:", &[1], 0x05).with_pin("1234", 8, &[2]);
        let public = ssh_key::public::SkEd25519::new(
            ssh_key::public::Ed25519PublicKey(device.public()),
            "ssh:",
        );
        let key = SkEd25519::new(public, 0x05, device.key_handle()).unwrap();
        let mut body = Vec::new();
        key.encode(&mut body).unwrap();
        "ferris@example.com".encode(&mut body).unwrap();
        let key = decode(SK_SSH_ED25519, &mut body.as_slice()).unwrap();
        assert!(key.needs_verification());
        let mut hid = CtapHid::new(device);
        assert!(matches!(
            key.sign_with(&mut hid, b"hello", None, &|| {}),
            Err(fido::FidoError::UvRequired)
        ));
        let protocol = fido::PinProtocol::V2;
        let token = fido::pin::pin_token(&mut hid, protocol, "1234", None).unwrap();
        let auth = fido::PinAuth {
            protocol,
            token: &token,
        };
        let sig = key
            .sign_with(&mut hid, b"hello", Some(auth), &|| {})
            .unwrap();
        keys::verify(key.public_key(), b"hello", &sig).unwrap();
        // The signature carries the UV flag the server checks.
        assert_eq!(sig.as_bytes()[64] & USER_VERIFICATION, USER_VERIFICATION);
    }

    /// A registry with okagent's security-key decoder.
    fn registry() -> ssh_agent_kit::KeyRegistry {
        let sink = Arc::new(onlykey_agent::challenge::RecordingSink::default());
        let mut registry = ssh_agent_kit::KeyRegistry::builtin();
        registry.register(SkDecoder(Arc::new(SkBackend::new(sink))));
        registry
    }

    /// `ssh-add FILE` of a security key decodes through [`SkDecoder`], with
    /// or without the `sk-provider@openssh.com` constraint ssh-add attaches.
    #[test]
    fn security_key_adds_parse_with_the_decoder() {
        use ssh_agent_kit::wire::{self, Request, WireError};
        let device = FakeFido::new(&[0x42; 32], "ssh:", &[1, 2, 3], 0x01);
        let mut add = vec![wire::SSH2_AGENTC_ADD_IDENTITY];
        SK_SSH_ED25519.encode(&mut add).unwrap();
        add.extend(add_body(&device, "ferris@example.com"));
        match wire::parse_request_with(&registry(), &add).unwrap() {
            Request::AddIdentity { key, lifetime, .. } => {
                assert_eq!(key.comment(), "ferris@example.com");
                assert_eq!(key.public_key().algorithm(), Algorithm::SkEd25519);
                assert_eq!(lifetime, None);
            }
            other => panic!("unexpected request {other:?}"),
        }

        let mut constrained = add.clone();
        constrained[0] = wire::SSH2_AGENTC_ADD_ID_CONSTRAINED;
        wire::SSH_AGENT_CONSTRAIN_EXTENSION
            .encode(&mut constrained)
            .unwrap();
        "sk-provider@openssh.com".encode(&mut constrained).unwrap();
        "internal".encode(&mut constrained).unwrap();
        assert!(matches!(
            wire::parse_request_with(&registry(), &constrained).unwrap(),
            Request::AddIdentity { .. }
        ));

        // A malformed body is a decode error, not a crash.
        let mut truncated = vec![wire::SSH2_AGENTC_ADD_IDENTITY];
        SK_SSH_ED25519.encode(&mut truncated).unwrap();
        assert!(matches!(
            wire::parse_request_with(&registry(), &truncated),
            Err(WireError::Key(KeyDecodeError::Malformed(_)))
        ));
    }

    /// A security key's certificate decodes through [`SkDecoder`] as well.
    #[test]
    fn decodes_a_security_key_certificate_add() {
        use ssh_agent_kit::testing::{cert_body, certify};
        use ssh_key::public::{Ed25519PublicKey, SkEd25519};
        let public = SkEd25519::new(Ed25519PublicKey([0x42; 32]), "ssh:");
        let cert = certify(&KeyData::SkEd25519(public));
        // Without the public key and application: flags, handle, reserved.
        let mut private = Vec::new();
        0x01u8.encode(&mut private).unwrap();
        [1u8, 2, 3].as_slice().encode(&mut private).unwrap();
        b"".as_slice().encode(&mut private).unwrap();
        let body = cert_body(&cert, &private, "ferris@example.com");
        let mut r = body.as_slice();
        let (key, _) = ssh_agent_kit::cert::decode_cert_add(
            &registry(),
            "sk-ssh-ed25519-cert-v01@openssh.com",
            &mut r,
        )
        .unwrap();
        assert!(r.is_empty());
        assert_eq!(key.public_key().algorithm(), Algorithm::SkEd25519);
        assert!(cert.certifies(key.public_key()));
    }
}
