//! Pluggable SSH key types the agent can load with `ssh-add FILE`.
//!
//! An [`SSH2_AGENTC_ADD_IDENTITY`](super::wire::SSH2_AGENTC_ADD_IDENTITY)
//! request names its key type (for example `ssh-ed25519` or
//! `sk-ssh-ed25519@openssh.com`) followed by the type-specific body. Decoding
//! is delegated to a [`KeyDecoder`] registered under that name, so callers can
//! teach the agent new key types without changing it. A [`KeyRegistry`] holds
//! the decoders, the built-ins first; a later registration under a name wins.
//! This is the key-material counterpart of [`super::Extension`].
//!
//! A decoded key is a [`HeldKey`]: either a private key the agent signs with
//! in memory ([`LocalKey`](super::local::LocalKey)) or a FIDO credential the
//! authenticator signs for ([`SkKey`]). Register a decoder with
//! [`Agent::register_key_type`](super::server::Agent::register_key_type).

use super::local::{self, LocalKeyRef};
use super::sk::{self, SkKey};
use ssh_key::PublicKey;
use thiserror::Error;

/// Why an `ADD_IDENTITY` request's key could not be decoded.
#[derive(Debug, Error)]
pub enum KeyDecodeError {
    #[error("unsupported key type {0:?}")]
    UnsupportedType(String),
    #[error("malformed {0} private key")]
    Malformed(&'static str),
    #[error("{key_type} key of {bits} bits is below the {min}-bit minimum")]
    TooSmall {
        key_type: &'static str,
        bits: usize,
        min: usize,
    },
}

/// A private key decoded from an `ADD_IDENTITY` request.
///
/// These are the two signing capabilities the agent serves.
#[derive(Debug, PartialEq, Eq)]
pub enum HeldKey {
    /// A private key the agent signs with in memory, with no device.
    Local(LocalKeyRef),
    /// A FIDO credential the authenticator signs for. Boxed to keep the enum
    /// small next to the much smaller `Local` variant.
    SecurityKey(Box<SkKey>),
}

impl HeldKey {
    /// The matching public key, whose comment is the identity the agent lists.
    pub fn public_key(&self) -> &PublicKey {
        match self {
            HeldKey::Local(key) => key.public_key(),
            HeldKey::SecurityKey(key) => key.public_key(),
        }
    }

    /// Wire blob used to match sign and remove requests.
    pub fn key_blob(&self) -> Vec<u8> {
        match self {
            HeldKey::Local(key) => key.key_blob(),
            HeldKey::SecurityKey(key) => key.key_blob(),
        }
    }
}

/// Decodes one family of SSH key types from an `ADD_IDENTITY` request.
///
/// Implementations read the type-specific fields and the trailing comment,
/// leaving `reader` just past the comment. Register one with
/// [`Agent::register_key_type`](super::server::Agent::register_key_type); a
/// later registration under a name wins.
pub trait KeyDecoder: Send + Sync {
    /// The SSH key type names this decoder answers, e.g. `["ssh-ed25519"]`.
    fn key_types(&self) -> &[&str];

    /// Decode the body after the key type name, including the trailing
    /// comment. `key_type` is the name from [`Self::key_types`] that matched.
    fn decode(&self, key_type: &str, reader: &mut &[u8]) -> Result<HeldKey, KeyDecodeError>;
}

/// A local (in-memory) private key type, decoded by [`local::decode`].
struct LocalDecoder(&'static [&'static str]);

impl KeyDecoder for LocalDecoder {
    fn key_types(&self) -> &[&str] {
        self.0
    }

    fn decode(&self, key_type: &str, reader: &mut &[u8]) -> Result<HeldKey, KeyDecodeError> {
        local::decode(key_type, reader).map(HeldKey::Local)
    }
}

/// The FIDO `sk-` key types, decoded by [`sk::decode`].
struct SkDecoder;

impl KeyDecoder for SkDecoder {
    fn key_types(&self) -> &[&str] {
        &[sk::SK_SSH_ED25519, sk::SK_ECDSA_P256]
    }

    fn decode(&self, key_type: &str, reader: &mut &[u8]) -> Result<HeldKey, KeyDecodeError> {
        sk::decode(key_type, reader).map(|key| HeldKey::SecurityKey(Box::new(key)))
    }
}

/// The key types the agent can decode, in registration order.
pub struct KeyRegistry {
    decoders: Vec<Box<dyn KeyDecoder>>,
}

impl KeyRegistry {
    /// A registry with every built-in key type registered: ed25519, RSA,
    /// ECDSA (nistp256/384/521), DSA and the FIDO `sk-` types.
    pub fn builtin() -> Self {
        let mut registry = KeyRegistry {
            decoders: Vec::new(),
        };
        registry.register(LocalDecoder(&["ssh-ed25519"]));
        registry.register(LocalDecoder(&["ssh-rsa"]));
        registry.register(LocalDecoder(&[
            "ecdsa-sha2-nistp256",
            "ecdsa-sha2-nistp384",
            "ecdsa-sha2-nistp521",
        ]));
        registry.register(LocalDecoder(&["ssh-dss"]));
        registry.register(SkDecoder);
        registry
    }

    /// Register a decoder. A later registration under a name wins, so a caller
    /// can replace a built-in type as well as add a new one.
    pub fn register(&mut self, decoder: impl KeyDecoder + 'static) {
        self.decoders.push(Box::new(decoder));
    }

    /// Decode an `ADD_IDENTITY` body's key by name, including the trailing
    /// comment. An unregistered name is [`KeyDecodeError::UnsupportedType`].
    pub fn decode(&self, key_type: &str, reader: &mut &[u8]) -> Result<HeldKey, KeyDecodeError> {
        self.decoders
            .iter()
            .rev()
            .find(|decoder| decoder.key_types().contains(&key_type))
            .ok_or_else(|| KeyDecodeError::UnsupportedType(key_type.to_owned()))?
            .decode(key_type, reader)
    }
}

impl Default for KeyRegistry {
    fn default() -> Self {
        Self::builtin()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssh_encoding::Encode;
    use ssh_key::private::Ed25519Keypair;

    fn ed25519_body(comment: &str) -> Vec<u8> {
        let pair = Ed25519Keypair::from_seed(&[0x42; 32]);
        let mut body = Vec::new();
        pair.encode(&mut body).unwrap();
        comment.encode(&mut body).unwrap();
        body
    }

    #[test]
    fn builtin_registry_decodes_local_and_security_keys() {
        let registry = KeyRegistry::builtin();

        let body = ed25519_body("ferris@example.com");
        match registry
            .decode("ssh-ed25519", &mut body.as_slice())
            .unwrap()
        {
            HeldKey::Local(key) => assert_eq!(key.comment(), "ferris@example.com"),
            other => panic!("expected a local key, got {other:?}"),
        }

        // A malformed security-key body is a decode error like any other.
        let mut sk: &[u8] = &[];
        assert!(matches!(
            registry.decode("sk-ssh-ed25519@openssh.com", &mut sk),
            Err(KeyDecodeError::Malformed(_))
        ));

        let mut unknown: &[u8] = &[];
        assert!(matches!(
            registry.decode("ssh-future@example.com", &mut unknown),
            Err(KeyDecodeError::UnsupportedType(t)) if t == "ssh-future@example.com"
        ));
    }

    /// A decoder registered for a new name is consulted for that name.
    #[test]
    fn a_registered_decoder_serves_a_new_key_type() {
        struct Example(&'static [&'static str]);

        impl KeyDecoder for Example {
            fn key_types(&self) -> &[&str] {
                self.0
            }

            fn decode(
                &self,
                _key_type: &str,
                reader: &mut &[u8],
            ) -> Result<HeldKey, KeyDecodeError> {
                // Reuse the ed25519 body: the point is that this decoder was
                // reached for a name the built-ins do not know.
                local::decode("ssh-ed25519", reader).map(HeldKey::Local)
            }
        }

        let mut registry = KeyRegistry::builtin();
        registry.register(Example(&["ssh-example@example.com"]));
        let body = ed25519_body("ferris@example.com");
        match registry
            .decode("ssh-example@example.com", &mut body.as_slice())
            .unwrap()
        {
            HeldKey::Local(key) => assert_eq!(key.comment(), "ferris@example.com"),
            other => panic!("expected a local key, got {other:?}"),
        }
    }

    /// A later registration under a name overrides the earlier one.
    #[test]
    fn the_last_registration_under_a_name_wins() {
        struct Reject(&'static [&'static str]);

        impl KeyDecoder for Reject {
            fn key_types(&self) -> &[&str] {
                self.0
            }

            fn decode(
                &self,
                _key_type: &str,
                _reader: &mut &[u8],
            ) -> Result<HeldKey, KeyDecodeError> {
                Err(KeyDecodeError::Malformed("overridden"))
            }
        }

        let mut registry = KeyRegistry::builtin();
        registry.register(Reject(&["ssh-ed25519"]));
        let body = ed25519_body("ferris@example.com");
        assert!(matches!(
            registry.decode("ssh-ed25519", &mut body.as_slice()),
            Err(KeyDecodeError::Malformed("overridden"))
        ));
    }
}
