//! Local (software) private keys the agent holds in memory.
//!
//! A [`LocalKey`] is a private key the agent signs with directly, with no
//! OnlyKey and no challenge. Keys arrive over the agent protocol as an
//! `SSH2_AGENTC_ADD_IDENTITY` request (`ssh-add ~/.ssh/id_ed25519`); see
//! [`crate::agent::wire`]. New key types are added by implementing [`LocalKey`]
//! and one arm of [`decode`], without touching the server.

use signature::Signer;
use ssh_encoding::{Decode, Reader};
use ssh_key::private::Ed25519Keypair;
use ssh_key::public::KeyData;
use ssh_key::{PublicKey, Signature};
use std::fmt;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum LocalKeyError {
    #[error("unsupported local key type {0:?}")]
    UnsupportedType(String),
    #[error("malformed {0} private key")]
    Malformed(&'static str),
    #[error("signing with a local key failed: {0}")]
    Sign(#[from] signature::Error),
}

/// A private key held in memory that the agent signs with itself, with no
/// device and no challenge.
///
/// Implementations should not expose the secret half through `fmt::Debug`.
pub trait LocalKey: Send + Sync {
    /// The matching public key. Its comment is the identity the agent lists.
    fn public_key(&self) -> &PublicKey;

    /// Sign `data` in software, returning a complete SSH signature.
    fn sign(&self, data: &[u8]) -> Result<Signature, LocalKeyError>;

    /// Wire blob used to match sign and remove requests.
    fn key_blob(&self) -> Vec<u8> {
        self.public_key().to_bytes().expect("vec write")
    }
}

/// A boxed [`LocalKey`] with value semantics.
///
/// `PartialEq`/`Eq` compare only the public key, so a request that carries a
/// trait object can still derive them; `Debug` shows the public key only.
pub struct LocalKeyRef(Box<dyn LocalKey>);

impl LocalKeyRef {
    pub fn new(key: impl LocalKey + 'static) -> Self {
        LocalKeyRef(Box::new(key))
    }

    pub fn public_key(&self) -> &PublicKey {
        self.0.public_key()
    }

    pub fn sign(&self, data: &[u8]) -> Result<Signature, LocalKeyError> {
        self.0.sign(data)
    }

    pub fn key_blob(&self) -> Vec<u8> {
        self.0.key_blob()
    }

    pub fn comment(&self) -> &str {
        self.0.public_key().comment()
    }

    pub fn into_inner(self) -> Box<dyn LocalKey> {
        self.0
    }
}

impl fmt::Debug for LocalKeyRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("LocalKeyRef")
            .field(self.0.public_key())
            .finish()
    }
}

impl PartialEq for LocalKeyRef {
    fn eq(&self, other: &Self) -> bool {
        self.0.key_blob() == other.0.key_blob()
    }
}

impl Eq for LocalKeyRef {}

/// A plain ed25519 private key.
///
/// The seed is expanded into an [`Ed25519Keypair`], which is zeroized when the
/// key is dropped.
pub struct Ed25519LocalKey {
    pair: Ed25519Keypair,
    public: PublicKey,
}

impl Ed25519LocalKey {
    fn from_pair(pair: Ed25519Keypair, comment: &str) -> Self {
        let public = PublicKey::new(KeyData::Ed25519(pair.public), comment);
        Ed25519LocalKey { pair, public }
    }
}

impl LocalKey for Ed25519LocalKey {
    fn public_key(&self) -> &PublicKey {
        &self.public
    }

    fn sign(&self, data: &[u8]) -> Result<Signature, LocalKeyError> {
        Ok(Signer::try_sign(&self.pair, data)?)
    }
}

impl fmt::Debug for Ed25519LocalKey {
    /// Shows the public key only, so the private half never reaches a log.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ed25519LocalKey")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

/// Decode the type-specific private fields of an `ADD_IDENTITY` request body,
/// plus the trailing comment, leaving the reader just past the comment.
///
/// This is the extension point for new local key types: add an arm for the key
/// type and an implementation of [`LocalKey`].
pub fn decode(key_type: &str, reader: &mut impl Reader) -> Result<LocalKeyRef, LocalKeyError> {
    match key_type {
        "ssh-ed25519" => {
            // The agent's private fields are the public key followed by the
            // 64-byte `seed || public`, which is exactly the keypair encoding.
            let pair = Ed25519Keypair::decode(reader).map_err(|_| malformed())?;
            let comment = String::decode(reader).map_err(|_| malformed())?;
            Ok(LocalKeyRef::new(Ed25519LocalKey::from_pair(pair, &comment)))
        }
        other => Err(LocalKeyError::UnsupportedType(other.to_owned())),
    }
}

fn malformed() -> LocalKeyError {
    LocalKeyError::Malformed("ssh-ed25519")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys;
    use ssh_encoding::Encode;

    fn keypair() -> Ed25519Keypair {
        Ed25519Keypair::from_seed(&[0x42; 32])
    }

    fn encoded_body(pair: &Ed25519Keypair, comment: &str) -> Vec<u8> {
        let mut body = Vec::new();
        pair.encode(&mut body).unwrap();
        comment.encode(&mut body).unwrap();
        body
    }

    #[test]
    fn decodes_signs_and_verifies_an_ed25519_key() {
        let pair = keypair();
        let body = encoded_body(&pair, "ferris@example.com");
        let key = decode("ssh-ed25519", &mut body.as_slice()).unwrap();
        assert_eq!(key.public_key().comment(), "ferris@example.com");
        assert_eq!(
            key.public_key().key_data().ed25519().unwrap().0,
            pair.public.0
        );

        let sig = key.sign(b"hello").unwrap();
        assert_eq!(sig.algorithm(), ssh_key::Algorithm::Ed25519);
        keys::verify(key.public_key(), b"hello", &sig).unwrap();
        assert!(keys::verify(key.public_key(), b"other", &sig).is_err());
    }

    #[test]
    fn rejects_unknown_types_and_truncated_keys() {
        let mut empty: &[u8] = &[];
        assert!(matches!(
            decode("ssh-rsa", &mut empty),
            Err(LocalKeyError::UnsupportedType(t)) if t == "ssh-rsa"
        ));
        let pair = keypair();
        let mut body = encoded_body(&pair, "c");
        body.truncate(10);
        assert!(matches!(
            decode("ssh-ed25519", &mut body.as_slice()),
            Err(LocalKeyError::Malformed(_))
        ));
    }

    #[test]
    fn equality_and_debug_ignore_the_secret() {
        let a = decode(
            "ssh-ed25519",
            &mut encoded_body(&keypair(), "one").as_slice(),
        )
        .unwrap();
        let b = decode(
            "ssh-ed25519",
            &mut encoded_body(&keypair(), "one").as_slice(),
        )
        .unwrap();
        let other = Ed25519Keypair::from_seed(&[0x43; 32]);
        let c = decode("ssh-ed25519", &mut encoded_body(&other, "one").as_slice()).unwrap();
        assert_eq!(a, b);
        assert_ne!(a, c);
        let debug = format!("{a:?}");
        assert!(debug.contains("LocalKeyRef"), "{debug}");
        // The seed itself never appears in the debug output.
        assert!(!debug.contains(&hex::encode([0x42u8; 32])), "{debug}");
    }
}
