//! Local (software) private keys the agent holds in memory.
//!
//! A [`LocalKey`] is a private key the agent signs with directly, with no
//! OnlyKey and no challenge. Keys arrive over the agent protocol as an
//! `SSH2_AGENTC_ADD_IDENTITY` request (`ssh-add ~/.ssh/id_ed25519`); see
//! [`crate::agent::wire`]. New key types are added by implementing [`LocalKey`]
//! and one arm of [`decode`], without touching the server.

use sha2::{Sha256, Sha512};
use signature::{SignatureEncoding, Signer};
use ssh_encoding::{Decode, Reader};
use ssh_key::private::{Ed25519Keypair, RsaKeypair};
use ssh_key::public::KeyData;
use ssh_key::{Algorithm, HashAlg, Mpint, PublicKey, Signature};
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
    #[error("cannot encode the signature: {0}")]
    Signature(#[from] ssh_key::Error),
    #[error("cannot sign with an unsupported RSA digest")]
    UnsupportedHash,
}

/// A private key held in memory that the agent signs with itself, with no
/// device and no challenge.
///
/// Implementations should not expose the secret half through `fmt::Debug`.
pub trait LocalKey: Send + Sync {
    /// The matching public key. Its comment is the identity the agent lists.
    fn public_key(&self) -> &PublicKey;

    /// Sign `data` in software, returning a complete SSH signature. `hash`
    /// selects the RSA digest (`sha2-256` or `sha2-512`); other key types
    /// ignore it.
    fn sign(&self, data: &[u8], hash: HashAlg) -> Result<Signature, LocalKeyError>;

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

    pub fn sign(&self, data: &[u8], hash: HashAlg) -> Result<Signature, LocalKeyError> {
        self.0.sign(data, hash)
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

    fn sign(&self, data: &[u8], _hash: HashAlg) -> Result<Signature, LocalKeyError> {
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

/// A plain RSA private key.
///
/// The SSH wire form carries `n`, `e`, `d`, `iqmp`, `p` and `q`; the key is
/// rebuilt with the `rsa` crate, which recomputes the CRT parameters and
/// zeroizes every secret when dropped. OpenSSH labels RSA signatures with the
/// requested digest, so [`LocalKey::sign`] packs a PKCS#1 v1.5 signature under
/// `rsa-sha2-256` or `rsa-sha2-512`.
pub struct RsaLocalKey {
    key: rsa::RsaPrivateKey,
    public: PublicKey,
}

impl RsaLocalKey {
    fn from_pair(pair: RsaKeypair, comment: &str) -> Result<Self, LocalKeyError> {
        let key = rsa_private_key(&pair)?;
        let public = PublicKey::new(KeyData::Rsa(pair.public), comment);
        Ok(RsaLocalKey { key, public })
    }
}

/// Rebuild an [`rsa::RsaPrivateKey`] from the SSH fields, with `p` and `q` in
/// the order the wire gives them (`ssh-key`'s own conversion passes `p` twice,
/// so it is not used).
fn rsa_private_key(pair: &RsaKeypair) -> Result<rsa::RsaPrivateKey, LocalKeyError> {
    let mpint = |m: &Mpint| {
        m.as_positive_bytes()
            .map(rsa::BigUint::from_bytes_be)
            .ok_or_else(malformed_rsa)
    };
    rsa::RsaPrivateKey::from_components(
        mpint(&pair.public.n)?,
        mpint(&pair.public.e)?,
        mpint(&pair.private.d)?,
        vec![mpint(&pair.private.p)?, mpint(&pair.private.q)?],
    )
    .map_err(|_| malformed_rsa())
}

fn malformed_rsa() -> LocalKeyError {
    LocalKeyError::Malformed("ssh-rsa")
}

impl LocalKey for RsaLocalKey {
    fn public_key(&self) -> &PublicKey {
        &self.public
    }

    fn sign(&self, data: &[u8], hash: HashAlg) -> Result<Signature, LocalKeyError> {
        let (algorithm, raw) = match hash {
            HashAlg::Sha256 => (
                Algorithm::Rsa {
                    hash: Some(HashAlg::Sha256),
                },
                rsa::pkcs1v15::SigningKey::<Sha256>::new(self.key.clone()).try_sign(data)?,
            ),
            HashAlg::Sha512 => (
                Algorithm::Rsa {
                    hash: Some(HashAlg::Sha512),
                },
                rsa::pkcs1v15::SigningKey::<Sha512>::new(self.key.clone()).try_sign(data)?,
            ),
            _ => return Err(LocalKeyError::UnsupportedHash),
        };
        Ok(Signature::new(algorithm, raw.to_vec())?)
    }
}

impl fmt::Debug for RsaLocalKey {
    /// Shows the public key only, so the private half never reaches a log.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RsaLocalKey")
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
            let pair = Ed25519Keypair::decode(reader).map_err(|_| malformed_ed25519())?;
            let comment = String::decode(reader).map_err(|_| malformed_ed25519())?;
            Ok(LocalKeyRef::new(Ed25519LocalKey::from_pair(pair, &comment)))
        }
        "ssh-rsa" => {
            // The agent's RSA private fields are `n e d iqmp p q`, which is
            // exactly the keypair encoding, followed by the comment.
            let pair = RsaKeypair::decode(reader).map_err(|_| malformed_rsa())?;
            let comment = String::decode(reader).map_err(|_| malformed_rsa())?;
            Ok(LocalKeyRef::new(RsaLocalKey::from_pair(pair, &comment)?))
        }
        other => Err(LocalKeyError::UnsupportedType(other.to_owned())),
    }
}

fn malformed_ed25519() -> LocalKeyError {
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

        let sig = key.sign(b"hello", HashAlg::Sha512).unwrap();
        assert_eq!(sig.algorithm(), Algorithm::Ed25519);
        keys::verify(key.public_key(), b"hello", &sig).unwrap();
        assert!(keys::verify(key.public_key(), b"other", &sig).is_err());
    }

    #[test]
    fn rejects_unknown_types_and_truncated_keys() {
        let mut empty: &[u8] = &[];
        assert!(matches!(
            decode("ssh-dss", &mut empty),
            Err(LocalKeyError::UnsupportedType(t)) if t == "ssh-dss"
        ));
        let pair = keypair();
        let mut body = encoded_body(&pair, "c");
        body.truncate(10);
        assert!(matches!(
            decode("ssh-ed25519", &mut body.as_slice()),
            Err(LocalKeyError::Malformed(_))
        ));
        let mut rsa: &[u8] = &[];
        assert!(matches!(
            decode("ssh-rsa", &mut rsa),
            Err(LocalKeyError::Malformed("ssh-rsa"))
        ));
    }

    /// Build the agent's `ssh-rsa` private-key body from a known key and check
    /// that it decodes, signs each supported digest and verifies.
    #[test]
    fn decodes_signs_and_verifies_an_rsa_key() {
        use rsa::pkcs1::DecodeRsaPrivateKey;
        use rsa::traits::PublicKeyParts;

        let sk = rsa::RsaPrivateKey::from_pkcs1_pem(include_str!("../../tests/common/rsa2048.pem"))
            .unwrap();
        let pair = RsaKeypair::try_from(&sk).unwrap();
        let mut body = Vec::new();
        pair.encode(&mut body).unwrap();
        "ferris@example.com".encode(&mut body).unwrap();

        let key = decode("ssh-rsa", &mut body.as_slice()).unwrap();
        assert_eq!(key.public_key().comment(), "ferris@example.com");
        let n = key.public_key().key_data().rsa().unwrap().n.clone();
        assert_eq!(
            n.as_positive_bytes().unwrap(),
            sk.n().to_bytes_be().as_slice()
        );

        for hash in [HashAlg::Sha256, HashAlg::Sha512] {
            let sig = key.sign(b"hello", hash).unwrap();
            assert_eq!(sig.algorithm(), Algorithm::Rsa { hash: Some(hash) });
            assert_eq!(sig.as_bytes().len(), 256);
            keys::verify(key.public_key(), b"hello", &sig).unwrap();
            assert!(keys::verify(key.public_key(), b"other", &sig).is_err());
        }

        let debug = format!("{key:?}");
        assert!(debug.contains("LocalKeyRef"), "{debug}");
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
