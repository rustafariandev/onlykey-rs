//! Conversion between device key material and SSH wire formats.

use crate::protocol::RawPublicKey;
use signature::Verifier;
use ssh_encoding::Encode;
use ssh_key::public::{EcdsaPublicKey, Ed25519PublicKey, KeyData, RsaPublicKey};
use ssh_key::{Algorithm, EcdsaCurve, Mpint, PublicKey, Signature};
use thiserror::Error;

/// The public exponent of every RSA key the token holds.
const RSA_EXPONENT: [u8; 3] = [0x01, 0x00, 0x01];

#[derive(Debug, Error)]
pub enum KeyError {
    #[error("invalid public key from device: {0}")]
    InvalidPublicKey(ssh_key::Error),
    #[error("invalid signature from device: {0}")]
    InvalidSignature(ssh_key::Error),
    #[error("signature from device is {0} bytes, expected 64")]
    SignatureLength(usize),
    #[error("cannot build a {0} signature")]
    UnsupportedAlgorithm(Algorithm),
    #[error("signature does not verify against the public key")]
    VerificationFailed,
}

/// Wrap a raw device key as an SSH public key with the given comment.
pub fn public_key(raw: &RawPublicKey, comment: &str) -> Result<PublicKey, KeyError> {
    let key_data = match raw {
        RawPublicKey::Ed25519(bytes) => KeyData::Ed25519(Ed25519PublicKey(*bytes)),
        RawPublicKey::NistP256(xy) => {
            let mut sec1 = [0u8; 65];
            sec1[0] = 0x04;
            sec1[1..].copy_from_slice(xy);
            KeyData::Ecdsa(
                EcdsaPublicKey::from_sec1_bytes(&sec1).map_err(KeyError::InvalidPublicKey)?,
            )
        }
        RawPublicKey::Rsa(modulus) => KeyData::Rsa(RsaPublicKey {
            e: Mpint::from_positive_bytes(&RSA_EXPONENT).map_err(KeyError::InvalidPublicKey)?,
            n: Mpint::from_positive_bytes(modulus).map_err(KeyError::InvalidPublicKey)?,
        }),
    };
    Ok(PublicKey::new(key_data, comment))
}

/// Build the SSH signature from the raw bytes the device returns.
///
/// Ed25519 signatures (64 bytes) are used as-is. P-256 signatures arrive as
/// `r || s` and must be re-encoded as two minimal mpints. RSA signatures are
/// the PKCS#1 v1.5 block as-is, labelled with the hash the token was given.
pub fn signature(algorithm: &Algorithm, raw: &[u8]) -> Result<Signature, KeyError> {
    match algorithm {
        Algorithm::Ed25519 | Algorithm::Rsa { hash: Some(_) } => {
            Signature::new(algorithm.clone(), raw.to_vec()).map_err(KeyError::InvalidSignature)
        }
        Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP256,
        } => {
            if raw.len() != 64 {
                return Err(KeyError::SignatureLength(raw.len()));
            }
            let mut encoded = Vec::with_capacity(74);
            for scalar in [&raw[..32], &raw[32..]] {
                Mpint::from_positive_bytes(scalar)
                    .map_err(KeyError::InvalidSignature)?
                    .encode(&mut encoded)
                    .map_err(|e| KeyError::InvalidSignature(e.into()))?;
            }
            Signature::new(algorithm.clone(), encoded).map_err(KeyError::InvalidSignature)
        }
        other => Err(KeyError::UnsupportedAlgorithm(other.clone())),
    }
}

/// Check a device signature against the public key.
pub fn verify(key: &PublicKey, message: &[u8], sig: &Signature) -> Result<(), KeyError> {
    Verifier::verify(key, message, sig).map_err(|_| KeyError::VerificationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssh_encoding::Decode;

    fn goldens() -> serde_json::Value {
        serde_json::from_str(include_str!("../tests/goldens.json")).unwrap()
    }

    fn hex32(s: &str) -> [u8; 32] {
        hex::decode(s).unwrap().try_into().unwrap()
    }

    fn hex64(s: &str) -> [u8; 64] {
        hex::decode(s).unwrap().try_into().unwrap()
    }

    #[test]
    fn ed25519_pub_line_matches_python() {
        let g = goldens();
        let raw = RawPublicKey::Ed25519(hex32(g["pubkeys"]["ed25519_raw"].as_str().unwrap()));
        let line = g["pubkeys"]["ed25519_line"].as_str().unwrap();
        let comment = line.rsplit_once(' ').unwrap().1;
        let key = public_key(&raw, comment).unwrap();
        assert_eq!(key.to_openssh().unwrap(), line);
        assert_eq!(key.algorithm(), Algorithm::Ed25519);
    }

    #[test]
    fn p256_pub_line_matches_python() {
        let g = goldens();
        let raw = RawPublicKey::NistP256(hex64(g["pubkeys"]["p256_raw_xy"].as_str().unwrap()));
        let line = g["pubkeys"]["p256_line"].as_str().unwrap();
        let comment = line.rsplit_once(' ').unwrap().1;
        let key = public_key(&raw, comment).unwrap();
        assert_eq!(key.to_openssh().unwrap(), line);
        assert_eq!(
            key.algorithm(),
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP256
            }
        );
    }

    #[test]
    fn ed25519_signature_verifies() {
        let g = goldens();
        let raw = RawPublicKey::Ed25519(hex32(g["pubkeys"]["ed25519_raw"].as_str().unwrap()));
        let key = public_key(&raw, "").unwrap();
        let msg = hex::decode(g["ed25519_sig_example"]["msg"].as_str().unwrap()).unwrap();
        let sig = signature(
            &Algorithm::Ed25519,
            &hex64(g["ed25519_sig_example"]["sig"].as_str().unwrap()),
        )
        .unwrap();
        assert!(matches!(
            signature(&Algorithm::Ed25519, &[0; 63]),
            Err(KeyError::InvalidSignature(_))
        ));
        verify(&key, &msg, &sig).unwrap();
        assert!(verify(&key, b"other", &sig).is_err());
        assert_eq!(sig.algorithm(), Algorithm::Ed25519);
    }

    #[test]
    fn p256_signature_verifies_and_uses_minimal_mpints() {
        let g = goldens();
        let raw = RawPublicKey::NistP256(hex64(g["pubkeys"]["p256_raw_xy"].as_str().unwrap()));
        let key = public_key(&raw, "").unwrap();
        let msg = hex::decode(g["p256_sig_example"]["msg"].as_str().unwrap()).unwrap();
        let rs = hex64(g["p256_sig_example"]["sig_rs"].as_str().unwrap());
        let p256 = Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP256,
        };
        assert!(matches!(
            signature(&p256, &rs[..63]),
            Err(KeyError::SignatureLength(63))
        ));
        let sig = signature(&p256, &rs).unwrap();
        verify(&key, &msg, &sig).unwrap();
        assert!(verify(&key, b"other", &sig).is_err());

        // The encoded form must decode back to the same r and s.
        let mut reader = sig.as_bytes();
        let r = Mpint::decode(&mut reader).unwrap();
        let s = Mpint::decode(&mut reader).unwrap();
        assert_eq!(r.as_positive_bytes().unwrap(), &rs[..32]);
        assert_eq!(s.as_positive_bytes().unwrap(), &rs[32..]);
    }

    #[test]
    fn rsa_modulus_becomes_ssh_rsa_key_and_pkcs1_signatures_verify() {
        use rsa::pkcs1::DecodeRsaPrivateKey;
        use rsa::traits::PublicKeyParts;
        use sha2::Digest;
        use ssh_key::HashAlg;

        let sk = rsa::RsaPrivateKey::from_pkcs1_pem(include_str!("../tests/common/rsa2048.pem"))
            .unwrap();
        let modulus = sk.n().to_bytes_be();
        assert_eq!(modulus.len(), 256);
        let key = public_key(&RawPublicKey::Rsa(modulus), "<ssh://a@b|rsa|RSA1>").unwrap();
        assert_eq!(key.algorithm(), Algorithm::Rsa { hash: None });
        let line = key.to_openssh().unwrap();
        assert!(line.starts_with("ssh-rsa AAAAB3NzaC1yc2E"), "{line}");
        assert_eq!(PublicKey::from_openssh(&line).unwrap(), key);

        // The token signs a precomputed hash; the label says which one.
        for (hash, digest) in [
            (HashAlg::Sha256, sha2::Sha256::digest(b"hello").to_vec()),
            (HashAlg::Sha512, sha2::Sha512::digest(b"hello").to_vec()),
        ] {
            let raw = match hash {
                HashAlg::Sha256 => sk.sign(rsa::Pkcs1v15Sign::new::<sha2::Sha256>(), &digest),
                HashAlg::Sha512 => sk.sign(rsa::Pkcs1v15Sign::new::<sha2::Sha512>(), &digest),
                _ => unreachable!(),
            }
            .unwrap();
            assert_eq!(raw.len(), 256);
            let sig = signature(&Algorithm::Rsa { hash: Some(hash) }, &raw).unwrap();
            assert_eq!(sig.algorithm(), Algorithm::Rsa { hash: Some(hash) });
            verify(&key, b"hello", &sig).unwrap();
            assert!(verify(&key, b"other", &sig).is_err());
            // A mislabelled hash must not verify either.
            let other = match hash {
                HashAlg::Sha256 => HashAlg::Sha512,
                _ => HashAlg::Sha256,
            };
            let wrong = signature(&Algorithm::Rsa { hash: Some(other) }, &raw).unwrap();
            assert!(verify(&key, b"hello", &wrong).is_err());
        }
        assert!(matches!(
            signature(&Algorithm::Rsa { hash: None }, &[1; 256]),
            Err(KeyError::UnsupportedAlgorithm(_))
        ));
    }
}
