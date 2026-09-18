//! Conversion between device key material and SSH wire formats.

use crate::identity::Curve;
use crate::protocol::RawPublicKey;
use signature::Verifier;
use ssh_encoding::Encode;
use ssh_key::public::{EcdsaPublicKey, Ed25519PublicKey, KeyData};
use ssh_key::{Algorithm, EcdsaCurve, Mpint, PublicKey, Signature};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum KeyError {
    #[error("invalid public key from device: {0}")]
    InvalidPublicKey(ssh_key::Error),
    #[error("invalid signature from device: {0}")]
    InvalidSignature(ssh_key::Error),
    #[error("signature does not verify against the derived public key")]
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
    };
    Ok(PublicKey::new(key_data, comment))
}

/// Build the SSH signature from the 64 raw bytes the device returns.
///
/// Ed25519 signatures are used as-is. P-256 signatures arrive as `r || s` and
/// must be re-encoded as two minimal mpints.
pub fn signature(curve: Curve, raw: &[u8; 64]) -> Result<Signature, KeyError> {
    match curve {
        Curve::Ed25519 => {
            Signature::new(Algorithm::Ed25519, raw.to_vec()).map_err(KeyError::InvalidSignature)
        }
        Curve::NistP256 => {
            let mut encoded = Vec::with_capacity(74);
            for scalar in [&raw[..32], &raw[32..]] {
                Mpint::from_positive_bytes(scalar)
                    .map_err(KeyError::InvalidSignature)?
                    .encode(&mut encoded)
                    .map_err(|e| KeyError::InvalidSignature(e.into()))?;
            }
            Signature::new(
                Algorithm::Ecdsa {
                    curve: EcdsaCurve::NistP256,
                },
                encoded,
            )
            .map_err(KeyError::InvalidSignature)
        }
    }
}

/// Check a device signature against the derived public key.
pub fn verify(key: &PublicKey, message: &[u8], sig: &Signature) -> Result<(), KeyError> {
    Verifier::verify(key, message, sig).map_err(|_| KeyError::VerificationFailed)
}

/// Curve of an SSH public key, if it is one this agent can produce.
pub fn curve_of(key: &PublicKey) -> Option<Curve> {
    match key.key_data() {
        KeyData::Ed25519(_) => Some(Curve::Ed25519),
        KeyData::Ecdsa(EcdsaPublicKey::NistP256(_)) => Some(Curve::NistP256),
        _ => None,
    }
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
        let key = public_key(&raw, "<ssh://james@example.com|ed25519>").unwrap();
        assert_eq!(
            key.to_openssh().unwrap(),
            g["pubkeys"]["ed25519_line"].as_str().unwrap()
        );
        assert_eq!(curve_of(&key), Some(Curve::Ed25519));
    }

    #[test]
    fn p256_pub_line_matches_python() {
        let g = goldens();
        let raw = RawPublicKey::NistP256(hex64(g["pubkeys"]["p256_raw_xy"].as_str().unwrap()));
        let key = public_key(&raw, "<ssh://james@example.com|nist256p1>").unwrap();
        assert_eq!(
            key.to_openssh().unwrap(),
            g["pubkeys"]["p256_line"].as_str().unwrap()
        );
        assert_eq!(curve_of(&key), Some(Curve::NistP256));
    }

    #[test]
    fn ed25519_signature_verifies() {
        let g = goldens();
        let raw = RawPublicKey::Ed25519(hex32(g["pubkeys"]["ed25519_raw"].as_str().unwrap()));
        let key = public_key(&raw, "").unwrap();
        let msg = hex::decode(g["ed25519_sig_example"]["msg"].as_str().unwrap()).unwrap();
        let sig = signature(
            Curve::Ed25519,
            &hex64(g["ed25519_sig_example"]["sig"].as_str().unwrap()),
        )
        .unwrap();
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
        let sig = signature(Curve::NistP256, &rs).unwrap();
        verify(&key, &msg, &sig).unwrap();
        assert!(verify(&key, b"other", &sig).is_err());

        // The encoded form must decode back to the same r and s.
        let mut reader = sig.as_bytes();
        let r = Mpint::decode(&mut reader).unwrap();
        let s = Mpint::decode(&mut reader).unwrap();
        assert_eq!(r.as_positive_bytes().unwrap(), &rs[..32]);
        assert_eq!(s.as_positive_bytes().unwrap(), &rs[32..]);
    }
}
