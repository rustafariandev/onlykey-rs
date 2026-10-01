//! FIDO security keys the agent serves by driving the authenticator.
//!
//! An `sk-` private key holds no secret: it carries the credential's public
//! key, application and key handle, and every signature is produced by the
//! attached FIDO device. `ssh-add FILE` loads one through
//! `SSH2_AGENTC_ADD_IDENTITY`, decoded here; signing goes through
//! [`crate::fido`].

use super::keytype::KeyDecodeError;
use crate::fido;
use crate::fido::ctaphid::CtapHid;
use crate::transport::HidTransport;
use sha2::{Digest, Sha256};
use ssh_encoding::{Decode, Encode, Reader};
use ssh_key::private::{SkEcdsaSha2NistP256, SkEd25519};
use ssh_key::public::KeyData;
use ssh_key::{Algorithm, Mpint, PublicKey, Signature};

/// `sk-ssh-ed25519@openssh.com`, from OpenSSH's `PROTOCOL.u2f`.
pub const SK_SSH_ED25519: &str = "sk-ssh-ed25519@openssh.com";
/// `sk-ecdsa-sha2-nistp256@openssh.com`, from OpenSSH's `PROTOCOL.u2f`.
pub const SK_ECDSA_P256: &str = "sk-ecdsa-sha2-nistp256@openssh.com";

/// `SSH_SK_USER_PRESENCE_REQD`: the key must be touched to sign.
const USER_PRESENCE: u8 = 0x01;
/// `SSH_SK_USER_VERIFICATION_REQD`: the key needs a PIN as well.
const USER_VERIFICATION: u8 = 0x04;

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

    /// Whether the credential belongs to SSH. Any other application may be a
    /// web credential, so the agent only signs SSH data with it.
    pub fn is_ssh_application(&self) -> bool {
        self.application.starts_with("ssh:")
    }

    /// Wire blob used to match sign and remove requests.
    pub fn key_blob(&self) -> Vec<u8> {
        self.public.to_bytes().expect("vec write")
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
        self.sign_with(&mut CtapHid::new(transport), data, on_presence)
    }

    /// [`Self::sign`] over a CTAPHID channel already in use, such as one
    /// [`Self::is_held_by`] just probed.
    pub fn sign_with<T: HidTransport>(
        &self,
        hid: &mut CtapHid<T>,
        data: &[u8],
        on_presence: &dyn Fn(),
    ) -> Result<Signature, fido::FidoError> {
        if self.needs_verification() {
            return Err(fido::FidoError::UvRequired);
        }
        let client_data_hash: [u8; 32] = Sha256::digest(data).into();
        let up = self.flags & USER_PRESENCE != 0;
        let assertion = fido::get_assertion(
            hid,
            &self.application,
            &client_data_hash,
            &self.key_handle,
            up,
            on_presence,
        )?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fido::fake::FakeFido;
    use crate::keys;

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
    fn verification_required_keys_are_refused_for_now() {
        let device = FakeFido::new(&[0x43; 32], "ssh:", &[1], 0x05);
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
        assert!(matches!(
            key.sign(device, b"hello", &|| {}),
            Err(fido::FidoError::UvRequired)
        ));
    }
}
