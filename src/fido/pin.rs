//! CTAP2 `authenticatorClientPIN` (0x06): turning the user's PIN into a PIN
//! token that authorises a getAssertion.
//!
//! A credential enrolled with user verification required (`ssh-keygen -O
//! verify-required`) signs only when the getAssertion carries
//! `pinUvAuthParam`, an HMAC of `clientDataHash` under a PIN token. The token
//! comes from `getPINToken`: the host agrees an ECDH P-256 secret with the
//! authenticator and sends it the encrypted hash of the PIN.
//!
//! Both PIN/UV auth protocols are implemented: protocol 1 (CTAP2.0, AES-CBC
//! with a zero IV and 16-byte HMACs) and protocol 2 (CTAP2.1, HKDF-derived
//! keys, a random IV and 32-byte HMACs). [`Info::protocol`] picks one from
//! what the authenticator lists.

use super::FidoError;
use super::ctap_status;
use super::ctaphid::{CTAPHID_CBOR, CtapHid};
use crate::transport::HidTransport;
use cbc::cipher::block_padding::NoPadding;
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use minicbor::{Decoder, Encoder};
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::{EncodedPoint, PublicKey, SecretKey};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// The CTAP2 command byte of `authenticatorGetInfo`.
pub const AUTHENTICATOR_GET_INFO: u8 = 0x04;
/// The CTAP2 command byte of `authenticatorClientPIN`.
pub const AUTHENTICATOR_CLIENT_PIN: u8 = 0x06;

/// `authenticatorClientPIN` subcommands.
pub const GET_RETRIES: u8 = 0x01;
pub const GET_KEY_AGREEMENT: u8 = 0x02;
pub const GET_PIN_TOKEN: u8 = 0x05;

/// Shortest PIN in Unicode code points and longest in UTF-8 bytes, as
/// CTAP2 requires. A PIN outside these bounds is refused before it reaches
/// the authenticator, so it does not cost one of the PIN's tries.
pub const MIN_PIN_CHARS: usize = 4;
pub const MAX_PIN_BYTES: usize = 63;

/// COSE key parameters for an ECDH P-256 key agreement key.
const COSE_KTY: i8 = 1;
const COSE_ALG: i8 = 3;
const COSE_CRV: i8 = -1;
const COSE_X: i8 = -2;
const COSE_Y: i8 = -3;
const KTY_EC2: i8 = 2;
const CRV_P256: i8 = 1;
/// `ECDH-ES+HKDF-256`, the algorithm CTAP2 names for its key agreement key.
const ALG_ECDH_ES_HKDF_256: i8 = -25;

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
type HmacSha256 = Hmac<Sha256>;

/// A PIN/UV auth protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PinProtocol {
    /// Protocol 1, from CTAP2.0.
    V1,
    /// Protocol 2, from CTAP2.1.
    V2,
}

impl PinProtocol {
    /// The protocol's number on the wire.
    pub fn number(self) -> u8 {
        match self {
            PinProtocol::V1 => 1,
            PinProtocol::V2 => 2,
        }
    }

    /// The shared secret from the x-coordinate `z` of the ECDH point:
    /// `SHA-256(z)` for protocol 1, an HMAC key then an AES key derived with
    /// HKDF-SHA-256 for protocol 2.
    fn kdf(self, z: &[u8]) -> Zeroizing<Vec<u8>> {
        match self {
            PinProtocol::V1 => Zeroizing::new(Sha256::digest(z).to_vec()),
            PinProtocol::V2 => {
                let hkdf = hkdf::Hkdf::<Sha256>::new(Some(&[0u8; 32]), z);
                let mut secret = Zeroizing::new(vec![0u8; 64]);
                hkdf.expand(b"CTAP2 HMAC key", &mut secret[..32])
                    .expect("32 bytes is a valid HKDF length");
                hkdf.expand(b"CTAP2 AES key", &mut secret[32..])
                    .expect("32 bytes is a valid HKDF length");
                secret
            }
        }
    }

    /// The AES key within a shared secret.
    fn aes_key(self, key: &[u8]) -> Result<&[u8; 32], FidoError> {
        let key = match self {
            PinProtocol::V1 => key,
            PinProtocol::V2 => key.get(32..).unwrap_or_default(),
        };
        key.try_into()
            .map_err(|_| FidoError::Protocol("bad PIN protocol key length"))
    }

    /// Encrypt `plaintext`, a whole number of AES blocks, under the shared
    /// secret `key`: with a zero IV for protocol 1, and with a random IV
    /// placed before the ciphertext for protocol 2.
    pub fn encrypt(self, key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, FidoError> {
        let mut iv = [0u8; 16];
        if self == PinProtocol::V2 {
            OsRng
                .try_fill_bytes(&mut iv)
                .map_err(|_| FidoError::Protocol("no system randomness"))?;
        }
        self.encrypt_with_iv(key, &iv, plaintext)
    }

    fn encrypt_with_iv(
        self,
        key: &[u8],
        iv: &[u8; 16],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, FidoError> {
        if !plaintext.len().is_multiple_of(16) {
            return Err(FidoError::Protocol("PIN protocol data is not whole blocks"));
        }
        let mut buffer = plaintext.to_vec();
        Aes256CbcEnc::new(self.aes_key(key)?.into(), iv.into())
            .encrypt_padded_mut::<NoPadding>(&mut buffer, plaintext.len())
            .map_err(|_| FidoError::Protocol("PIN protocol data is not whole blocks"))?;
        let mut out = Vec::with_capacity(16 + buffer.len());
        if self == PinProtocol::V2 {
            out.extend_from_slice(iv);
        }
        out.extend_from_slice(&buffer);
        Ok(out)
    }

    /// Decrypt what the authenticator encrypted under the shared secret
    /// `key`.
    pub fn decrypt(self, key: &[u8], ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, FidoError> {
        let (iv, body) = match self {
            PinProtocol::V1 => ([0u8; 16], ciphertext),
            PinProtocol::V2 => {
                if ciphertext.len() < 16 {
                    return Err(FidoError::Protocol("short PIN protocol ciphertext"));
                }
                let (iv, body) = ciphertext.split_at(16);
                (iv.try_into().expect("split at 16"), body)
            }
        };
        if body.is_empty() || !body.len().is_multiple_of(16) {
            return Err(FidoError::Protocol("PIN protocol data is not whole blocks"));
        }
        let mut buffer = Zeroizing::new(body.to_vec());
        Aes256CbcDec::new(self.aes_key(key)?.into(), (&iv).into())
            .decrypt_padded_mut::<NoPadding>(&mut buffer)
            .map_err(|_| FidoError::Protocol("PIN protocol data is not whole blocks"))?;
        Ok(buffer)
    }

    /// HMAC-SHA-256 of `message` under `key`: its first 16 bytes for
    /// protocol 1, all 32 for protocol 2. A protocol 2 shared secret
    /// authenticates with its HMAC half; a PIN token is used whole.
    pub fn authenticate(self, key: &[u8], message: &[u8]) -> Vec<u8> {
        let key = match self {
            PinProtocol::V2 if key.len() == 64 => &key[..32],
            _ => key,
        };
        let mut mac = HmacSha256::new_from_slice(key).expect("HMAC takes any key length");
        mac.update(message);
        let tag = mac.finalize().into_bytes();
        match self {
            PinProtocol::V1 => tag[..16].to_vec(),
            PinProtocol::V2 => tag.to_vec(),
        }
    }
}

/// What `authenticatorGetInfo` says about PINs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Info {
    /// The `clientPin` option: `Some(true)` when a PIN is set,
    /// `Some(false)` when one could be but is not, `None` when PINs are not
    /// supported.
    pub client_pin: Option<bool>,
    /// The PIN/UV auth protocols listed, in the authenticator's order.
    pub protocols: Vec<u8>,
}

impl Info {
    /// The protocol to use: 2 when listed, else 1. An authenticator that
    /// lists none is a CTAP2.0 one, which speaks protocol 1.
    pub fn protocol(&self) -> Option<PinProtocol> {
        if self.protocols.is_empty() {
            return Some(PinProtocol::V1);
        }
        if self.protocols.contains(&2) {
            Some(PinProtocol::V2)
        } else if self.protocols.contains(&1) {
            Some(PinProtocol::V1)
        } else {
            None
        }
    }
}

/// Ask the authenticator for its options and PIN protocols.
pub fn get_info<T: HidTransport>(hid: &mut CtapHid<T>) -> Result<Info, FidoError> {
    let reply = command(hid, &[AUTHENTICATOR_GET_INFO])?;
    parse_info(&reply)
}

fn parse_info(cbor: &[u8]) -> Result<Info, FidoError> {
    let mut d = Decoder::new(cbor);
    let mut info = Info::default();
    for _ in 0..definite_map(&mut d)? {
        match d.u8().map_err(cbor_error)? {
            4 => {
                for _ in 0..definite_map(&mut d)? {
                    let name = d.str().map_err(cbor_error)?;
                    if name == "clientPin" {
                        info.client_pin = Some(d.bool().map_err(cbor_error)?);
                    } else {
                        d.skip().map_err(cbor_error)?;
                    }
                }
            }
            6 => {
                let count = d
                    .array()
                    .map_err(cbor_error)?
                    .ok_or(FidoError::Protocol("indefinite CTAP array"))?;
                for _ in 0..count {
                    let number = d.u64().map_err(cbor_error)?;
                    info.protocols.push(u8::try_from(number).unwrap_or(u8::MAX));
                }
            }
            _ => d.skip().map_err(cbor_error)?,
        }
    }
    Ok(info)
}

/// How many wrong PINs the authenticator still accepts before it blocks.
pub fn retries<T: HidTransport>(
    hid: &mut CtapHid<T>,
    protocol: PinProtocol,
) -> Result<u8, FidoError> {
    let request = client_pin_request(protocol, GET_RETRIES, &[])?;
    let reply = command(hid, &request)?;
    let mut d = Decoder::new(&reply);
    for _ in 0..definite_map(&mut d)? {
        match d.u8().map_err(cbor_error)? {
            3 => {
                let retries = d.u64().map_err(cbor_error)?;
                return Ok(u8::try_from(retries).unwrap_or(u8::MAX));
            }
            _ => d.skip().map_err(cbor_error)?,
        }
    }
    Err(FidoError::Protocol("getRetries reply without pinRetries"))
}

/// Whether `pin` is within the lengths CTAP2 allows.
pub fn pin_length_ok(pin: &str) -> bool {
    pin.chars().count() >= MIN_PIN_CHARS && pin.len() <= MAX_PIN_BYTES
}

/// Exchange `pin` for a PIN token with `getPINToken`.
///
/// A wrong PIN fails with [`FidoError::PinInvalid`] and costs one of the
/// PIN's tries; [`FidoError::PinAuthBlocked`] means the authenticator wants
/// to be replugged before it takes another, and [`FidoError::PinBlocked`]
/// that it takes no more at all.
pub fn pin_token<T: HidTransport>(
    hid: &mut CtapHid<T>,
    protocol: PinProtocol,
    pin: &str,
) -> Result<Zeroizing<Vec<u8>>, FidoError> {
    if !pin_length_ok(pin) {
        return Err(FidoError::PinLength);
    }
    let device_key = key_agreement(hid, protocol)?;
    let platform = SecretKey::random(&mut OsRng);
    let secret = shared_secret(protocol, &platform, &device_key);
    let pin_hash = Zeroizing::new(Sha256::digest(pin.as_bytes()));
    let pin_hash_enc = protocol.encrypt(&secret, &pin_hash[..16])?;
    let request = pin_token_request(protocol, &platform.public_key(), &pin_hash_enc)?;
    let reply = command(hid, &request)?;
    let mut d = Decoder::new(&reply);
    let mut encrypted = None;
    for _ in 0..definite_map(&mut d)? {
        match d.u8().map_err(cbor_error)? {
            2 => encrypted = Some(d.bytes().map_err(cbor_error)?.to_vec()),
            _ => d.skip().map_err(cbor_error)?,
        }
    }
    let encrypted = encrypted.ok_or(FidoError::Protocol("getPINToken reply without a token"))?;
    protocol.decrypt(&secret, &encrypted)
}

/// The authenticator's key agreement public key, from `getKeyAgreement`.
fn key_agreement<T: HidTransport>(
    hid: &mut CtapHid<T>,
    protocol: PinProtocol,
) -> Result<PublicKey, FidoError> {
    let request = client_pin_request(protocol, GET_KEY_AGREEMENT, &[])?;
    let reply = command(hid, &request)?;
    let mut d = Decoder::new(&reply);
    for _ in 0..definite_map(&mut d)? {
        match d.u8().map_err(cbor_error)? {
            1 => return decode_cose_key(&mut d),
            _ => d.skip().map_err(cbor_error)?,
        }
    }
    Err(FidoError::Protocol("getKeyAgreement reply without a key"))
}

/// The protocol's shared secret between `platform` and `device`.
pub(crate) fn shared_secret(
    protocol: PinProtocol,
    platform: &SecretKey,
    device: &PublicKey,
) -> Zeroizing<Vec<u8>> {
    let shared = p256::ecdh::diffie_hellman(platform.to_nonzero_scalar(), device.as_affine());
    protocol.kdf(shared.raw_secret_bytes())
}

/// An `authenticatorClientPIN` request: `pinUvAuthProtocol` (1),
/// `subCommand` (2), then `extra`, already encoded entries with higher keys
/// counted as `extra.len()` pairs by the caller.
fn client_pin_request(
    protocol: PinProtocol,
    sub_command: u8,
    extra: &[u8],
) -> Result<Vec<u8>, FidoError> {
    client_pin_request_with(protocol, sub_command, 0, extra)
}

fn client_pin_request_with(
    protocol: PinProtocol,
    sub_command: u8,
    extra_pairs: u64,
    extra: &[u8],
) -> Result<Vec<u8>, FidoError> {
    let mut buffer = vec![AUTHENTICATOR_CLIENT_PIN];
    let mut e = Encoder::new(&mut buffer);
    e.map(2 + extra_pairs)
        .and_then(|e| e.u8(1))
        .and_then(|e| e.u8(protocol.number()))
        .and_then(|e| e.u8(2))
        .and_then(|e| e.u8(sub_command))
        .map_err(|e| FidoError::Cbor(e.to_string()))?;
    buffer.extend_from_slice(extra);
    Ok(buffer)
}

/// A `getPINToken` request: the host's key agreement key (3) and
/// `pinHashEnc` (6), after the protocol and subcommand.
fn pin_token_request(
    protocol: PinProtocol,
    platform: &PublicKey,
    pin_hash_enc: &[u8],
) -> Result<Vec<u8>, FidoError> {
    let mut extra = Vec::new();
    let mut e = Encoder::new(&mut extra);
    e.u8(3).map_err(|e| FidoError::Cbor(e.to_string()))?;
    encode_cose_key(&mut e, platform)?;
    e.u8(6)
        .and_then(|e| e.bytes(pin_hash_enc))
        .map_err(|e| FidoError::Cbor(e.to_string()))?;
    client_pin_request_with(protocol, GET_PIN_TOKEN, 2, &extra)
}

/// Encode `key` as a COSE_Key in CTAP2 canonical order: 1, 3, -1, -2, -3.
pub(crate) fn encode_cose_key<W: minicbor::encode::Write>(
    e: &mut Encoder<W>,
    key: &PublicKey,
) -> Result<(), FidoError>
where
    W::Error: std::fmt::Display,
{
    let point = key.to_encoded_point(false);
    let x = point.x().ok_or(FidoError::Protocol("identity point"))?;
    let y = point.y().ok_or(FidoError::Protocol("identity point"))?;
    e.map(5)
        .and_then(|e| e.i8(COSE_KTY))
        .and_then(|e| e.i8(KTY_EC2))
        .and_then(|e| e.i8(COSE_ALG))
        .and_then(|e| e.i8(ALG_ECDH_ES_HKDF_256))
        .and_then(|e| e.i8(COSE_CRV))
        .and_then(|e| e.i8(CRV_P256))
        .and_then(|e| e.i8(COSE_X))
        .and_then(|e| e.bytes(x))
        .and_then(|e| e.i8(COSE_Y))
        .and_then(|e| e.bytes(y))
        .map_err(|e| FidoError::Cbor(e.to_string()))?;
    Ok(())
}

/// Decode a P-256 COSE_Key, checking its key type and curve.
pub(crate) fn decode_cose_key(d: &mut Decoder) -> Result<PublicKey, FidoError> {
    let mut kty = None;
    let mut crv = None;
    let mut x = None;
    let mut y = None;
    for _ in 0..definite_map(d)? {
        match d.i8().map_err(cbor_error)? {
            COSE_KTY => kty = Some(d.i8().map_err(cbor_error)?),
            COSE_CRV => crv = Some(d.i8().map_err(cbor_error)?),
            COSE_X => x = Some(d.bytes().map_err(cbor_error)?.to_vec()),
            COSE_Y => y = Some(d.bytes().map_err(cbor_error)?.to_vec()),
            _ => d.skip().map_err(cbor_error)?,
        }
    }
    if kty != Some(KTY_EC2) || crv != Some(CRV_P256) {
        return Err(FidoError::Protocol("key agreement key is not P-256"));
    }
    let (Some(x), Some(y)) = (x, y) else {
        return Err(FidoError::Protocol("key agreement key without coordinates"));
    };
    if x.len() != 32 || y.len() != 32 {
        return Err(FidoError::Protocol("bad key agreement coordinate length"));
    }
    let point =
        EncodedPoint::from_affine_coordinates(x.as_slice().into(), y.as_slice().into(), false);
    Option::from(PublicKey::from_encoded_point(&point))
        .ok_or(FidoError::Protocol("key agreement key is not on the curve"))
}

/// Send one CTAP2 message and return the CBOR of a successful reply.
fn command<T: HidTransport>(hid: &mut CtapHid<T>, message: &[u8]) -> Result<Vec<u8>, FidoError> {
    let reply = hid.transact(CTAPHID_CBOR, message, &|| {})?;
    let (&status, cbor) = reply
        .split_first()
        .ok_or(FidoError::Protocol("empty CTAP reply"))?;
    if let Some(error) = ctap_status(status) {
        return Err(error);
    }
    Ok(cbor.to_vec())
}

fn definite_map(d: &mut Decoder) -> Result<u64, FidoError> {
    d.map()
        .map_err(cbor_error)?
        .ok_or(FidoError::Protocol("indefinite CTAP map"))
}

fn cbor_error(e: minicbor::decode::Error) -> FidoError {
    FidoError::Cbor(e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret_key(byte: u8) -> SecretKey {
        SecretKey::from_slice(&[byte; 32]).unwrap()
    }

    #[test]
    fn protocol_one_round_trips_with_a_zero_iv() {
        let key = [7u8; 32];
        let plaintext = [0x5Au8; 32];
        let ct = PinProtocol::V1.encrypt(&key, &plaintext).unwrap();
        assert_eq!(ct.len(), 32);
        // A zero IV makes encryption deterministic.
        assert_eq!(ct, PinProtocol::V1.encrypt(&key, &plaintext).unwrap());
        assert_eq!(
            PinProtocol::V1.decrypt(&key, &ct).unwrap().as_slice(),
            plaintext
        );
        assert_eq!(PinProtocol::V1.authenticate(&key, b"m").len(), 16);
    }

    #[test]
    fn protocol_two_prefixes_a_random_iv() {
        let key = [7u8; 64];
        let plaintext = [0x5Au8; 16];
        let a = PinProtocol::V2.encrypt(&key, &plaintext).unwrap();
        let b = PinProtocol::V2.encrypt(&key, &plaintext).unwrap();
        assert_eq!(a.len(), 32);
        assert_ne!(a, b);
        assert_eq!(
            PinProtocol::V2.decrypt(&key, &a).unwrap().as_slice(),
            plaintext
        );
        assert_eq!(PinProtocol::V2.authenticate(&key, b"m").len(), 32);
        // The shared secret authenticates with its HMAC half; a 32-byte
        // token is used whole.
        assert_eq!(
            PinProtocol::V2.authenticate(&key, b"m"),
            PinProtocol::V2.authenticate(&key[..32], b"m")
        );
    }

    #[test]
    fn partial_blocks_are_refused() {
        assert!(PinProtocol::V1.encrypt(&[0; 32], &[0; 15]).is_err());
        assert!(PinProtocol::V1.decrypt(&[0; 32], &[0; 17]).is_err());
        assert!(PinProtocol::V2.decrypt(&[0; 64], &[0; 16]).is_err());
        assert!(PinProtocol::V2.encrypt(&[0; 32], &[0; 16]).is_err());
    }

    /// pinHashEnc under protocol 1 for fixed keys and PIN "1234", checked
    /// against bytes computed independently with Python's `cryptography`:
    /// ECDH x-coordinate, SHA-256 of it, then AES-256-CBC with a zero IV
    /// over the first 16 bytes of SHA-256("1234").
    #[test]
    fn protocol_one_pin_hash_matches_a_fixed_vector() {
        let platform = secret_key(0x11);
        let device = secret_key(0x22).public_key();
        let secret = shared_secret(PinProtocol::V1, &platform, &device);
        // Both sides agree on the secret.
        assert_eq!(
            secret,
            shared_secret(PinProtocol::V1, &secret_key(0x22), &platform.public_key())
        );
        let pin_hash = Sha256::digest(b"1234");
        let enc = PinProtocol::V1.encrypt(&secret, &pin_hash[..16]).unwrap();
        assert_eq!(hex::encode(&secret), FIXED_V1_SECRET);
        assert_eq!(hex::encode(enc), FIXED_V1_PIN_HASH_ENC);
    }

    /// Protocol 2's HKDF keys for the same fixed agreement.
    #[test]
    fn protocol_two_kdf_matches_a_fixed_vector() {
        let secret = shared_secret(
            PinProtocol::V2,
            &secret_key(0x11),
            &secret_key(0x22).public_key(),
        );
        assert_eq!(hex::encode(&secret), FIXED_V2_SECRET);
        let enc = PinProtocol::V2
            .encrypt_with_iv(&secret, &[0x33; 16], &Sha256::digest(b"1234")[..16])
            .unwrap();
        assert_eq!(hex::encode(enc), FIXED_V2_PIN_HASH_ENC);
    }

    const FIXED_V1_SECRET: &str =
        "98f5bf15dbc72627acd9a8ab61ce21349ea3496d79136adf08ad381cc9c0fa25";
    const FIXED_V1_PIN_HASH_ENC: &str = "cd782dd78eb3517e6279ff687e577f00";
    const FIXED_V2_SECRET: &str = "abc3809533cb07b6ae481ea05b28ac708ffed9777147a09aabc8ab58e167ba0e\
                                   aecad75245932defecf4cd0d93420fcd05d99403d09a49655fed76fa64c2cf82";
    const FIXED_V2_PIN_HASH_ENC: &str =
        "33333333333333333333333333333333c606ac6f4acdbfa892f8587e28373e24";

    #[test]
    fn cose_key_round_trips_in_canonical_order() {
        let key = secret_key(0x11).public_key();
        let mut buffer = Vec::new();
        encode_cose_key(&mut Encoder::new(&mut buffer), &key).unwrap();
        // map(5), 1: 2, 3: -25, -1: 1, -2: bstr(32), ...
        assert_eq!(
            &buffer[..9],
            &[0xA5, 0x01, 0x02, 0x03, 0x38, 0x18, 0x20, 0x01, 0x21]
        );
        let decoded = decode_cose_key(&mut Decoder::new(&buffer)).unwrap();
        assert_eq!(decoded, key);
    }

    #[test]
    fn info_prefers_protocol_two() {
        let info = |protocols: Vec<u8>| Info {
            client_pin: Some(true),
            protocols,
        };
        assert_eq!(info(vec![]).protocol(), Some(PinProtocol::V1));
        assert_eq!(info(vec![1]).protocol(), Some(PinProtocol::V1));
        assert_eq!(info(vec![1, 2]).protocol(), Some(PinProtocol::V2));
        assert_eq!(info(vec![2, 1]).protocol(), Some(PinProtocol::V2));
        assert_eq!(info(vec![3]).protocol(), None);
    }

    #[test]
    fn info_reads_client_pin_and_protocols() {
        let mut cbor = Vec::new();
        let mut e = Encoder::new(&mut cbor);
        e.map(3)
            .and_then(|e| e.u8(1))
            .and_then(|e| e.array(1))
            .and_then(|e| e.str("FIDO_2_0"))
            .and_then(|e| e.u8(4))
            .and_then(|e| e.map(2))
            .and_then(|e| e.str("rk"))
            .and_then(|e| e.bool(true))
            .and_then(|e| e.str("clientPin"))
            .and_then(|e| e.bool(true))
            .and_then(|e| e.u8(6))
            .and_then(|e| e.array(1))
            .and_then(|e| e.u8(1))
            .unwrap();
        let info = parse_info(&cbor).unwrap();
        assert_eq!(info.client_pin, Some(true));
        assert_eq!(info.protocols, vec![1]);
        assert_eq!(parse_info(&[0xA0]).unwrap(), Info::default());
    }

    #[test]
    fn pin_lengths_follow_ctap2() {
        assert!(!pin_length_ok("123"));
        assert!(pin_length_ok("1234"));
        // Four code points, though more than four bytes.
        assert!(pin_length_ok("ééé1"));
        assert!(pin_length_ok(&"x".repeat(63)));
        assert!(!pin_length_ok(&"x".repeat(64)));
    }
}
