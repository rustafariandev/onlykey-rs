//! Everything that names a key: identity strings, curves and key slots.
//!
//! An identity is `[user@]host`. Only those two parts feed key derivation: the
//! device hashes the ASCII-transliterated `user@host` (or bare `host`) and
//! derives the key from that hash. A `scheme://` prefix, `:port` and `/path`
//! are accepted for convenience and ignored, matching the Python agent.
//!
//! A key is either *derived* from that hash on every use, or *stored*: written
//! into one of the token's 16 ECC slots or 4 RSA slots with the OnlyKey app. A
//! [`KeySpec`] holds the identity and a [`KeyKind`] saying which.

use crate::protocol::DERIVED_KEY_SLOT;
use sha2::{Digest, Sha256};
use ssh_key::{Algorithm, EcdsaCurve, HashAlg};
use std::fmt;
use std::str::FromStr;
use thiserror::Error;

/// Key type to derive on the device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Curve {
    /// Ed25519 (`ssh-ed25519`), the default.
    #[default]
    #[cfg_attr(feature = "serde", serde(rename = "ed25519"))]
    Ed25519,
    /// NIST P-256 (`ecdsa-sha2-nistp256`).
    #[cfg_attr(
        feature = "serde",
        serde(rename = "nistp256", alias = "p256", alias = "nist256p1")
    )]
    NistP256,
}

impl Curve {
    /// Byte that prefixes the identity hash in an `OKGETPUBKEY` request.
    pub fn derivation_tag(self) -> u8 {
        match self {
            Curve::Ed25519 => 0x01,
            Curve::NistP256 => 0x02,
        }
    }

    /// Slot number used in an `OKSIGN` request for a derived key.
    pub fn sign_slot(self) -> u8 {
        match self {
            Curve::Ed25519 => 201,
            Curve::NistP256 => 202,
        }
    }

    /// Name the Python agent uses in `.pub` comments.
    pub fn legacy_name(self) -> &'static str {
        match self {
            Curve::Ed25519 => "ed25519",
            Curve::NistP256 => "nist256p1",
        }
    }
}

impl fmt::Display for Curve {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Curve::Ed25519 => "ed25519",
            Curve::NistP256 => "nistp256",
        })
    }
}

impl FromStr for Curve {
    type Err = IdentityError;

    /// Accepts `ed25519`, `nistp256`, `p256` or `nist256p1` (case-insensitive).
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "ed25519" => Ok(Curve::Ed25519),
            "nistp256" | "p256" | "nist256p1" => Ok(Curve::NistP256),
            _ => Err(IdentityError::UnknownCurve(s.to_owned())),
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum IdentityError {
    #[error("identity {0:?} has no host part")]
    MissingHost(String),
    #[error("unknown curve {0:?}; expected ed25519 or nistp256")]
    UnknownCurve(String),
    #[error("bad key slot {0:?}; expected ECC1 to ECC16 or RSA1 to RSA4")]
    BadSlot(String),
    #[error("the token cannot sign a {0} digest; use sha256 or sha512")]
    UnsupportedHash(HashAlg),
}

/// One of the token's ECC key slots, `ECC1` to `ECC16`, holding a key written
/// with the OnlyKey app. The firmware numbers them 101 to 116 on the wire and
/// reserves 132 for derived keys; it does not answer for anything in between.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EccSlot(u8);

impl EccSlot {
    pub const MIN: u8 = 1;
    pub const MAX: u8 = 16;

    /// Slot by its number in the OnlyKey app, 1 to 16.
    pub fn new(number: u8) -> Result<Self, IdentityError> {
        if (Self::MIN..=Self::MAX).contains(&number) {
            Ok(EccSlot(number))
        } else {
            Err(IdentityError::BadSlot(format!("ECC{number}")))
        }
    }

    /// Number as shown in the OnlyKey app, 1 to 16.
    pub fn number(self) -> u8 {
        self.0
    }

    /// Slot byte on the wire: ECC slots are numbered from 101.
    pub fn device_slot(self) -> u8 {
        100 + self.0
    }
}

impl fmt::Display for EccSlot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ECC{}", self.0)
    }
}

impl FromStr for EccSlot {
    type Err = IdentityError;

    /// Accepts `ECC3`, `ecc3` or a bare `3`.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let trimmed = s.trim();
        let digits = trimmed
            .get(..3)
            .filter(|p| p.eq_ignore_ascii_case("ecc"))
            .map_or(trimmed, |_| &trimmed[3..]);
        digits
            .parse::<u8>()
            .ok()
            .and_then(|n| Self::new(n).ok())
            .ok_or_else(|| IdentityError::BadSlot(s.to_owned()))
    }
}

/// One of the token's four RSA key slots, `RSA1` to `RSA4`. The wire slot
/// byte is the same number. The modulus size (2048 or 4096 bits) is whatever
/// was written into the slot; it is read back from the token, not declared.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RsaSlot(u8);

impl RsaSlot {
    pub const MIN: u8 = 1;
    pub const MAX: u8 = 4;

    /// Slot by its number in the OnlyKey app, 1 to 4.
    pub fn new(number: u8) -> Result<Self, IdentityError> {
        if (Self::MIN..=Self::MAX).contains(&number) {
            Ok(RsaSlot(number))
        } else {
            Err(IdentityError::BadSlot(format!("RSA{number}")))
        }
    }

    /// Number as shown in the OnlyKey app, 1 to 4.
    pub fn number(self) -> u8 {
        self.0
    }

    /// Slot byte on the wire.
    pub fn device_slot(self) -> u8 {
        self.0
    }
}

impl fmt::Display for RsaSlot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RSA{}", self.0)
    }
}

impl FromStr for RsaSlot {
    type Err = IdentityError;

    /// Accepts `RSA1` or `rsa1`.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let trimmed = s.trim();
        trimmed
            .get(..3)
            .filter(|p| p.eq_ignore_ascii_case("rsa"))
            .and_then(|_| trimmed[3..].parse::<u8>().ok())
            .and_then(|n| Self::new(n).ok())
            .ok_or_else(|| IdentityError::BadSlot(s.to_owned()))
    }
}

/// Any stored-key slot, as named on the command line or in a config file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Slot {
    Ecc(EccSlot),
    Rsa(RsaSlot),
}

impl Slot {
    /// Slot byte on the wire.
    pub fn device_slot(self) -> u8 {
        match self {
            Slot::Ecc(slot) => slot.device_slot(),
            Slot::Rsa(slot) => slot.device_slot(),
        }
    }
}

impl From<EccSlot> for Slot {
    fn from(slot: EccSlot) -> Self {
        Slot::Ecc(slot)
    }
}

impl From<RsaSlot> for Slot {
    fn from(slot: RsaSlot) -> Self {
        Slot::Rsa(slot)
    }
}

impl fmt::Display for Slot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Slot::Ecc(slot) => slot.fmt(f),
            Slot::Rsa(slot) => slot.fmt(f),
        }
    }
}

impl FromStr for Slot {
    type Err = IdentityError;

    /// Accepts `ECC3`, a bare `3` (an ECC slot) or `RSA1`, case-insensitively.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.trim()
            .get(..3)
            .is_some_and(|p| p.eq_ignore_ascii_case("rsa"))
        {
            s.parse().map(Slot::Rsa)
        } else {
            s.parse().map(Slot::Ecc)
        }
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for Slot {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Slot {
    /// Accepts `"ECC3"`, `"RSA1"` or the number `3` (an ECC slot).
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(serde::Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Number(u8),
            Text(String),
        }
        match Raw::deserialize(deserializer)? {
            Raw::Number(n) => EccSlot::new(n).map(Slot::Ecc),
            Raw::Text(s) => s.parse(),
        }
        .map_err(serde::de::Error::custom)
    }
}

/// Where the private key lives on the token; a summary of [`KeyKind`] for
/// prompts and logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum KeySource {
    /// Re-derived from the identity hash for every operation.
    #[default]
    Derived,
    /// Stored in a slot; the identity only names the key.
    Stored(Slot),
}

impl fmt::Display for KeySource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeySource::Derived => f.write_str("derived"),
            KeySource::Stored(slot) => slot.fmt(f),
        }
    }
}

/// What kind of key a [`KeySpec`] names. Only the combinations the token
/// supports can be expressed: a derived key has a curve, a stored ECC key has
/// a slot and the curve it was written with, and an RSA key has just a slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyKind {
    /// Derived from the identity hash on `Curve`.
    Derived(Curve),
    /// The key in an ECC slot; `curve` must match the type it was written with.
    StoredEcc { slot: EccSlot, curve: Curve },
    /// The key in an RSA slot.
    StoredRsa(RsaSlot),
}

impl KeyKind {
    /// The ECC curve, if this is not an RSA key.
    pub fn curve(&self) -> Option<Curve> {
        match *self {
            KeyKind::Derived(curve) | KeyKind::StoredEcc { curve, .. } => Some(curve),
            KeyKind::StoredRsa(_) => None,
        }
    }

    pub fn slot(&self) -> Option<Slot> {
        match *self {
            KeyKind::Derived(_) => None,
            KeyKind::StoredEcc { slot, .. } => Some(Slot::Ecc(slot)),
            KeyKind::StoredRsa(slot) => Some(Slot::Rsa(slot)),
        }
    }

    pub fn source(&self) -> KeySource {
        self.slot().map_or(KeySource::Derived, KeySource::Stored)
    }

    pub fn is_rsa(&self) -> bool {
        matches!(self, KeyKind::StoredRsa(_))
    }

    /// Name used in the public key comment: the Python agent's curve name,
    /// or `rsa`.
    pub fn legacy_name(&self) -> &'static str {
        match self.curve() {
            Some(curve) => curve.legacy_name(),
            None => "rsa",
        }
    }

    /// Algorithm of the public key, as [`ssh_key::PublicKey::algorithm`]
    /// reports it.
    pub fn public_algorithm(&self) -> Algorithm {
        match self.curve() {
            Some(Curve::Ed25519) => Algorithm::Ed25519,
            Some(Curve::NistP256) => Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP256,
            },
            None => Algorithm::Rsa { hash: None },
        }
    }

    /// Algorithm of a signature made with this key; `hash` only matters for
    /// RSA, where it picks `rsa-sha2-256` or `rsa-sha2-512`.
    pub fn signature_algorithm(&self, hash: HashAlg) -> Algorithm {
        match self.curve() {
            Some(_) => self.public_algorithm(),
            None => Algorithm::Rsa { hash: Some(hash) },
        }
    }
}

impl fmt::Display for KeyKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyKind::Derived(curve) => write!(f, "derived {curve}"),
            KeyKind::StoredEcc { slot, curve } => write!(f, "{curve} in {slot}"),
            KeyKind::StoredRsa(slot) => write!(f, "rsa in {slot}"),
        }
    }
}

/// Everything that picks one key: the identity and the [`KeyKind`]. This is
/// what the device operations and the agent work on.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KeySpec {
    pub identity: Identity,
    pub kind: KeyKind,
}

impl KeySpec {
    /// A key derived from `identity` on `curve`.
    pub fn derived(identity: Identity, curve: Curve) -> Self {
        KeySpec {
            identity,
            kind: KeyKind::Derived(curve),
        }
    }

    /// The key stored in ECC slot `slot`, named by `identity`. `curve` must
    /// match the key type the slot was written with.
    pub fn stored(identity: Identity, curve: Curve, slot: EccSlot) -> Self {
        KeySpec {
            identity,
            kind: KeyKind::StoredEcc { slot, curve },
        }
    }

    /// The key stored in RSA slot `slot`, named by `identity`.
    pub fn rsa(identity: Identity, slot: RsaSlot) -> Self {
        KeySpec {
            identity,
            kind: KeyKind::StoredRsa(slot),
        }
    }

    pub fn curve(&self) -> Option<Curve> {
        self.kind.curve()
    }

    pub fn slot(&self) -> Option<Slot> {
        self.kind.slot()
    }

    pub fn source(&self) -> KeySource {
        self.kind.source()
    }

    /// Slot byte of the `OKGETPUBKEY` request.
    pub fn pubkey_slot(&self) -> u8 {
        match self.kind {
            KeyKind::Derived(_) => DERIVED_KEY_SLOT,
            KeyKind::StoredEcc { slot, .. } => slot.device_slot(),
            KeyKind::StoredRsa(slot) => slot.device_slot(),
        }
    }

    /// Byte that prefixes the identity hash in the `OKGETPUBKEY` request:
    /// the curve tag, or `0x00` for an RSA slot, as the Python agent sends.
    pub fn pubkey_tag(&self) -> u8 {
        self.curve().map_or(0x00, Curve::derivation_tag)
    }

    /// Slot byte of the `OKSIGN` request: a per-curve pseudo-slot asks the
    /// firmware to derive the key, the real slot uses the stored one.
    pub fn sign_slot(&self) -> u8 {
        match self.kind {
            KeyKind::Derived(curve) => curve.sign_slot(),
            KeyKind::StoredEcc { slot, .. } => slot.device_slot(),
            KeyKind::StoredRsa(slot) => slot.device_slot(),
        }
    }

    /// The `OKSIGN` payload for `blob`, which the challenge digits are
    /// computed over. A derived key gets `blob || identity hash`, a stored
    /// ECC key `blob` alone, and an RSA key the `hash` of `blob`: the token
    /// only applies the PKCS#1 v1.5 padding and the private key.
    pub fn sign_message(&self, blob: &[u8], hash: HashAlg) -> Result<Vec<u8>, IdentityError> {
        Ok(match self.kind {
            KeyKind::Derived(_) => {
                let mut message = blob.to_vec();
                message.extend_from_slice(&self.identity.derivation_hash());
                message
            }
            KeyKind::StoredEcc { .. } => blob.to_vec(),
            KeyKind::StoredRsa(_) => match hash {
                HashAlg::Sha256 => Sha256::digest(blob).to_vec(),
                HashAlg::Sha512 => sha2::Sha512::digest(blob).to_vec(),
                other => return Err(IdentityError::UnsupportedHash(other)),
            },
        })
    }

    /// Longest `blob` that [`Self::sign_message`] keeps within the device
    /// buffer; `None` when the blob is hashed first and any length works.
    pub fn max_blob_len(&self) -> Option<usize> {
        match self.kind {
            KeyKind::Derived(_) => Some(crate::protocol::MAX_LARGE_PAYLOAD - 32),
            KeyKind::StoredEcc { .. } => Some(crate::protocol::MAX_LARGE_PAYLOAD),
            KeyKind::StoredRsa(_) => None,
        }
    }

    /// Comment placed on the public key line: `<ssh://user@host|curve>` for a
    /// derived key, as the Python agent writes it, with the slot appended as
    /// a third field for a stored key (`|ECC3` or `|RSA1`) so that keys for
    /// one identity never share a label.
    pub fn label(&self) -> String {
        match self.slot() {
            None => format!("<ssh://{}|{}>", self.identity, self.kind.legacy_name()),
            Some(slot) => format!(
                "<ssh://{}|{}|{slot}>",
                self.identity,
                self.kind.legacy_name()
            ),
        }
    }
}

/// The `[user@]host` pair that names a derived key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Identity {
    pub user: Option<String>,
    pub host: String,
}

impl Identity {
    pub fn new(user: Option<&str>, host: &str) -> Self {
        Identity {
            user: user.map(str::to_owned),
            host: host.to_owned(),
        }
    }

    /// The bytes the device hashes: ASCII transliteration of `user@host`.
    pub fn derivation_input(&self) -> String {
        let joined = match &self.user {
            Some(user) => format!("{user}@{}", self.host),
            None => self.host.clone(),
        };
        deunicode::deunicode(&joined)
    }

    /// True if transliteration changed the identity, which is worth a warning
    /// because different transliteration tables could derive different keys.
    pub fn is_transliterated(&self) -> bool {
        !self.to_string().is_ascii()
    }

    /// SHA-256 of [`Self::derivation_input`].
    pub fn derivation_hash(&self) -> [u8; 32] {
        Sha256::digest(self.derivation_input().as_bytes()).into()
    }

    /// Comment placed on the public key line, e.g. `<ssh://user@host|ed25519>`;
    /// see [`KeySpec::label`] for the general form.
    pub fn label(&self, curve: Curve) -> String {
        format!("<ssh://{self}|{}>", curve.legacy_name())
    }
}

impl fmt::Display for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(user) = &self.user {
            write!(f, "{user}@")?;
        }
        f.write_str(&self.host)
    }
}

impl FromStr for Identity {
    type Err = IdentityError;

    /// Parse `[scheme://][user@]host[:port][/path]`, keeping only user and host.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let rest = match s.find("://") {
            Some(i) => &s[i + 3..],
            None => s,
        };
        let rest = rest.split('/').next().unwrap_or("");
        let (user, host_port) = match rest.rfind('@') {
            Some(i) => (Some(&rest[..i]), &rest[i + 1..]),
            None => (None, rest),
        };
        let host = match host_port.rfind(':') {
            Some(i)
                if host_port[i + 1..]
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric()) =>
            {
                &host_port[..i]
            }
            _ => host_port,
        };
        if host.is_empty() {
            return Err(IdentityError::MissingHost(s.to_owned()));
        }
        Ok(Identity::new(user.filter(|u| !u.is_empty()), host))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_hashes_like_python() {
        let g: serde_json::Value =
            serde_json::from_str(include_str!("../tests/goldens.json")).unwrap();
        for case in g["identities"].as_array().unwrap() {
            let id: Identity = case["input"].as_str().unwrap().parse().unwrap();
            assert_eq!(id.user.as_deref(), case["user"].as_str(), "{case}");
            assert_eq!(id.host, case["host"].as_str().unwrap(), "{case}");
            assert_eq!(
                id.derivation_input(),
                case["derivation_input"].as_str().unwrap()
            );
            assert_eq!(
                hex::encode(id.derivation_hash()),
                case["hash_hex"].as_str().unwrap()
            );
        }
    }

    #[test]
    fn curve_parses_aliases() {
        assert_eq!("ed25519".parse::<Curve>().unwrap(), Curve::Ed25519);
        assert_eq!("NistP256".parse::<Curve>().unwrap(), Curve::NistP256);
        assert_eq!("p256".parse::<Curve>().unwrap(), Curve::NistP256);
        assert_eq!("nist256p1".parse::<Curve>().unwrap(), Curve::NistP256);
        assert!("secp256k1".parse::<Curve>().is_err());
    }

    #[test]
    fn ecc_slot_parses_and_maps_to_device_slot() {
        let slot: EccSlot = "ECC3".parse().unwrap();
        assert_eq!(slot.number(), 3);
        assert_eq!(slot.device_slot(), 103);
        assert_eq!(slot.to_string(), "ECC3");
        assert_eq!("ecc16".parse::<EccSlot>().unwrap().device_slot(), 116);
        assert_eq!("1".parse::<EccSlot>().unwrap().device_slot(), 101);
        for bad in ["ECC0", "ECC17", "ECC32", "ECC", "RSA1", "", "ECC 3", "300"] {
            assert!(
                matches!(bad.parse::<EccSlot>(), Err(IdentityError::BadSlot(_))),
                "{bad:?}"
            );
        }
        assert!(EccSlot::new(17).is_err());
    }

    #[test]
    fn rsa_slot_and_combined_slot_parse() {
        let slot: RsaSlot = "rsa2".parse().unwrap();
        assert_eq!(slot.number(), 2);
        assert_eq!(slot.device_slot(), 2);
        assert_eq!(slot.to_string(), "RSA2");
        for bad in ["RSA0", "RSA5", "RSA", "2", "ECC2"] {
            assert!(bad.parse::<RsaSlot>().is_err(), "{bad:?}");
        }
        assert_eq!(
            "RSA1".parse::<Slot>().unwrap(),
            Slot::Rsa(RsaSlot::new(1).unwrap())
        );
        assert_eq!(
            "ECC3".parse::<Slot>().unwrap(),
            Slot::Ecc(EccSlot::new(3).unwrap())
        );
        assert_eq!(
            "3".parse::<Slot>().unwrap(),
            Slot::Ecc(EccSlot::new(3).unwrap())
        );
        assert_eq!("RSA1".parse::<Slot>().unwrap().device_slot(), 1);
        assert_eq!("ECC3".parse::<Slot>().unwrap().device_slot(), 103);
        assert!("RSA9".parse::<Slot>().is_err());
        assert!("DSA1".parse::<Slot>().is_err());
    }

    #[test]
    fn key_spec_slots_and_messages() {
        let id: Identity = "james@example.com".parse().unwrap();
        let derived = KeySpec::derived(id.clone(), Curve::NistP256);
        assert_eq!(derived.pubkey_slot(), 132);
        assert_eq!(derived.pubkey_tag(), 0x02);
        assert_eq!(derived.sign_slot(), 202);
        assert_eq!(derived.slot(), None);
        let mut want = b"abc".to_vec();
        want.extend_from_slice(&id.derivation_hash());
        assert_eq!(derived.sign_message(b"abc", HashAlg::Sha512).unwrap(), want);
        assert_eq!(derived.max_blob_len(), Some(736));
        assert_eq!(derived.label(), "<ssh://james@example.com|nist256p1>");
        assert_eq!(derived.kind.to_string(), "derived nistp256");
        assert_eq!(
            derived.kind.signature_algorithm(HashAlg::Sha512),
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP256
            }
        );

        let stored = KeySpec::stored(id.clone(), Curve::Ed25519, EccSlot::new(3).unwrap());
        assert_eq!(stored.pubkey_slot(), 103);
        assert_eq!(stored.pubkey_tag(), 0x01);
        assert_eq!(stored.sign_slot(), 103);
        assert_eq!(stored.slot(), Some(Slot::Ecc(EccSlot::new(3).unwrap())));
        assert_eq!(
            stored.sign_message(b"abc", HashAlg::Sha256).unwrap(),
            b"abc"
        );
        assert_eq!(stored.max_blob_len(), Some(768));
        assert_eq!(stored.label(), "<ssh://james@example.com|ed25519|ECC3>");
        assert_eq!(stored.source().to_string(), "ECC3");
        assert_eq!(stored.kind.to_string(), "ed25519 in ECC3");
        assert_eq!(KeySource::Derived.to_string(), "derived");

        let rsa = KeySpec::rsa(id, RsaSlot::new(2).unwrap());
        assert_eq!(rsa.curve(), None);
        assert!(rsa.kind.is_rsa());
        assert_eq!(rsa.pubkey_slot(), 2);
        assert_eq!(rsa.pubkey_tag(), 0x00);
        assert_eq!(rsa.sign_slot(), 2);
        assert_eq!(
            rsa.sign_message(b"abc", HashAlg::Sha256).unwrap(),
            Sha256::digest(b"abc").to_vec()
        );
        assert_eq!(rsa.sign_message(b"abc", HashAlg::Sha512).unwrap().len(), 64);
        assert_eq!(rsa.max_blob_len(), None);
        assert_eq!(rsa.label(), "<ssh://james@example.com|rsa|RSA2>");
        assert_eq!(rsa.source().to_string(), "RSA2");
        assert_eq!(rsa.kind.to_string(), "rsa in RSA2");
        assert_eq!(rsa.kind.public_algorithm(), Algorithm::Rsa { hash: None });
        assert_eq!(
            rsa.kind.signature_algorithm(HashAlg::Sha512),
            Algorithm::Rsa {
                hash: Some(HashAlg::Sha512)
            }
        );
    }

    #[test]
    fn rejects_empty_host() {
        assert!("".parse::<Identity>().is_err());
        assert!("user@".parse::<Identity>().is_err());
        assert!("ssh://".parse::<Identity>().is_err());
    }

    #[test]
    fn label_matches_python_comment() {
        let id: Identity = "james@example.com".parse().unwrap();
        assert_eq!(
            id.label(Curve::Ed25519),
            "<ssh://james@example.com|ed25519>"
        );
        assert_eq!(
            id.label(Curve::NistP256),
            "<ssh://james@example.com|nist256p1>"
        );
        assert!(!id.is_transliterated());
        let id: Identity = "jämes@example.com".parse().unwrap();
        assert!(id.is_transliterated());
    }
}
