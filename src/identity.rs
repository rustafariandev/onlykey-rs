//! Identity strings and key derivation input.
//!
//! An identity is `[user@]host`. Only those two parts feed key derivation: the
//! device hashes the ASCII-transliterated `user@host` (or bare `host`) and
//! derives the key from that hash. A `scheme://` prefix, `:port` and `/path`
//! are accepted for convenience and ignored, matching the Python agent.

use sha2::{Digest, Sha256};
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

    /// Comment placed on the public key line, e.g. `<ssh://user@host|ed25519>`.
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
