//! Optional TOML configuration: `$XDG_CONFIG_HOME/okagent/config.toml`.
//!
//! ```toml
//! curve = "ed25519"            # default curve for identities below and on the command line
//! notify-command = "notify-send OnlyKey"
//! socket = "/run/user/1000/okagent/agent.sock"
//! log-file = "/home/ferris/.local/state/okagent.log"
//! fido-device = "/dev/hidraw5"  # optional, when several FIDO keys are attached
//!
//! [[identity]]
//! name = "ferris@example.com"
//!
//! [[identity]]
//! name = "git@github.com"
//! curve = "nistp256"
//!
//! [[identity]]
//! name = "ferris@legacy.example.com"
//! slot = "ECC3"                # key stored in the token by the OnlyKey app
//!
//! [[identity]]
//! name = "ferris@old.example.com"
//! slot = "RSA1"                # RSA keys take no curve
//! ```

use onlykey_agent::identity::{Curve, Identity, KeyKind, KeySpec, Slot};
use serde::Deserialize;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub identity: Vec<IdentityEntry>,
    pub curve: Option<Curve>,
    pub socket: Option<PathBuf>,
    pub notify_command: Option<String>,
    pub pubkey_file: Option<PathBuf>,
    pub log_file: Option<PathBuf>,
    /// FIDO security key path substring for `sk-` keys.
    pub fido_device: Option<PathBuf>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct IdentityEntry {
    pub name: String,
    pub curve: Option<Curve>,
    /// Stored slot (`ECC3`, `3` or `RSA1`); absent means a derived key.
    pub slot: Option<Slot>,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("cannot read {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("cannot parse {path}: {source}")]
    Parse {
        path: PathBuf,
        source: toml::de::Error,
    },
    #[error("bad identity in config: {0}")]
    Identity(#[from] onlykey_agent::identity::IdentityError),
    #[error("identity {name:?}: `curve` does not apply to RSA slot {slot}")]
    CurveForRsa { name: String, slot: Slot },
}

impl Config {
    /// Load `path`, or the default location when `None`. A missing default
    /// file yields an empty config; a missing explicit file is an error.
    pub fn load(path: Option<&Path>) -> Result<Self, ConfigError> {
        let (path, explicit) = match path {
            Some(p) => (p.to_owned(), true),
            None => match default_path() {
                Some(p) => (p, false),
                None => return Ok(Config::default()),
            },
        };
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(e) if !explicit && e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Config::default());
            }
            Err(source) => return Err(ConfigError::Read { path, source }),
        };
        Self::parse(&text).map_err(|source| ConfigError::Parse { path, source })
    }

    pub fn parse(text: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(text)
    }

    /// Entries from the config, applying `default_curve` where none is given.
    pub fn entries(&self, default_curve: Curve) -> Result<Vec<KeySpec>, ConfigError> {
        self.identity
            .iter()
            .map(|e| {
                let curve = e.curve.unwrap_or(default_curve);
                let kind = match (e.slot, e.curve) {
                    (None, _) => KeyKind::Derived(curve),
                    (Some(Slot::Ecc(slot)), _) => KeyKind::StoredEcc { slot, curve },
                    (Some(Slot::Rsa(slot)), None) => KeyKind::StoredRsa(slot),
                    (Some(slot @ Slot::Rsa(_)), Some(_)) => {
                        return Err(ConfigError::CurveForRsa {
                            name: e.name.clone(),
                            slot,
                        });
                    }
                };
                Ok(KeySpec {
                    identity: e.name.parse::<Identity>()?,
                    kind,
                })
            })
            .collect()
    }
}

/// `$XDG_CONFIG_HOME/okagent/config.toml`, falling back to `~/.config`.
pub fn default_path() -> Option<PathBuf> {
    let base = match std::env::var_os("XDG_CONFIG_HOME") {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir),
        _ => PathBuf::from(std::env::var_os("HOME")?).join(".config"),
    };
    Some(base.join("okagent").join("config.toml"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_config() {
        let cfg = Config::parse(
            r#"
            curve = "nistp256"
            notify-command = "notify-send OnlyKey"
            socket = "/tmp/x.sock"
            log-file = "/tmp/okagent.log"
            [[identity]]
            name = "ferris@example.com"
            [[identity]]
            name = "git@github.com"
            curve = "ed25519"
            [[identity]]
            name = "ferris@legacy.example.com"
            slot = "ECC3"
            [[identity]]
            name = "ferris@other.example.com"
            curve = "ed25519"
            slot = 4
            [[identity]]
            name = "ferris@old.example.com"
            slot = "RSA1"
            "#,
        )
        .unwrap();
        assert_eq!(cfg.curve, Some(Curve::NistP256));
        assert_eq!(cfg.notify_command.as_deref(), Some("notify-send OnlyKey"));
        assert_eq!(cfg.log_file.as_deref(), Some(Path::new("/tmp/okagent.log")));
        let entries = cfg.entries(cfg.curve.unwrap_or_default()).unwrap();
        assert_eq!(entries.len(), 5);
        assert_eq!(entries[0].kind, KeyKind::Derived(Curve::NistP256));
        assert_eq!(entries[1].kind, KeyKind::Derived(Curve::Ed25519));
        assert_eq!(entries[1].identity.to_string(), "git@github.com");
        assert_eq!(
            entries[2].kind,
            KeyKind::StoredEcc {
                slot: "ECC3".parse().unwrap(),
                curve: Curve::NistP256
            }
        );
        assert_eq!(
            entries[3].kind,
            KeyKind::StoredEcc {
                slot: "ECC4".parse().unwrap(),
                curve: Curve::Ed25519
            }
        );
        assert_eq!(entries[4].kind, KeyKind::StoredRsa("RSA1".parse().unwrap()));
        assert_eq!(
            entries[4].label(),
            "<ssh://ferris@old.example.com|rsa|RSA1>"
        );

        let cfg =
            Config::parse("[[identity]]\nname = \"a@b\"\nslot = \"RSA2\"\ncurve = \"ed25519\"")
                .unwrap();
        assert!(matches!(
            cfg.entries(Curve::Ed25519),
            Err(ConfigError::CurveForRsa { .. })
        ));
    }

    #[test]
    fn rejects_unknown_fields_and_bad_identities() {
        assert!(Config::parse("bogus = 1").is_err());
        let cfg = Config::parse("[[identity]]\nname = \"\"").unwrap();
        assert!(cfg.entries(Curve::Ed25519).is_err());
        for bad in ["\"ECC32\"", "\"RSA5\"", "0", "\"three\""] {
            let text = format!("[[identity]]\nname = \"a@b\"\nslot = {bad}");
            assert!(Config::parse(&text).is_err(), "{bad}");
        }
    }

    #[test]
    fn missing_default_file_is_empty_config() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = Config::load(Some(&dir.path().join("missing.toml")));
        assert!(cfg.is_err());
        let empty = Config::parse("").unwrap();
        assert!(empty.identity.is_empty());
    }
}
