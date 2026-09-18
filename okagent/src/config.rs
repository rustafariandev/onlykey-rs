//! Optional TOML configuration: `$XDG_CONFIG_HOME/okagent/config.toml`.
//!
//! ```toml
//! curve = "ed25519"            # default curve for identities below and on the command line
//! notify-command = "notify-send OnlyKey"
//! socket = "/run/user/1000/okagent/agent.sock"
//!
//! [[identity]]
//! name = "james@example.com"
//!
//! [[identity]]
//! name = "git@github.com"
//! curve = "nistp256"
//! ```

use onlykey_agent::agent::Entry;
use onlykey_agent::identity::{Curve, Identity};
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
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct IdentityEntry {
    pub name: String,
    pub curve: Option<Curve>,
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
    pub fn entries(&self, default_curve: Curve) -> Result<Vec<Entry>, ConfigError> {
        self.identity
            .iter()
            .map(|e| {
                Ok(Entry {
                    identity: e.name.parse::<Identity>()?,
                    curve: e.curve.unwrap_or(default_curve),
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
            [[identity]]
            name = "james@example.com"
            [[identity]]
            name = "git@github.com"
            curve = "ed25519"
            "#,
        )
        .unwrap();
        assert_eq!(cfg.curve, Some(Curve::NistP256));
        assert_eq!(cfg.notify_command.as_deref(), Some("notify-send OnlyKey"));
        let entries = cfg.entries(cfg.curve.unwrap_or_default()).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].curve, Curve::NistP256);
        assert_eq!(entries[1].curve, Curve::Ed25519);
        assert_eq!(entries[1].identity.to_string(), "git@github.com");
    }

    #[test]
    fn rejects_unknown_fields_and_bad_identities() {
        assert!(Config::parse("bogus = 1").is_err());
        let cfg = Config::parse("[[identity]]\nname = \"\"").unwrap();
        assert!(cfg.entries(Curve::Ed25519).is_err());
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
