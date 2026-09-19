//! Presenting the 3-digit button challenge to the user.
//!
//! The agent may run without a controlling terminal (daemon mode, agent
//! forwarding), so the prompt is abstracted behind [`ChallengeSink`].

use crate::identity::KeySource;
use std::fs::OpenOptions;
use std::io::Write;
use std::process::Command;

/// One signing request that needs the user's confirmation on the device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    pub digits: [u8; 3],
    /// Identity whose key is being used, e.g. `james@example.com`.
    pub identity: String,
    /// Whether the key is derived from the identity or stored in a slot.
    pub source: KeySource,
    /// What is being signed, if the request could be summarised.
    pub subject: Option<String>,
}

impl Challenge {
    /// One-line human-readable prompt.
    pub fn message(&self) -> String {
        let [a, b, c] = self.digits;
        let slot = match self.source {
            KeySource::Derived => String::new(),
            KeySource::Stored(slot) => format!(" with stored key {slot}"),
        };
        let subject = self
            .subject
            .as_deref()
            .map(|s| format!(" ({s})"))
            .unwrap_or_default();
        format!(
            "OnlyKey: enter {a} {b} {c} to sign as {}{slot}{subject}, or press any button if challenge mode is off",
            self.identity
        )
    }
}

/// Somewhere a challenge can be shown.
pub trait ChallengeSink: Send + Sync {
    fn present(&self, challenge: &Challenge);
}

/// Writes the prompt to the controlling terminal, or stderr if there is none.
#[derive(Debug, Default)]
pub struct TtyPrompt;

impl ChallengeSink for TtyPrompt {
    fn present(&self, challenge: &Challenge) {
        let line = format!("{}\n", challenge.message());
        let written = OpenOptions::new()
            .write(true)
            .open("/dev/tty")
            .and_then(|mut tty| tty.write_all(line.as_bytes()));
        if written.is_err() {
            let _ = std::io::stderr().write_all(line.as_bytes());
        }
    }
}

/// Runs an external command with the prompt as its last argument, e.g.
/// `notify-send OnlyKey`. Environment variables `OKAGENT_DIGITS` and
/// `OKAGENT_IDENTITY` carry the parts separately, and `OKAGENT_SLOT` names
/// the slot (`ECC3`) when a stored key is used.
#[derive(Debug, Clone)]
pub struct CommandNotifier {
    program: String,
    args: Vec<String>,
}

impl CommandNotifier {
    /// Parse a command line split on whitespace; the first word is the program.
    pub fn parse(command: &str) -> Option<Self> {
        let mut words = command.split_whitespace().map(str::to_owned);
        let program = words.next()?;
        Some(CommandNotifier {
            program,
            args: words.collect(),
        })
    }
}

impl ChallengeSink for CommandNotifier {
    fn present(&self, challenge: &Challenge) {
        let [a, b, c] = challenge.digits;
        let mut command = Command::new(&self.program);
        command
            .args(&self.args)
            .arg(challenge.message())
            .env("OKAGENT_DIGITS", format!("{a} {b} {c}"))
            .env("OKAGENT_IDENTITY", &challenge.identity);
        if let KeySource::Stored(slot) = challenge.source {
            command.env("OKAGENT_SLOT", slot.to_string());
        }
        let result = command.spawn();
        match result {
            Ok(mut child) => {
                std::thread::spawn(move || {
                    let _ = child.wait();
                });
            }
            Err(e) => tracing::warn!(program = %self.program, error = %e, "notify command failed"),
        }
    }
}

/// Fans one challenge out to several sinks.
#[derive(Default)]
pub struct MultiSink(pub Vec<Box<dyn ChallengeSink>>);

impl ChallengeSink for MultiSink {
    fn present(&self, challenge: &Challenge) {
        for sink in &self.0 {
            sink.present(challenge);
        }
    }
}

/// Records challenges instead of showing them; for tests.
#[derive(Debug, Default)]
pub struct RecordingSink(pub std::sync::Mutex<Vec<Challenge>>);

impl ChallengeSink for RecordingSink {
    fn present(&self, challenge: &Challenge) {
        self.0.lock().unwrap().push(challenge.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_mentions_digits_identity_and_subject() {
        let c = Challenge {
            digits: [3, 1, 5],
            identity: "james@example.com".into(),
            source: KeySource::Derived,
            subject: Some("ssh login to host".into()),
        };
        let m = c.message();
        assert!(m.contains("3 1 5"));
        assert!(m.contains("james@example.com"));
        assert!(m.contains("(ssh login to host)"));
        assert!(!m.contains("stored key"));
        let stored = Challenge {
            source: KeySource::Stored("ECC3".parse().unwrap()),
            ..c
        };
        assert!(
            stored
                .message()
                .contains("sign as james@example.com with stored key ECC3 (ssh login to host)")
        );
    }

    #[test]
    fn command_notifier_parses_words() {
        let n = CommandNotifier::parse("notify-send -u critical OnlyKey").unwrap();
        assert_eq!(n.program, "notify-send");
        assert_eq!(n.args, vec!["-u", "critical", "OnlyKey"]);
        assert!(CommandNotifier::parse("   ").is_none());
    }
}
