//! Presenting the 3-digit button challenge to the user, and the request to
//! touch a FIDO security key.
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
    /// Identity whose key is being used, e.g. `ferris@example.com`.
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

/// A signing request waiting for the user to touch a FIDO security key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TouchRequest {
    /// Comment of the key being used, e.g. `ferris@example.com`.
    pub identity: String,
    /// What is being signed, if the request could be summarised.
    pub subject: Option<String>,
}

impl TouchRequest {
    /// One-line human-readable prompt.
    pub fn message(&self) -> String {
        let subject = self
            .subject
            .as_deref()
            .map(|s| format!(" ({s})"))
            .unwrap_or_default();
        format!(
            "Security key: touch it to sign as {}{subject}",
            self.identity
        )
    }
}

/// Somewhere a challenge can be shown.
pub trait ChallengeSink: Send + Sync {
    fn present(&self, challenge: &Challenge);

    /// Tell the user a FIDO security key is waiting for a touch. The default
    /// does nothing, for sinks that only handle OnlyKey challenges.
    fn present_touch(&self, _request: &TouchRequest) {}
}

/// Writes the prompt to the controlling terminal, or stderr if there is none.
#[derive(Debug, Default)]
pub struct TtyPrompt;

impl ChallengeSink for TtyPrompt {
    fn present(&self, challenge: &Challenge) {
        write_tty(&challenge.message());
    }

    fn present_touch(&self, request: &TouchRequest) {
        write_tty(&request.message());
    }
}

/// Write one line to the controlling terminal, or stderr if there is none.
fn write_tty(message: &str) {
    let line = format!("{message}\n");
    let written = OpenOptions::new()
        .write(true)
        .open("/dev/tty")
        .and_then(|mut tty| tty.write_all(line.as_bytes()));
    if written.is_err() {
        let _ = std::io::stderr().write_all(line.as_bytes());
    }
}

/// Runs an external command with the prompt as its last argument, e.g.
/// `notify-send OnlyKey`. Environment variables `OKAGENT_DIGITS` and
/// `OKAGENT_IDENTITY` carry the parts separately, and `OKAGENT_SLOT` names
/// the slot (`ECC3`) when a stored key is used. A security-key touch request
/// sets `OKAGENT_TOUCH=1` and `OKAGENT_IDENTITY`, with no digits.
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
        self.spawn(command);
    }

    fn present_touch(&self, request: &TouchRequest) {
        let mut command = Command::new(&self.program);
        command
            .args(&self.args)
            .arg(request.message())
            .env("OKAGENT_TOUCH", "1")
            .env("OKAGENT_IDENTITY", &request.identity);
        self.spawn(command);
    }
}

impl CommandNotifier {
    /// Start `command` and reap it in the background.
    fn spawn(&self, mut command: Command) {
        match command.spawn() {
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

    fn present_touch(&self, request: &TouchRequest) {
        for sink in &self.0 {
            sink.present_touch(request);
        }
    }
}

/// Records challenges and touch requests instead of showing them; for tests.
#[derive(Debug, Default)]
pub struct RecordingSink(
    pub std::sync::Mutex<Vec<Challenge>>,
    pub std::sync::Mutex<Vec<TouchRequest>>,
);

impl ChallengeSink for RecordingSink {
    fn present(&self, challenge: &Challenge) {
        self.0.lock().unwrap().push(challenge.clone());
    }

    fn present_touch(&self, request: &TouchRequest) {
        self.1.lock().unwrap().push(request.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_mentions_digits_identity_and_subject() {
        let c = Challenge {
            digits: [3, 1, 5],
            identity: "ferris@example.com".into(),
            source: KeySource::Derived,
            subject: Some("ssh login to host".into()),
        };
        let m = c.message();
        assert!(m.contains("3 1 5"));
        assert!(m.contains("ferris@example.com"));
        assert!(m.contains("(ssh login to host)"));
        assert!(!m.contains("stored key"));
        let stored = Challenge {
            source: KeySource::Stored("ECC3".parse().unwrap()),
            ..c
        };
        assert!(
            stored
                .message()
                .contains("sign as ferris@example.com with stored key ECC3 (ssh login to host)")
        );
    }

    #[test]
    fn touch_message_mentions_identity_and_subject() {
        let r = TouchRequest {
            identity: "ferris@example.com".into(),
            subject: Some("ssh login to host".into()),
        };
        assert_eq!(
            r.message(),
            "Security key: touch it to sign as ferris@example.com (ssh login to host)"
        );
        let bare = TouchRequest { subject: None, ..r };
        assert_eq!(
            bare.message(),
            "Security key: touch it to sign as ferris@example.com"
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
