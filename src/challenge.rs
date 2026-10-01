//! Presenting the 3-digit button challenge to the user, the request to
//! touch a FIDO security key, and asking for a security key's PIN.
//!
//! The agent may run without a controlling terminal (daemon mode, agent
//! forwarding), so the prompt is abstracted behind [`ChallengeSink`], and
//! PIN entry behind [`PinPrompt`].

use crate::identity::KeySource;
use std::collections::VecDeque;
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::sync::Mutex;
use zeroize::Zeroizing;

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

/// A signature with a FIDO security key that needs the key's PIN.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinRequest {
    /// Comment of the key being used, e.g. `ferris@example.com`.
    pub identity: String,
    /// What is being signed, if the request could be summarised.
    pub subject: Option<String>,
    /// PIN tries left before the security key blocks, if it said.
    pub retries: Option<u8>,
    /// Why the PIN is asked for again, e.g. "Wrong PIN".
    pub problem: Option<String>,
}

impl PinRequest {
    /// One-line human-readable prompt.
    pub fn message(&self) -> String {
        let problem = self
            .problem
            .as_deref()
            .map(|p| format!("{p}. "))
            .unwrap_or_default();
        let subject = self
            .subject
            .as_deref()
            .map(|s| format!(" ({s})"))
            .unwrap_or_default();
        let retries = match self.retries {
            Some(1) => ", 1 try left".to_owned(),
            Some(n) => format!(", {n} tries left"),
            None => String::new(),
        };
        format!(
            "{problem}Security key PIN to sign as {}{subject}{retries}:",
            self.identity
        )
    }
}

/// What a [`PinPrompt`] got from the user.
pub enum PinAnswer {
    Pin(Zeroizing<String>),
    /// The user declined to enter one.
    Cancelled,
    /// The prompt could not be shown (no askpass program, no terminal).
    Unavailable,
}

impl std::fmt::Debug for PinAnswer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PinAnswer::Pin(_) => f.write_str("Pin(..)"),
            PinAnswer::Cancelled => f.write_str("Cancelled"),
            PinAnswer::Unavailable => f.write_str("Unavailable"),
        }
    }
}

/// Somewhere a security key's PIN can be asked for.
pub trait PinPrompt: Send + Sync {
    fn pin(&self, request: &PinRequest) -> PinAnswer;

    /// Whether the prompt could be shown now, checked before a device is
    /// opened so a key that needs a PIN is refused without touching it. A
    /// prompt that passes may still turn out [`PinAnswer::Unavailable`].
    fn available(&self) -> bool {
        true
    }
}

/// Runs an askpass program, as `ssh` does with `SSH_ASKPASS`: the prompt is
/// its only argument and the PIN is what it prints. A non-zero exit or empty
/// output means the user cancelled.
#[derive(Debug, Clone)]
pub struct AskpassPin {
    program: String,
}

impl AskpassPin {
    pub fn new(program: impl Into<String>) -> Self {
        AskpassPin {
            program: program.into(),
        }
    }
}

impl PinPrompt for AskpassPin {
    fn available(&self) -> bool {
        is_executable(&self.program)
    }

    fn pin(&self, request: &PinRequest) -> PinAnswer {
        let output = Command::new(&self.program)
            .arg(request.message())
            // Unset, it asks for a secret rather than a yes/no confirmation.
            .env_remove("SSH_ASKPASS_PROMPT")
            .stdin(Stdio::null())
            .stderr(Stdio::inherit())
            .output();
        let output = match output {
            Ok(output) => output,
            Err(e) => {
                tracing::warn!(program = %self.program, error = %e, "cannot run askpass");
                return PinAnswer::Unavailable;
            }
        };
        let stdout = Zeroizing::new(output.stdout);
        if !output.status.success() {
            return PinAnswer::Cancelled;
        }
        let Ok(text) = std::str::from_utf8(&stdout) else {
            tracing::warn!(program = %self.program, "askpass printed a PIN that is not UTF-8");
            return PinAnswer::Cancelled;
        };
        answer(text)
    }
}

/// Whether `program` names an executable file, directly when it contains a
/// slash and otherwise through `PATH`, as a shell would find it.
fn is_executable(program: &str) -> bool {
    use nix::unistd::{AccessFlags, access};
    use std::path::Path;
    let runnable = |path: &Path| path.is_file() && access(path, AccessFlags::X_OK).is_ok();
    if program.contains('/') {
        return runnable(Path::new(program));
    }
    std::env::var_os("PATH")
        .is_some_and(|paths| std::env::split_paths(&paths).any(|dir| runnable(&dir.join(program))))
}

/// The PIN in one line of input, without its line ending; empty means
/// cancelled.
fn answer(line: &str) -> PinAnswer {
    let pin = line.trim_end_matches(['\n', '\r']);
    if pin.is_empty() {
        PinAnswer::Cancelled
    } else {
        PinAnswer::Pin(Zeroizing::new(pin.to_owned()))
    }
}

/// Reads the PIN from the controlling terminal with echo off.
#[derive(Debug, Default)]
pub struct TtyPin;

impl PinPrompt for TtyPin {
    fn available(&self) -> bool {
        OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")
            .is_ok()
    }

    fn pin(&self, request: &PinRequest) -> PinAnswer {
        use nix::sys::termios::{LocalFlags, SetArg, tcgetattr, tcsetattr};

        let Ok(mut tty) = OpenOptions::new().read(true).write(true).open("/dev/tty") else {
            return PinAnswer::Unavailable;
        };
        let Ok(saved) = tcgetattr(&tty) else {
            return PinAnswer::Unavailable;
        };
        let mut quiet = saved.clone();
        quiet.local_flags.remove(LocalFlags::ECHO);
        // Still echo the newline, so the next output starts on its own line.
        quiet.local_flags.insert(LocalFlags::ECHONL);
        if tcsetattr(&tty, SetArg::TCSAFLUSH, &quiet).is_err() {
            return PinAnswer::Unavailable;
        }
        /// Puts the terminal back however the read ends.
        struct Restore<'a>(&'a std::fs::File, nix::sys::termios::Termios);
        impl Drop for Restore<'_> {
            fn drop(&mut self) {
                let _ = tcsetattr(self.0, SetArg::TCSAFLUSH, &self.1);
            }
        }
        let reader = match tty.try_clone() {
            Ok(reader) => reader,
            Err(_) => {
                let _ = tcsetattr(&tty, SetArg::TCSAFLUSH, &saved);
                return PinAnswer::Unavailable;
            }
        };
        let _restore = Restore(&reader, saved);
        if write!(tty, "{} ", request.message()).is_err() {
            return PinAnswer::Unavailable;
        }
        let mut line = Zeroizing::new(String::new());
        match BufReader::new(&reader).read_line(&mut line) {
            // End of input (Ctrl-D) cancels.
            Ok(0) => PinAnswer::Cancelled,
            Ok(_) => answer(&line),
            Err(_) => PinAnswer::Unavailable,
        }
    }
}

/// Tries several prompts in turn, moving on only while a prompt is
/// unavailable: a cancel is the user's answer and ends the search.
#[derive(Default)]
pub struct ChainPin(pub Vec<Box<dyn PinPrompt>>);

impl PinPrompt for ChainPin {
    fn available(&self) -> bool {
        self.0.iter().any(|prompt| prompt.available())
    }

    fn pin(&self, request: &PinRequest) -> PinAnswer {
        for prompt in &self.0 {
            match prompt.pin(request) {
                PinAnswer::Unavailable => continue,
                answer => return answer,
            }
        }
        PinAnswer::Unavailable
    }
}

/// Answers PIN requests from a script and records them; for tests. Once
/// the script runs out every request is cancelled.
#[derive(Debug, Default)]
pub struct RecordingPin {
    answers: Mutex<VecDeque<PinAnswer>>,
    pub requests: Mutex<Vec<PinRequest>>,
}

impl RecordingPin {
    /// Answer with each of `pins` in turn.
    pub fn new(pins: &[&str]) -> Self {
        RecordingPin {
            answers: Mutex::new(
                pins.iter()
                    .map(|p| PinAnswer::Pin(Zeroizing::new((*p).to_owned())))
                    .collect(),
            ),
            requests: Mutex::default(),
        }
    }

    /// Answer with each of `answers` in turn.
    pub fn answering(answers: Vec<PinAnswer>) -> Self {
        RecordingPin {
            answers: Mutex::new(answers.into()),
            requests: Mutex::default(),
        }
    }
}

impl PinPrompt for RecordingPin {
    fn pin(&self, request: &PinRequest) -> PinAnswer {
        self.requests.lock().unwrap().push(request.clone());
        self.answers
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(PinAnswer::Cancelled)
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
    fn pin_message_mentions_problem_identity_subject_and_retries() {
        let r = PinRequest {
            identity: "ferris@example.com".into(),
            subject: Some("ssh login to host".into()),
            retries: Some(7),
            problem: None,
        };
        assert_eq!(
            r.message(),
            "Security key PIN to sign as ferris@example.com (ssh login to host), 7 tries left:"
        );
        let again = PinRequest {
            retries: Some(1),
            problem: Some("Wrong PIN".into()),
            subject: None,
            ..r
        };
        assert_eq!(
            again.message(),
            "Wrong PIN. Security key PIN to sign as ferris@example.com, 1 try left:"
        );
    }

    fn request() -> PinRequest {
        PinRequest {
            identity: "ferris@example.com".into(),
            subject: None,
            retries: None,
            problem: None,
        }
    }

    /// A small askpass script, as `SSH_ASKPASS` would name.
    fn askpass(dir: &std::path::Path, body: &str) -> String {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join("askpass");
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        path.to_str().unwrap().to_owned()
    }

    #[test]
    fn askpass_reads_the_pin_and_treats_failure_as_cancel() {
        let dir = tempfile::tempdir().unwrap();
        // The prompt arrives as the only argument.
        let program = askpass(
            dir.path(),
            r#"[ "$#" = 1 ] && case "$1" in *ferris*) echo 1234;; esac"#,
        );
        match AskpassPin::new(program).pin(&request()) {
            PinAnswer::Pin(pin) => assert_eq!(pin.as_str(), "1234"),
            other => panic!("unexpected answer {other:?}"),
        }
        let program = askpass(dir.path(), "exit 1");
        assert!(matches!(
            AskpassPin::new(program).pin(&request()),
            PinAnswer::Cancelled
        ));
        let program = askpass(dir.path(), "echo");
        assert!(matches!(
            AskpassPin::new(program).pin(&request()),
            PinAnswer::Cancelled
        ));
        let missing = AskpassPin::new(dir.path().join("missing").to_str().unwrap());
        assert!(!missing.available());
        assert!(matches!(missing.pin(&request()), PinAnswer::Unavailable));
    }

    #[test]
    fn askpass_is_available_only_when_executable() {
        let dir = tempfile::tempdir().unwrap();
        assert!(AskpassPin::new(askpass(dir.path(), "echo 1234")).available());
        assert!(AskpassPin::new("sh").available(), "found through PATH");
        assert!(!AskpassPin::new("okagent-no-such-askpass").available());
        let plain = dir.path().join("plain");
        std::fs::write(&plain, "echo 1234\n").unwrap();
        assert!(!AskpassPin::new(plain.to_str().unwrap()).available());
        assert!(!AskpassPin::new(dir.path().to_str().unwrap()).available());
    }

    #[test]
    fn chain_moves_on_only_while_unavailable() {
        let chain = ChainPin(vec![
            Box::new(RecordingPin::answering(vec![PinAnswer::Unavailable])),
            Box::new(RecordingPin::answering(vec![PinAnswer::Cancelled])),
            Box::new(RecordingPin::new(&["1234"])),
        ]);
        assert!(matches!(chain.pin(&request()), PinAnswer::Cancelled));
        assert!(matches!(
            ChainPin::default().pin(&request()),
            PinAnswer::Unavailable
        ));
        assert!(!ChainPin::default().available());
        assert!(!ChainPin(vec![Box::new(AskpassPin::new("okagent-no-such-askpass"))]).available());
    }

    #[test]
    fn command_notifier_parses_words() {
        let n = CommandNotifier::parse("notify-send -u critical OnlyKey").unwrap();
        assert_eq!(n.program, "notify-send");
        assert_eq!(n.args, vec!["-u", "critical", "OnlyKey"]);
        assert!(CommandNotifier::parse("   ").is_none());
    }
}
