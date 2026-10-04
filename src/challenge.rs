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
        printable(&format!(
            "OnlyKey: enter {a} {b} {c} to sign as {}{slot}{subject}, or press any button if challenge mode is off",
            self.identity
        ))
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
        printable(&format!(
            "Security key: touch it to sign as {}{subject}",
            self.identity
        ))
    }
}

/// One use of a key that the `ssh-add -c` confirm constraint asks the user
/// to allow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfirmRequest {
    /// Comment of the key being used, e.g. `ferris@example.com`.
    pub identity: String,
    /// The key's SHA-256 fingerprint, as `SHA256:…`.
    pub fingerprint: String,
    /// What is being signed, if the request could be summarised.
    pub subject: Option<String>,
}

impl ConfirmRequest {
    /// One-line human-readable prompt.
    pub fn message(&self) -> String {
        let subject = self
            .subject
            .as_deref()
            .map(|s| format!(" ({s})"))
            .unwrap_or_default();
        printable(&format!(
            "Allow use of key {}{subject}? Key fingerprint {}. (yes/no)",
            self.identity, self.fingerprint
        ))
    }
}

/// Something a FIDO security key needs its PIN for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinRequest {
    /// What the PIN is for, completing "Security key PIN to …", e.g.
    /// `sign as ferris@example.com`.
    pub action: String,
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
        printable(&format!(
            "{problem}Security key PIN to {}{subject}{retries}:",
            self.action
        ))
    }
}

/// `text` with control characters and bidirectional overrides escaped, so a
/// prompt stays one line that says what it seems to. Key comments and the
/// signed data's description come from clients, which could otherwise move
/// the cursor, rewrite the prompt or send terminal escape sequences.
fn printable(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        let reorders = matches!(
            c,
            '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'
        );
        if c.is_control() || reorders || c == '\u{2028}' || c == '\u{2029}' {
            out.extend(c.escape_unicode());
        } else {
            out.push(c);
        }
    }
    out
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

/// The controlling terminal, opened for reading and writing, while this
/// process is in its foreground process group. A background agent
/// (`okagent serve &`, or one under `okagent shell`) shares the terminal with
/// the user's shell: reading it would stop the agent with SIGTTIN, or take a
/// line the user typed for another program as the answer.
fn foreground_tty() -> Option<std::fs::File> {
    let tty = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .ok()?;
    let foreground = nix::unistd::tcgetpgrp(&tty).ok()?;
    (foreground == nix::unistd::getpgrp()).then_some(tty)
}

impl PinPrompt for TtyPin {
    fn available(&self) -> bool {
        foreground_tty().is_some()
    }

    fn pin(&self, request: &PinRequest) -> PinAnswer {
        use nix::sys::termios::{LocalFlags, SetArg, tcgetattr, tcsetattr};

        let Some(mut tty) = foreground_tty() else {
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
        match read_secret_line(&reader) {
            // End of input (Ctrl-D) cancels.
            Ok(None) => PinAnswer::Cancelled,
            Ok(Some(line)) => answer(&line),
            Err(_) => PinAnswer::Unavailable,
        }
    }
}

/// The longest line [`read_secret_line`] takes; CTAP2 PINs are at most 63
/// bytes.
const MAX_SECRET_LINE: usize = 256;

/// Read one line a byte at a time into a buffer that never grows, so the
/// returned, wiped one is the only copy: a `BufReader` would keep the PIN in
/// its own buffer, and a growing `String` in each one it outgrew. `None` at
/// end of input.
fn read_secret_line(mut reader: impl std::io::Read) -> std::io::Result<Option<Zeroizing<String>>> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_SECRET_LINE));
    let mut byte = Zeroizing::new([0u8; 1]);
    loop {
        if reader.read(&mut *byte)? == 0 {
            if bytes.is_empty() {
                return Ok(None);
            }
            break;
        }
        if byte[0] == b'\n' {
            break;
        }
        if bytes.len() == MAX_SECRET_LINE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "line too long",
            ));
        }
        bytes.push(byte[0]);
    }
    match String::from_utf8(std::mem::take(&mut *bytes)) {
        Ok(text) => Ok(Some(Zeroizing::new(text))),
        Err(e) => {
            drop(Zeroizing::new(e.into_bytes()));
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "not UTF-8",
            ))
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

    /// Ask the user to allow one use of a key added with `ssh-add -c`.
    /// `Some(true)` allows, `Some(false)` refuses, and `None` means this sink
    /// cannot ask (no terminal, no askpass program), so a later sink may.
    /// The default is `None`, which the agent treats as a refusal rather than
    /// weakening the constraint.
    fn confirm(&self, _request: &ConfirmRequest) -> Option<bool> {
        None
    }
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

    fn confirm(&self, request: &ConfirmRequest) -> Option<bool> {
        use nix::sys::termios::{FlushArg, tcflush};

        let mut tty = foreground_tty()?;
        let reader = tty.try_clone().ok()?;
        // Drop typeahead, so only an answer typed after the prompt counts.
        tcflush(&tty, FlushArg::TCIFLUSH).ok()?;
        if write!(tty, "{} ", request.message()).is_err() {
            return None;
        }
        let mut line = String::new();
        match BufReader::new(&reader).read_line(&mut line) {
            Ok(0) | Err(_) => None,
            Ok(_) => Some(matches!(
                line.trim().to_ascii_lowercase().as_str(),
                "yes" | "y"
            )),
        }
    }
}

/// Asks for confirmation through an askpass program, as `ssh` does when the
/// agent requires it: the prompt is the program's only argument,
/// `SSH_ASKPASS_PROMPT` is `confirm`, and a zero exit with a `yes` answer
/// allows the signature. `None` means the program could not be run.
#[derive(Debug, Clone)]
pub struct AskpassConfirm {
    program: String,
}

impl AskpassConfirm {
    pub fn new(program: impl Into<String>) -> Self {
        AskpassConfirm {
            program: program.into(),
        }
    }
}

impl ChallengeSink for AskpassConfirm {
    fn present(&self, _challenge: &Challenge) {}

    fn confirm(&self, request: &ConfirmRequest) -> Option<bool> {
        let output = Command::new(&self.program)
            .arg(request.message())
            .env("SSH_ASKPASS_PROMPT", "confirm")
            .stdin(Stdio::null())
            .stderr(Stdio::inherit())
            .output()
            .ok()?;
        if !output.status.success() {
            return Some(false);
        }
        let text = String::from_utf8_lossy(&output.stdout);
        Some(matches!(
            text.trim().to_ascii_lowercase().as_str(),
            "yes" | "y"
        ))
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

    fn confirm(&self, request: &ConfirmRequest) -> Option<bool> {
        // The first sink that can answer decides; the rest are not asked.
        self.0.iter().find_map(|sink| sink.confirm(request))
    }
}

/// Records challenges and touch requests instead of showing them; for tests.
/// The third field holds the answers a confirmation would get, `true` for
/// yes; when it runs out, confirmation is refused as by the trait default.
#[derive(Debug, Default)]
pub struct RecordingSink(
    pub std::sync::Mutex<Vec<Challenge>>,
    pub std::sync::Mutex<Vec<TouchRequest>>,
    pub std::sync::Mutex<VecDeque<bool>>,
);

impl ChallengeSink for RecordingSink {
    fn present(&self, challenge: &Challenge) {
        self.0.lock().unwrap().push(challenge.clone());
    }

    fn present_touch(&self, request: &TouchRequest) {
        self.1.lock().unwrap().push(request.clone());
    }

    fn confirm(&self, _request: &ConfirmRequest) -> Option<bool> {
        self.2.lock().unwrap().pop_front()
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
    fn secret_lines_are_read_up_to_the_newline() {
        let mut input: &[u8] = b"1234\r\nrest";
        assert_eq!(
            read_secret_line(&mut input).unwrap().unwrap().as_str(),
            "1234\r"
        );
        assert_eq!(input, b"rest", "nothing past the line is consumed");
        assert!(read_secret_line(&b""[..]).unwrap().is_none());
        assert_eq!(
            read_secret_line(&b"12"[..]).unwrap().unwrap().as_str(),
            "12"
        );
        assert!(read_secret_line(&[b'1'; MAX_SECRET_LINE + 1][..]).is_err());
        assert!(read_secret_line(&b"\xff\n"[..]).is_err());
    }

    #[test]
    fn messages_escape_control_and_bidi_characters() {
        let r = ConfirmRequest {
            identity: "a\u{202e}b".into(),
            fingerprint: "SHA256:x".into(),
            subject: Some("ssh\r\x1b[2KAllow harmless\n\u{9b}".into()),
        };
        let m = r.message();
        assert!(!m.chars().any(|c| c.is_control()), "{m:?}");
        assert!(!m.contains('\u{202e}'), "{m:?}");
        assert!(m.contains(r"a\u{202e}b"), "{m:?}");
        assert!(
            m.contains(r"ssh\u{d}\u{1b}[2KAllow harmless\u{a}\u{9b}"),
            "{m:?}"
        );
        assert!(m.contains("Key fingerprint SHA256:x."), "{m:?}");
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
    fn pin_message_mentions_problem_action_subject_and_retries() {
        let r = PinRequest {
            action: "sign as ferris@example.com".into(),
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
            action: "sign as ferris@example.com".into(),
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

    fn confirm_request() -> ConfirmRequest {
        ConfirmRequest {
            identity: "ferris@example.com".into(),
            fingerprint: "SHA256:abc".into(),
            subject: Some("ssh-connection login as \"ferris\"".into()),
        }
    }

    #[test]
    fn askpass_confirms_on_yes_and_reads_the_prompt() {
        let dir = tempfile::tempdir().unwrap();
        // The prompt arrives as the only argument with the confirm env var.
        let yes = askpass(
            dir.path(),
            r#"[ "$SSH_ASKPASS_PROMPT" = confirm ] && case "$1" in *ferris*) echo yes;; esac"#,
        );
        assert_eq!(
            AskpassConfirm::new(yes).confirm(&confirm_request()),
            Some(true)
        );
        assert_eq!(
            AskpassConfirm::new(askpass(dir.path(), "echo no")).confirm(&confirm_request()),
            Some(false)
        );
        assert_eq!(
            AskpassConfirm::new(askpass(dir.path(), "exit 1")).confirm(&confirm_request()),
            Some(false)
        );
        let missing = AskpassConfirm::new(dir.path().join("missing").to_str().unwrap());
        assert_eq!(missing.confirm(&confirm_request()), None);

        // MultiSink skips sinks that cannot answer and takes the first answer.
        let multi = MultiSink(vec![
            Box::new(missing),
            Box::new(AskpassConfirm::new(askpass(dir.path(), "echo yes"))),
        ]);
        assert_eq!(multi.confirm(&confirm_request()), Some(true));
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
