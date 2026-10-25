//! The terminal the user is sitting at: `/dev/tty` on Unix, the console
//! (`CONIN$` and `CONOUT$`) on Windows.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;
#[cfg(windows)]
use std::path::PathBuf;
use std::process::Command;

/// The user's terminal, split into its input and output.
pub(super) struct Tty {
    pub input: File,
    pub output: File,
}

/// Write one line to the terminal.
pub(super) fn write_line(line: &str) -> io::Result<()> {
    #[cfg(unix)]
    const OUTPUT: &str = "/dev/tty";
    #[cfg(windows)]
    const OUTPUT: &str = "CONOUT$";
    OpenOptions::new()
        .write(true)
        .open(OUTPUT)?
        .write_all(line.as_bytes())
}

/// The controlling terminal while this process is in its foreground process
/// group. A background agent (`okagent serve &`, or one under
/// `okagent shell`) shares the terminal with the user's shell: reading it
/// would stop the agent with SIGTTIN, or take a line the user typed for
/// another program as the answer.
#[cfg(unix)]
pub(super) fn foreground() -> Option<Tty> {
    let input = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .ok()?;
    let foreground = nix::unistd::tcgetpgrp(&input).ok()?;
    if foreground != nix::unistd::getpgrp() {
        return None;
    }
    let output = input.try_clone().ok()?;
    Some(Tty { input, output })
}

/// Set by [`give_up_console`].
#[cfg(windows)]
static CONSOLE_GIVEN_UP: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Never read the console again in this process, for when it is handed to
/// an interactive shell (`okagent shell`). Windows has no foreground
/// process group to tell the agent that the shell, or an ssh session it
/// runs, is reading the console too: a PIN read while ssh is in raw mode
/// would be split between the agent and the remote host. PINs and
/// confirmations then go to askpass, as they do under a Unix shell.
#[cfg(windows)]
pub fn give_up_console() {
    CONSOLE_GIVEN_UP.store(true, std::sync::atomic::Ordering::SeqCst);
}

/// The console this process is attached to, unless it gave it up with
/// [`give_up_console`]. An agent started with `serve --daemon` has no
/// console at all, so opening it fails.
#[cfg(windows)]
pub(super) fn foreground() -> Option<Tty> {
    if CONSOLE_GIVEN_UP.load(std::sync::atomic::Ordering::SeqCst) {
        return None;
    }
    // Write access too: changing the input mode and flushing it need it.
    let input = OpenOptions::new()
        .read(true)
        .write(true)
        .open("CONIN$")
        .ok()?;
    let output = OpenOptions::new().write(true).open("CONOUT$").ok()?;
    Some(Tty { input, output })
}

/// Turns echo back on when dropped.
pub(super) struct EchoOff<'a> {
    tty: &'a Tty,
    #[cfg(unix)]
    saved: nix::sys::termios::Termios,
    #[cfg(windows)]
    saved: windows_sys::Win32::System::Console::CONSOLE_MODE,
}

#[cfg(unix)]
impl Tty {
    /// Stop echoing input, dropping any typeahead.
    pub fn echo_off(&self) -> Option<EchoOff<'_>> {
        use nix::sys::termios::{LocalFlags, SetArg, tcgetattr, tcsetattr};
        let saved = tcgetattr(&self.input).ok()?;
        let mut quiet = saved.clone();
        quiet.local_flags.remove(LocalFlags::ECHO);
        // Still echo the newline, so the next output starts on its own line.
        quiet.local_flags.insert(LocalFlags::ECHONL);
        tcsetattr(&self.input, SetArg::TCSAFLUSH, &quiet).ok()?;
        Some(EchoOff { tty: self, saved })
    }

    /// Drop typeahead, so only an answer typed after the prompt counts.
    pub fn discard_input(&self) -> Option<()> {
        use nix::sys::termios::{FlushArg, tcflush};
        tcflush(&self.input, FlushArg::TCIFLUSH).ok()
    }
}

#[cfg(unix)]
impl Drop for EchoOff<'_> {
    fn drop(&mut self) {
        use nix::sys::termios::{SetArg, tcsetattr};
        let _ = tcsetattr(&self.tty.input, SetArg::TCSAFLUSH, &self.saved);
    }
}

#[cfg(windows)]
impl Tty {
    fn handle(&self) -> windows_sys::Win32::Foundation::HANDLE {
        use std::os::windows::io::AsRawHandle;
        self.input.as_raw_handle()
    }

    /// Stop echoing input, dropping any typeahead.
    pub fn echo_off(&self) -> Option<EchoOff<'_>> {
        use windows_sys::Win32::System::Console::{
            ENABLE_ECHO_INPUT, GetConsoleMode, SetConsoleMode,
        };
        let mut saved = 0;
        // SAFETY: the handle is the open console input; `saved` outlives the call.
        if unsafe { GetConsoleMode(self.handle(), &mut saved) } == 0 {
            return None;
        }
        self.discard_input()?;
        // SAFETY: as above.
        if unsafe { SetConsoleMode(self.handle(), saved & !ENABLE_ECHO_INPUT) } == 0 {
            return None;
        }
        Some(EchoOff { tty: self, saved })
    }

    /// Drop typeahead, so only an answer typed after the prompt counts.
    pub fn discard_input(&self) -> Option<()> {
        use windows_sys::Win32::System::Console::FlushConsoleInputBuffer;
        // SAFETY: the handle is the open console input.
        (unsafe { FlushConsoleInputBuffer(self.handle()) } != 0).then_some(())
    }
}

#[cfg(windows)]
impl Drop for EchoOff<'_> {
    fn drop(&mut self) {
        use windows_sys::Win32::System::Console::SetConsoleMode;
        // SAFETY: the handle is the open console input.
        unsafe { SetConsoleMode(self.tty.handle(), self.saved) };
        // The console echoed nothing, not even the Enter.
        let _ = (&self.tty.output).write_all(b"\r\n");
    }
}

/// Whether `program` names an executable file, directly when it contains a
/// slash and otherwise through `PATH`, as a shell would find it.
#[cfg(unix)]
pub(super) fn is_executable(program: &str) -> bool {
    use nix::unistd::{AccessFlags, access};
    let runnable = |path: &Path| path.is_file() && access(path, AccessFlags::X_OK).is_ok();
    if program.contains('/') {
        return runnable(Path::new(program));
    }
    std::env::var_os("PATH")
        .is_some_and(|paths| std::env::split_paths(&paths).any(|dir| runnable(&dir.join(program))))
}

/// Whether `program` names a file `CreateProcess` would run: directly when
/// it contains a path separator and otherwise through `PATH`, with each of
/// the `PATHEXT` extensions when it has none of its own.
#[cfg(windows)]
pub(super) fn is_executable(program: &str) -> bool {
    find_executable(program).is_some()
}

/// The file [`is_executable`] finds for `program`.
#[cfg(windows)]
fn find_executable(program: &str) -> Option<PathBuf> {
    let program = Path::new(program);
    let extensions: Vec<String> = if program.extension().is_some() {
        vec![String::new()]
    } else {
        std::env::var("PATHEXT")
            .unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".into())
            .split(';')
            .filter(|ext| !ext.is_empty())
            .map(str::to_owned)
            .collect()
    };
    let runnable = |path: &Path| {
        extensions.iter().find_map(|ext| {
            let mut candidate = path.as_os_str().to_owned();
            candidate.push(ext);
            let candidate = PathBuf::from(candidate);
            candidate.is_file().then_some(candidate)
        })
    };
    if program.components().count() > 1 || program.is_absolute() {
        return runnable(program);
    }
    let paths = std::env::var_os("PATH")?;
    std::env::split_paths(&paths).find_map(|dir| runnable(&dir.join(program)))
}

/// A command that runs `program` as [`is_executable`] finds it. On Windows
/// `Command` alone only adds `.exe`, so an askpass named without its `.cmd`
/// would be found and then fail to start.
pub(super) fn command(program: &str) -> Command {
    #[cfg(windows)]
    if let Some(path) = find_executable(program) {
        return Command::new(path);
    }
    Command::new(program)
}
