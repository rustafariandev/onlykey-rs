//! Command-line interface.

use crate::config::Config;
use anyhow::{Context, Result, anyhow, bail};
use clap::{Args, Parser, Subcommand};
use nix::unistd::{ForkResult, fork, setsid};
use onlykey_agent::agent::{self, Agent, Opener};
use onlykey_agent::challenge::{ChallengeSink, CommandNotifier, MultiSink, TtyPrompt};
use onlykey_agent::device::{OnlyKey, Timeouts};
use onlykey_agent::identity::{Curve, Identity, KeyKind, KeySpec, Slot};
use onlykey_agent::protocol::DeviceStatus;
use onlykey_agent::ssh_key::HashAlg;
use onlykey_agent::ssh_key::PublicKey;
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tracing_subscriber::EnvFilter;

/// SSH agent backed by an OnlyKey hardware token.
#[derive(Debug, Parser)]
#[command(name = "okagent", version, about)]
pub struct Cli {
    /// More log output (repeat for more).
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    pub verbose: u8,

    /// Append log output to this file instead of stderr.
    #[arg(long, global = true, value_name = "FILE")]
    pub log_file: Option<PathBuf>,

    /// Config file (default: $XDG_CONFIG_HOME/okagent/config.toml).
    #[arg(long, global = true, env = "OKAGENT_CONFIG")]
    pub config: Option<PathBuf>,

    /// Curve for identities given on the command line: ed25519 or nistp256.
    #[arg(long, global = true)]
    pub curve: Option<Curve>,

    /// Use the key stored in this slot (ECC1 to ECC16, or RSA1 to RSA4) for
    /// identities given on the command line, instead of deriving one.
    #[arg(long, global = true, value_name = "SLOT")]
    pub slot: Option<Slot>,

    /// Command run with the challenge prompt as its last argument
    /// (e.g. "notify-send OnlyKey"); also used when no terminal is available.
    #[arg(long, global = true)]
    pub notify_command: Option<String>,

    #[command(subcommand)]
    pub command: Cmd,
}

#[derive(Debug, Subcommand)]
pub enum Cmd {
    /// Show firmware version and lock state of the attached OnlyKey.
    Status,
    /// Print public keys in authorized_keys format.
    Pubkey(IdentityArgs),
    /// Run the agent on a unix socket.
    Serve(ServeArgs),
    /// Run a command with SSH_AUTH_SOCK pointing at a temporary agent.
    Run(RunArgs),
    /// Start $SHELL with SSH_AUTH_SOCK pointing at a temporary agent.
    Shell(IdentityArgs),
    /// Connect with ssh using the identity's key.
    Ssh(SshArgs),
    /// Sign a fixed test message and verify it (hardware check).
    #[command(hide = true)]
    DebugSign(DebugSignArgs),
}

#[derive(Debug, Args, Default)]
pub struct IdentityArgs {
    /// Identities as [user@]host; defaults to the config file's list, then
    /// to the comments in the public key file.
    pub identity: Vec<String>,

    /// Exported public keys to serve while the device is absent or locked;
    /// also names the identities when no other source gives any.
    #[arg(long)]
    pub pubkey_file: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct ServeArgs {
    #[command(flatten)]
    pub identities: IdentityArgs,

    /// Socket path (default: $XDG_RUNTIME_DIR/okagent/agent.sock).
    #[arg(long)]
    pub socket: Option<PathBuf>,

    /// Fork into the background and print shell commands that set SSH_AUTH_SOCK.
    #[arg(long, short)]
    pub daemon: bool,
}

#[derive(Debug, Args)]
pub struct RunArgs {
    #[command(flatten)]
    pub identities: IdentityArgs,

    /// Command to run after "--".
    #[arg(last = true, required = true)]
    pub command: Vec<String>,
}

#[derive(Debug, Args)]
pub struct SshArgs {
    /// Identity as [user@]host; the host is also the ssh destination.
    pub identity: String,

    /// Extra arguments passed to ssh after the destination (a remote command).
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub args: Vec<String>,
}

#[derive(Debug, Args)]
pub struct DebugSignArgs {
    pub identity: String,
    /// Length of the test message; 82 makes the device payload exactly 114 bytes.
    #[arg(long, default_value_t = 82)]
    pub len: usize,
}

/// Everything resolved from flags plus config.
struct Context_ {
    config: Config,
    curve: Curve,
    /// Whether `--curve` was given explicitly rather than defaulted.
    curve_given: bool,
    /// Applies to identities on the command line only.
    slot: Option<Slot>,
    sink: Arc<dyn ChallengeSink>,
    timeouts: Timeouts,
}

impl Context_ {
    fn key(&self, identity: &str) -> Result<KeySpec> {
        let kind = match self.slot {
            None => KeyKind::Derived(self.curve),
            Some(Slot::Ecc(slot)) => KeyKind::StoredEcc {
                slot,
                curve: self.curve,
            },
            Some(Slot::Rsa(slot)) => {
                if self.curve_given {
                    bail!("--curve does not apply to RSA slot {slot}");
                }
                KeyKind::StoredRsa(slot)
            }
        };
        Ok(KeySpec {
            identity: identity.parse::<Identity>()?,
            kind,
        })
    }

    /// Identities in order of preference: the command line, then the config
    /// file, then the comments of `preloaded` public keys.
    fn entries(&self, args: &IdentityArgs, preloaded: &[PublicKey]) -> Result<Vec<KeySpec>> {
        let entries = if !args.identity.is_empty() {
            args.identity
                .iter()
                .map(|s| self.key(s))
                .collect::<Result<Vec<_>>>()?
        } else {
            if self.slot.is_some() {
                bail!(
                    "--slot applies to identities given on the command line; use `slot` in [[identity]] for config entries"
                );
            }
            let from_config = self.config.entries(self.curve)?;
            if from_config.is_empty() {
                entries_from_keys(preloaded)
            } else {
                from_config
            }
        };
        if entries.is_empty() {
            bail!(
                "no identities given; pass [user@]host, add [[identity]] entries to the config file, or point --pubkey-file at exported keys"
            );
        }
        for e in &entries {
            if e.identity.is_transliterated() {
                tracing::warn!(identity = %e.identity, ascii = e.identity.derivation_input(), "identity was transliterated to ASCII before hashing");
            }
        }
        Ok(entries)
    }

    fn agent(&self, args: &IdentityArgs) -> Result<Arc<Agent>> {
        let pubkey_file = args
            .pubkey_file
            .clone()
            .or_else(|| self.config.pubkey_file.clone());
        let keys = match &pubkey_file {
            Some(path) => read_pubkey_file(path)?,
            None => Vec::new(),
        };
        let entries = self.entries(args, &keys)?;
        let timeouts = self.timeouts;
        let opener: Opener = Arc::new(move || Ok(OnlyKey::open_with_timeouts(timeouts)?.boxed()));
        let agent = Agent::new(entries, opener, Arc::clone(&self.sink));
        if let Some(path) = pubkey_file {
            let matched = agent.preload(keys);
            tracing::info!(matched, path = %path.display(), "preloaded public keys");
        }
        Ok(Arc::new(agent))
    }
}

/// Parse a file of `authorized_keys` lines as written by `okagent pubkey`.
/// Blank lines and `#` comments are skipped.
fn read_pubkey_file(path: &Path) -> Result<Vec<PublicKey>> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    text.lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .map(|l| {
            PublicKey::from_openssh(l).with_context(|| format!("parsing key in {}", path.display()))
        })
        .collect()
}

/// Identities named by the comments of exported keys, in file order without
/// duplicates. A comment that is not an `okagent` label is skipped with a
/// warning, as is a key whose type contradicts its label.
fn entries_from_keys(keys: &[PublicKey]) -> Vec<KeySpec> {
    let mut entries: Vec<KeySpec> = Vec::new();
    for key in keys {
        let spec = match KeySpec::from_label(key.comment()) {
            Ok(spec) => spec,
            Err(e) => {
                tracing::warn!(error = %e, "skipping public key: comment does not name an identity");
                continue;
            }
        };
        if key.algorithm() != spec.kind.public_algorithm() {
            tracing::warn!(label = %spec.label(), algorithm = %key.algorithm(), "skipping public key: type does not match its comment");
            continue;
        }
        if !entries.contains(&spec) {
            entries.push(spec);
        }
    }
    entries
}

/// Send log output to `log_file` (appended, owner-readable) or to stderr.
/// `OKAGENT_LOG` overrides the level chosen by `verbose`.
pub fn init_logging(verbose: u8, log_file: Option<&Path>) -> Result<()> {
    let level = match verbose {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };
    let filter = EnvFilter::try_from_env("OKAGENT_LOG").unwrap_or_else(|_| EnvFilter::new(level));
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false);
    match log_file {
        Some(path) => {
            use std::os::unix::fs::OpenOptionsExt;
            let file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .mode(0o600)
                .open(path)
                .with_context(|| format!("opening log file {}", path.display()))?;
            builder
                .with_writer(Mutex::new(file))
                .with_ansi(false)
                .init();
        }
        None => builder
            .with_writer(std::io::stderr)
            .with_ansi(std::io::stderr().is_terminal())
            .init(),
    }
    Ok(())
}

/// Run the CLI; returns the process exit code.
pub fn main(cli: Cli) -> Result<ExitCode> {
    let config = Config::load(cli.config.as_deref())?;
    init_logging(
        cli.verbose,
        cli.log_file.as_deref().or(config.log_file.as_deref()),
    )?;
    let curve = cli.curve.or(config.curve).unwrap_or_default();
    let mut sinks: Vec<Box<dyn ChallengeSink>> = vec![Box::new(TtyPrompt)];
    if let Some(cmd) = cli
        .notify_command
        .as_deref()
        .or(config.notify_command.as_deref())
    {
        let notifier =
            CommandNotifier::parse(cmd).ok_or_else(|| anyhow!("empty notify command"))?;
        sinks.push(Box::new(notifier));
    }
    let ctx = Context_ {
        config,
        curve,
        curve_given: cli.curve.is_some(),
        slot: cli.slot,
        sink: Arc::new(MultiSink(sinks)),
        timeouts: Timeouts::default(),
    };

    match cli.command {
        Cmd::Status => status(&ctx),
        Cmd::Pubkey(args) => pubkey(&ctx, &args),
        Cmd::Serve(args) => serve(&ctx, args),
        Cmd::Run(args) => run(&ctx, &args.identities, args.command),
        Cmd::Shell(args) => {
            let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".into());
            run(&ctx, &args, vec![shell])
        }
        Cmd::Ssh(args) => ssh(&ctx, args),
        Cmd::DebugSign(args) => debug_sign(&ctx, args),
    }
}

fn status(ctx: &Context_) -> Result<ExitCode> {
    let device = OnlyKey::open_with_timeouts(ctx.timeouts)?;
    match device.status() {
        DeviceStatus::Unlocked { version } => println!("OnlyKey unlocked, firmware {version}"),
        DeviceStatus::Locked => println!("OnlyKey locked: enter your PIN on the device"),
        DeviceStatus::Uninitialized => println!("OnlyKey has no PIN set"),
    }
    Ok(ExitCode::SUCCESS)
}

fn pubkey(ctx: &Context_, args: &IdentityArgs) -> Result<ExitCode> {
    let agent = ctx.agent(args)?;
    let keys = agent.derive_all()?;
    let mut out = std::io::stdout().lock();
    for key in keys {
        writeln!(out, "{}", key.to_openssh()?)?;
    }
    Ok(ExitCode::SUCCESS)
}

fn shutdown_flag() -> Result<Arc<AtomicBool>> {
    let flag = Arc::new(AtomicBool::new(false));
    for sig in [
        signal_hook::consts::SIGINT,
        signal_hook::consts::SIGTERM,
        signal_hook::consts::SIGHUP,
    ] {
        signal_hook::flag::register(sig, Arc::clone(&flag))?;
    }
    Ok(flag)
}

fn serve(ctx: &Context_, args: ServeArgs) -> Result<ExitCode> {
    let agent = ctx.agent(&args.identities)?;
    let path = args
        .socket
        .or_else(|| ctx.config.socket.clone())
        .unwrap_or_else(agent::default_socket_path);
    let (listener, guard) = agent::bind_socket(&path)?;
    if args.daemon {
        daemonize(&path)?;
    } else {
        eprintln!("SSH_AUTH_SOCK={}; export SSH_AUTH_SOCK;", path.display());
    }
    let shutdown = shutdown_flag()?;
    agent::serve(listener, agent, shutdown)?;
    drop(guard);
    Ok(ExitCode::SUCCESS)
}

/// Fork into the background. The parent prints the shell snippet and exits;
/// the child detaches from the terminal.
fn daemonize(socket: &std::path::Path) -> Result<()> {
    // SAFETY: no threads have been spawned yet and the child only continues
    // with async-signal-safe setup before returning to normal execution.
    match unsafe { fork() }.context("fork")? {
        ForkResult::Parent { .. } => {
            println!("SSH_AUTH_SOCK={}; export SSH_AUTH_SOCK;", socket.display());
            std::process::exit(0);
        }
        ForkResult::Child => {
            setsid().context("setsid")?;
            let _ = std::env::set_current_dir("/");
            let devnull = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open("/dev/null")?;
            nix::unistd::dup2_stdin(&devnull).context("redirect stdin")?;
            nix::unistd::dup2_stdout(&devnull).context("redirect stdout")?;
            Ok(())
        }
    }
}

/// Start an agent on a private socket, run `command` with `SSH_AUTH_SOCK` set,
/// and stop the agent when it exits.
fn run(ctx: &Context_, identities: &IdentityArgs, command: Vec<String>) -> Result<ExitCode> {
    let agent = ctx.agent(identities)?;
    let path = agent::ephemeral_socket_path();
    let (listener, guard) = agent::bind_socket(&path)?;
    let shutdown = shutdown_flag()?;
    let server = {
        let agent = Arc::clone(&agent);
        let shutdown = Arc::clone(&shutdown);
        std::thread::spawn(move || agent::serve(listener, agent, shutdown))
    };
    let (program, args) = command
        .split_first()
        .ok_or_else(|| anyhow!("no command given"))?;
    let status = Command::new(program)
        .args(args)
        .env("SSH_AUTH_SOCK", guard.path())
        .status()
        .with_context(|| format!("running {program}"));
    shutdown.store(true, Ordering::SeqCst);
    let _ = server.join();
    drop(guard);
    let status = status?;
    Ok(match status.code() {
        Some(code) => ExitCode::from(code.clamp(0, 255) as u8),
        None => ExitCode::from(128),
    })
}

fn ssh(ctx: &Context_, args: SshArgs) -> Result<ExitCode> {
    let identity: Identity = args.identity.parse()?;
    let id_args = IdentityArgs {
        identity: vec![args.identity.clone()],
        pubkey_file: None,
    };
    let agent = ctx.agent(&id_args)?;
    let keys = agent.derive_all()?;
    let key = keys.first().ok_or_else(|| anyhow!("no key derived"))?;
    let dir = tempfile::tempdir()?;
    let pub_path = dir.path().join("id.pub");
    std::fs::write(&pub_path, format!("{}\n", key.to_openssh()?))?;
    let mut command = vec![
        "ssh".to_owned(),
        "-o".into(),
        "IdentitiesOnly=yes".into(),
        "-o".into(),
        format!("IdentityFile={}", pub_path.display()),
    ];
    if let Some(user) = &identity.user {
        command.push("-l".into());
        command.push(user.clone());
    }
    command.push(identity.host.clone());
    command.extend(args.args);
    run(ctx, &id_args, command)
}

fn debug_sign(ctx: &Context_, args: DebugSignArgs) -> Result<ExitCode> {
    let spec = ctx.key(&args.identity)?;
    let message: Vec<u8> = (0..args.len).map(|i| i as u8).collect();
    let mut device = OnlyKey::open_with_timeouts(ctx.timeouts)?;
    let key = device.ssh_public_key(&spec)?;
    println!("{}", key.to_openssh()?);
    let hash = HashAlg::Sha512;
    let sig = device.ssh_sign(
        &spec,
        &key,
        &message,
        hash,
        Some("debug-sign".into()),
        ctx.sink.as_ref(),
    )?;
    println!(
        "{} signature over {} bytes verified ({} device payload bytes)",
        sig.algorithm(),
        args.len,
        spec.sign_message(&message, hash)?.len()
    );
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use onlykey_agent::ssh_key::public::{Ed25519PublicKey, KeyData};

    fn key(comment: &str) -> PublicKey {
        PublicKey::new(KeyData::Ed25519(Ed25519PublicKey([7; 32])), comment)
    }

    #[test]
    fn entries_come_from_labels_in_order_without_duplicates() {
        let keys = [
            key("<ssh://james@example.com|ed25519>"),
            key("james@laptop"),
            key("<ssh://james@example.com|nist256p1>"),
            key("<ssh://git@github.com|ed25519|ECC3>"),
            key("<ssh://james@example.com|ed25519>"),
        ];
        let entries = entries_from_keys(&keys);
        let labels: Vec<String> = entries.iter().map(KeySpec::label).collect();
        assert_eq!(
            labels,
            [
                "<ssh://james@example.com|ed25519>",
                "<ssh://git@github.com|ed25519|ECC3>"
            ]
        );
        assert!(entries_from_keys(&[]).is_empty());
    }

    #[test]
    fn pubkey_file_skips_blanks_and_comments() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keys.pub");
        let line = key("<ssh://james@example.com|ed25519>")
            .to_openssh()
            .unwrap();
        std::fs::write(&path, format!("# exported\n\n{line}\n")).unwrap();
        let keys = read_pubkey_file(&path).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].comment(), "<ssh://james@example.com|ed25519>");
        std::fs::write(&path, "not a key\n").unwrap();
        assert!(read_pubkey_file(&path).is_err());
        assert!(read_pubkey_file(&dir.path().join("missing")).is_err());
    }
}
