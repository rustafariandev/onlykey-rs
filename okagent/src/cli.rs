//! Command-line interface.

use crate::config::Config;
use anyhow::{Context, Result, anyhow, bail};
use clap::{Args, CommandFactory, Parser, Subcommand};
#[cfg(unix)]
use nix::unistd::{ForkResult, fork, setsid};
use okagent::agent::{self, Agent, Opener, SkOpener};
use okagent::agent::{client, sk};
use onlykey_agent::challenge::{
    AskpassConfirm, AskpassPin, ChainPin, ChallengeSink, CommandNotifier, MultiSink, PinPrompt,
    PinRequest, TtyPin, TtyPrompt,
};
use onlykey_agent::device::{OnlyKey, Timeouts};
use onlykey_agent::fido::credman;
use onlykey_agent::fido::ctaphid::CtapHid;
use onlykey_agent::fido::pin;
use onlykey_agent::identity::{Curve, Identity, KeyKind, KeySpec, Slot};
use onlykey_agent::protocol::DeviceStatus;
use onlykey_agent::ssh_key::HashAlg;
use onlykey_agent::ssh_key::PublicKey;
use onlykey_agent::transport::{
    DeviceEntry, DeviceKind, HidTransport, HidapiTransport, list_devices,
};
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tracing_subscriber::EnvFilter;

/// SSH agent backed by an OnlyKey hardware token.
#[derive(Debug, Parser)]
#[command(name = "okagent", version, about)]
pub struct Cli {
    /// More log output (repeat for more).
    #[arg(short, long, action = clap::ArgAction::Count, global = true, help_heading = "Global options")]
    pub verbose: u8,

    /// Append log output to this file instead of stderr.
    #[arg(
        long,
        global = true,
        value_name = "FILE",
        help_heading = "Global options"
    )]
    pub log_file: Option<PathBuf>,

    /// Config file (default: $XDG_CONFIG_HOME/okagent/config.toml, or
    /// %APPDATA%\okagent\config.toml on Windows).
    #[arg(
        long,
        global = true,
        env = "OKAGENT_CONFIG",
        help_heading = "Global options"
    )]
    pub config: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Cmd,
}

/// How identities given on the command line map to OnlyKey keys.
#[derive(Debug, Args, Default, Clone)]
#[command(next_help_heading = "Key options")]
pub struct KeyArgs {
    /// Curve for identities given on the command line: ed25519 or nistp256.
    #[arg(long)]
    pub curve: Option<Curve>,

    /// Use the key stored in this slot (ECC1 to ECC16, or RSA1 to RSA4) for
    /// identities given on the command line, instead of deriving one.
    #[arg(long, value_name = "SLOT")]
    pub slot: Option<Slot>,
}

/// Which FIDO security key signs for `sk-` keys, and how its PIN is asked.
#[derive(Debug, Args, Default, Clone)]
#[command(next_help_heading = "Security key options")]
pub struct SkArgs {
    /// FIDO security key to use for `sk-` keys, by hidraw path substring.
    /// Defaults to whichever attached authenticator, other than the OnlyKey,
    /// holds the key.
    #[arg(long, value_name = "PATH")]
    pub fido_device: Option<String>,

    /// Program that asks for a security key's PIN, for `sk-` keys enrolled
    /// with verify-required (default: the config's `askpass`, then
    /// $SSH_ASKPASS). Without one, the PIN is read from the terminal.
    #[arg(long, value_name = "PROGRAM")]
    pub askpass: Option<String>,
}

/// Options for commands that run an agent.
#[derive(Debug, Args, Default, Clone)]
#[command(next_help_heading = "Agent options")]
pub struct AgentArgs {
    /// Command run with the challenge prompt as its last argument
    /// (e.g. "notify-send OnlyKey"); also used when no terminal is available.
    #[arg(long)]
    pub notify_command: Option<String>,

    /// Seconds to reuse a security key's PIN before asking again; 0 (the
    /// default) asks for every signature.
    #[arg(long, value_name = "SECONDS")]
    pub pin_cache: Option<u64>,

    /// Default lifetime in seconds for keys added later with `ssh-add` that
    /// do not give their own `-t`; 0 (the default) keeps them until removed.
    #[arg(long, value_name = "SECONDS")]
    pub key_lifetime: Option<u32>,

    #[command(flatten)]
    pub sk: SkArgs,
}

#[derive(Debug, Subcommand)]
pub enum Cmd {
    /// Show firmware version and lock state of the attached OnlyKey.
    Status,
    /// List attached OnlyKeys and FIDO security keys.
    Devices(DevicesArgs),
    /// Print public keys in authorized_keys format.
    Pubkey(PubkeyArgs),
    /// Add the SSH keys stored on FIDO security keys (resident keys) to the
    /// agent, keeping whether each needs its PIN (unlike `ssh-add -K`).
    LoadResident(LoadResidentArgs),
    /// Run the agent on a unix socket (a named pipe on Windows).
    Serve(ServeArgs),
    /// Run a command with SSH_AUTH_SOCK and SSH_AGENT_PID set for a temporary agent.
    Run(RunArgs),
    /// Start $SHELL (%COMSPEC% on Windows) with SSH_AUTH_SOCK and
    /// SSH_AGENT_PID set for a temporary agent.
    Shell(ShellArgs),
    /// Connect with ssh using the identity's key.
    Ssh(SshArgs),
    /// Connect with mosh, whose ssh step uses the identity's key.
    Mosh(SshArgs),
    /// Install the identity's public key on the remote host with ssh-copy-id.
    SshCopyId(SshCopyIdArgs),
    /// Sign a fixed test message and verify it (hardware check).
    #[command(hide = true)]
    DebugSign(DebugSignArgs),
    /// Print a shell completion script for the given shell.
    Completions(CompletionsArgs),
}

/// Identities given as positional arguments, with `--pubkey-file`.
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

/// Positional identities plus extra identities given with `-i`/`--identity`,
/// which are added to the list rather than replacing it.
#[derive(Debug, Args, Default)]
pub struct ExtraIdentityArgs {
    #[command(flatten)]
    pub base: IdentityArgs,

    /// Additional identities, added to the positional or config-file list
    /// instead of replacing it.
    #[arg(short = 'i', long = "identity", value_name = "IDENTITY")]
    pub additional: Vec<String>,
}

#[derive(Debug, Args)]
pub struct PubkeyArgs {
    #[command(flatten)]
    pub identities: IdentityArgs,

    #[command(flatten)]
    pub key: KeyArgs,
}

#[derive(Debug, Args)]
pub struct ShellArgs {
    #[command(flatten)]
    pub identities: ExtraIdentityArgs,

    #[command(flatten)]
    pub key: KeyArgs,

    #[command(flatten)]
    pub agent: AgentArgs,
}

#[derive(Debug, Args)]
pub struct ServeArgs {
    #[command(flatten)]
    pub identities: ExtraIdentityArgs,

    /// Socket path (default: $XDG_RUNTIME_DIR/okagent/agent.sock, or
    /// $TMPDIR/okagent/agent.sock on macOS; the pipe \\.\pipe\okagent-USER
    /// on Windows).
    #[arg(long)]
    pub socket: Option<PathBuf>,

    /// Run in the background and print shell commands (PowerShell on
    /// Windows) that set SSH_AUTH_SOCK and SSH_AGENT_PID.
    #[arg(long, short)]
    pub daemon: bool,

    /// Also answer PuTTY, WinSCP and other Pageant clients (Windows only).
    #[arg(long, hide = cfg!(not(windows)))]
    pub pageant: bool,

    #[command(flatten)]
    pub key: KeyArgs,

    #[command(flatten)]
    pub agent: AgentArgs,
}

#[derive(Debug, Args)]
pub struct RunArgs {
    #[command(flatten)]
    pub identities: ExtraIdentityArgs,

    /// Command to run after "--".
    #[arg(last = true, required = true)]
    pub command: Vec<String>,

    #[command(flatten)]
    pub key: KeyArgs,

    #[command(flatten)]
    pub agent: AgentArgs,
}

#[derive(Debug, Args)]
pub struct SshArgs {
    /// Identity as [user@]host[:port] naming the key.
    pub identity: String,

    /// Server to connect to as [user@]host[:port]; defaults to the identity's
    /// host. Use it to connect to a different server than the identity names.
    /// Without a user the identity's user is kept; without a port the default
    /// port is used (the identity's :port is not carried over).
    #[arg(long, value_name = "HOST")]
    pub host: Option<String>,

    /// Exported public keys to serve while the device is absent or locked.
    #[arg(long)]
    pub pubkey_file: Option<PathBuf>,

    /// Additional identities to serve alongside the primary one, for example
    /// for agent forwarding (-A). Repeatable; give it before the identity so
    /// it is not mistaken for ssh's own -i.
    #[arg(short = 'i', long = "identity", value_name = "IDENTITY")]
    pub additional: Vec<String>,

    /// Extra arguments passed after the destination (a remote command).
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub args: Vec<String>,

    #[command(flatten)]
    pub key: KeyArgs,

    #[command(flatten)]
    pub agent: AgentArgs,
}

#[derive(Debug, Args)]
pub struct SshCopyIdArgs {
    /// Identity as [user@]host[:port] naming the key.
    pub identity: String,

    /// Server to connect to as [user@]host[:port]; defaults to the identity's
    /// host. Use it to install the key on a different server than the identity
    /// names. Without a user the identity's user is kept; without a port the
    /// default port is used (the identity's :port is not carried over).
    #[arg(long, value_name = "HOST")]
    pub host: Option<String>,

    /// Exported public keys to serve while the device is absent or locked.
    #[arg(long)]
    pub pubkey_file: Option<PathBuf>,

    /// Extra arguments for ssh-copy-id (for example -f or -n), passed before
    /// the destination.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub args: Vec<String>,

    #[command(flatten)]
    pub key: KeyArgs,

    #[command(flatten)]
    pub agent: AgentArgs,
}

/// Which remote-shell program `SshArgs` drives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Remote {
    Ssh,
    Mosh,
}

#[derive(Debug, Args)]
pub struct DebugSignArgs {
    pub identity: String,
    /// Length of the test message; 82 makes the device payload exactly 114 bytes.
    #[arg(long, default_value_t = 82)]
    pub len: usize,
    /// Digest for an RSA key: sha256 or sha512.
    #[arg(long, default_value = "sha512")]
    pub hash: String,
    #[command(flatten)]
    pub key: KeyArgs,
    #[command(flatten)]
    pub agent: AgentArgs,
}

#[derive(Debug, Args)]
pub struct LoadResidentArgs {
    /// Agent socket to add the keys to (default: $SSH_AUTH_SOCK, then the
    /// config's `socket`, then okagent's default socket).
    #[arg(long)]
    pub socket: Option<PathBuf>,

    #[command(flatten)]
    pub sk: SkArgs,
}

#[derive(Debug, Args)]
pub struct DevicesArgs {
    /// List only OnlyKeys.
    #[arg(long)]
    pub onlykey: bool,

    /// List only FIDO security keys (including the OnlyKey's FIDO interface).
    #[arg(long)]
    pub fido: bool,
}

#[derive(Debug, Args)]
pub struct CompletionsArgs {
    /// Shell to generate a completion script for.
    #[arg(value_enum)]
    pub shell: clap_complete::Shell,
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
    /// Optional FIDO device path for `sk-` keys.
    fido_device: Option<String>,
    /// Asks for security key PINs.
    pin_prompt: Arc<dyn PinPrompt>,
    pin_cache: Duration,
    /// Default lifetime for keys added later, from `--key-lifetime`.
    key_lifetime: Option<u32>,
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
    /// file, then the comments of `preloaded` public keys. `additional`
    /// identities are appended to whichever list is chosen.
    ///
    /// An empty list is allowed: an agent started with no identities serves no
    /// keys until `ssh-add` adds some. Callers that need a key to connect
    /// (`ssh`, `mosh`, `ssh-copy-id`) check for one themselves.
    fn entries(
        &self,
        args: &IdentityArgs,
        additional: &[String],
        preloaded: &[PublicKey],
    ) -> Result<Vec<KeySpec>> {
        let mut entries = if !args.identity.is_empty() {
            args.identity
                .iter()
                .map(|s| self.key(s))
                .collect::<Result<Vec<_>>>()?
        } else {
            if self.slot.is_some() && additional.is_empty() {
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
        for identity in additional {
            entries.push(self.key(identity)?);
        }
        if entries.is_empty() {
            tracing::info!("no identities given; serving no keys until ssh-add adds some");
        }
        for e in &entries {
            if e.identity.is_transliterated() {
                tracing::warn!(identity = %e.identity, ascii = e.identity.derivation_input(), "identity was transliterated to ASCII before hashing: it derives the same key as the ASCII identity, and as any other that transliterates to it");
            }
        }
        Ok(entries)
    }

    fn agent(&self, args: &IdentityArgs, additional: &[String]) -> Result<Arc<Agent>> {
        let pubkey_file = args
            .pubkey_file
            .clone()
            .or_else(|| self.config.pubkey_file.clone());
        let keys = match &pubkey_file {
            Some(path) => read_pubkey_file(path)?,
            None => Vec::new(),
        };
        let entries = self.entries(args, additional, &keys)?;
        let timeouts = self.timeouts;
        let opener: Opener = Arc::new(move || Ok(OnlyKey::open_with_timeouts(timeouts)?.boxed()));
        let fido_device = self.fido_device.clone();
        let sk_opener: SkOpener = Arc::new(move || {
            Ok(HidapiTransport::open_all_fido(fido_device.as_deref())?
                .into_iter()
                .map(|t| Box::new(t) as Box<dyn HidTransport>)
                .collect())
        });
        let agent = Agent::new(entries, opener, Arc::clone(&self.sink))
            .with_sk_opener(sk_opener)
            .with_pin_prompt(Arc::clone(&self.pin_prompt))
            .with_pin_cache(self.pin_cache)
            .with_default_lifetime(self.key_lifetime);
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
            let mut options = std::fs::OpenOptions::new();
            options.create(true).append(true);
            // On Windows a new file inherits its directory's access list,
            // which in the user's profile is the user's alone.
            #[cfg(unix)]
            std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
            let file = options
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
    if let Cmd::Completions(args) = &cli.command {
        return completions(args);
    }
    let config = Config::load(cli.config.as_deref())?;
    init_logging(
        cli.verbose,
        cli.log_file.as_deref().or(config.log_file.as_deref()),
    )?;
    let (key, opts) = cli.command.options();
    let ctx = context(config, &key, &opts)?;

    match cli.command {
        Cmd::Status => status(&ctx),
        Cmd::Devices(args) => devices(&args),
        Cmd::Pubkey(args) => pubkey(&ctx, &args.identities),
        Cmd::LoadResident(args) => load_resident(&ctx, &args),
        Cmd::Serve(args) => serve(&ctx, args),
        Cmd::Run(args) => run(&ctx, &args.identities, args.command),
        Cmd::Shell(args) => {
            #[cfg(unix)]
            let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".into());
            #[cfg(windows)]
            let shell = std::env::var("COMSPEC").unwrap_or_else(|_| "cmd.exe".into());
            run(&ctx, &args.identities, vec![shell])
        }
        Cmd::Ssh(args) => connect(&ctx, args, Remote::Ssh),
        Cmd::Mosh(args) => connect(&ctx, args, Remote::Mosh),
        Cmd::SshCopyId(args) => ssh_copy_id(&ctx, args),
        Cmd::DebugSign(args) => debug_sign(&ctx, args),
        Cmd::Completions(args) => completions(&args),
    }
}

impl Cmd {
    /// The key and agent options this command takes; defaults for the ones
    /// it does not, so the config file still fills them in.
    fn options(&self) -> (KeyArgs, AgentArgs) {
        match self {
            Cmd::Pubkey(args) => (args.key.clone(), AgentArgs::default()),
            Cmd::LoadResident(args) => (
                KeyArgs::default(),
                AgentArgs {
                    sk: args.sk.clone(),
                    ..AgentArgs::default()
                },
            ),
            Cmd::Serve(ServeArgs { key, agent, .. })
            | Cmd::Run(RunArgs { key, agent, .. })
            | Cmd::Shell(ShellArgs { key, agent, .. })
            | Cmd::Ssh(SshArgs { key, agent, .. })
            | Cmd::Mosh(SshArgs { key, agent, .. })
            | Cmd::SshCopyId(SshCopyIdArgs { key, agent, .. })
            | Cmd::DebugSign(DebugSignArgs { key, agent, .. }) => (key.clone(), agent.clone()),
            Cmd::Status | Cmd::Devices(_) | Cmd::Completions(_) => {
                (KeyArgs::default(), AgentArgs::default())
            }
        }
    }
}

/// Resolve the command's options against the config file and defaults.
fn context(config: Config, key: &KeyArgs, opts: &AgentArgs) -> Result<Context_> {
    let curve = key.curve.or(config.curve).unwrap_or_default();
    let mut sinks: Vec<Box<dyn ChallengeSink>> = vec![Box::new(TtyPrompt)];
    if let Some(cmd) = opts
        .notify_command
        .as_deref()
        .or(config.notify_command.as_deref())
    {
        let notifier =
            CommandNotifier::parse(cmd).ok_or_else(|| anyhow!("empty notify command"))?;
        sinks.push(Box::new(notifier));
    }
    let fido_device = opts
        .sk
        .fido_device
        .clone()
        .or_else(|| config.fido_device.clone());
    let askpass = opts
        .sk
        .askpass
        .clone()
        .or_else(|| config.askpass.clone())
        .or_else(|| std::env::var("SSH_ASKPASS").ok())
        .filter(|program| !program.is_empty());
    // `ssh-add -c` confirmation goes through the same askpass program, when
    // one is configured and no terminal is available.
    if let Some(program) = askpass.clone() {
        sinks.push(Box::new(AskpassConfirm::new(program)));
    }
    let pin_cache = Duration::from_secs(opts.pin_cache.or(config.pin_cache).unwrap_or(0));
    let key_lifetime = opts.key_lifetime.or(config.key_lifetime);
    Ok(Context_ {
        pin_prompt: Arc::new(pin_prompt(askpass)),
        pin_cache,
        key_lifetime,
        config,
        curve,
        curve_given: key.curve.is_some(),
        slot: key.slot,
        sink: Arc::new(MultiSink(sinks)),
        timeouts: Timeouts::default(),
        fido_device,
    })
}

/// Ask for PINs with the askpass program when there is one, else on the
/// terminal.
fn pin_prompt(askpass: Option<String>) -> ChainPin {
    let mut prompts: Vec<Box<dyn PinPrompt>> = Vec::new();
    if let Some(program) = askpass {
        prompts.push(Box::new(AskpassPin::new(program)));
    }
    prompts.push(Box::new(TtyPin));
    ChainPin(prompts)
}

fn completions(args: &CompletionsArgs) -> Result<ExitCode> {
    let mut cmd = Cli::command();
    let name = cmd.get_name().to_string();
    // Buffer first: `generate` writes into a `Vec`, so a closed stdout (for
    // example `okagent completions bash | head`) is an ordinary I/O error
    // rather than a panic inside clap_complete.
    let mut buf = Vec::new();
    clap_complete::generate(args.shell, &mut cmd, name, &mut buf);
    match std::io::stdout().write_all(&buf) {
        Ok(()) => Ok(ExitCode::SUCCESS),
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => Ok(ExitCode::SUCCESS),
        Err(e) => Err(e.into()),
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

/// List the attached devices, one per line; fails when none matches.
fn devices(args: &DevicesArgs) -> Result<ExitCode> {
    let all = !args.onlykey && !args.fido;
    let entries: Vec<DeviceEntry> = list_devices()?
        .into_iter()
        .filter(|e| match e.kind {
            DeviceKind::OnlyKey => all || args.onlykey,
            DeviceKind::Fido => all || args.fido,
        })
        .collect();
    if entries.is_empty() {
        eprintln!("okagent: no devices found");
        return Ok(ExitCode::FAILURE);
    }
    let width = entries.iter().map(|e| e.path.len()).max().unwrap_or(0);
    let text: String = entries
        .iter()
        .map(|e| format!("{}\n", format_entry(e, width)))
        .collect();
    match std::io::stdout().write_all(text.as_bytes()) {
        Ok(()) => Ok(ExitCode::SUCCESS),
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => Ok(ExitCode::SUCCESS),
        Err(e) => Err(e.into()),
    }
}

/// One `devices` line: kind, path padded to `width`, USB ids and names.
fn format_entry(entry: &DeviceEntry, width: usize) -> String {
    let kind = match entry.kind {
        DeviceKind::OnlyKey => "onlykey",
        DeviceKind::Fido => "fido",
    };
    let name = [entry.manufacturer.as_deref(), entry.product.as_deref()]
        .into_iter()
        .flatten()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    let mut line = format!(
        "{kind:<7}  {:<width$}  {:04x}:{:04x}",
        entry.path, entry.vendor_id, entry.product_id
    );
    if !name.is_empty() {
        line.push_str("  ");
        line.push_str(&name);
    }
    if entry.kind == DeviceKind::Fido && entry.is_onlykey {
        line.push_str(" (OnlyKey FIDO interface)");
    }
    line
}

fn pubkey(ctx: &Context_, args: &IdentityArgs) -> Result<ExitCode> {
    let agent = ctx.agent(args, &[])?;
    let keys = agent.derive_all()?;
    let mut out = std::io::stdout().lock();
    for key in keys {
        writeln!(out, "{}", key.to_openssh()?)?;
    }
    Ok(ExitCode::SUCCESS)
}

/// Read the resident SSH keys of every attached security key (or the one
/// `--fido-device` names) and add them to the agent; fails when none is
/// added.
fn load_resident(ctx: &Context_, args: &LoadResidentArgs) -> Result<ExitCode> {
    let socket = args
        .socket
        .clone()
        .or_else(|| {
            std::env::var_os("SSH_AUTH_SOCK")
                .filter(|s| !s.is_empty())
                .map(PathBuf::from)
        })
        .or_else(|| ctx.config.socket.clone())
        .unwrap_or_else(agent::default_socket_path);
    if !ctx.pin_prompt.available() {
        bail!(
            "listing resident keys needs the security key's PIN, but there is no askpass program (--askpass or SSH_ASKPASS) or terminal to ask with"
        );
    }
    let mut added = 0;
    for transport in HidapiTransport::open_all_fido(ctx.fido_device.as_deref())? {
        let path = transport.path().to_owned();
        let mut hid = CtapHid::new(transport);
        match load_resident_from(ctx, &mut hid, &path, &socket) {
            Ok(count) => added += count,
            Err(e) => eprintln!("okagent: {path}: {e:#}"),
        }
    }
    if added == 0 {
        eprintln!("okagent: no resident SSH keys added");
        return Ok(ExitCode::FAILURE);
    }
    Ok(ExitCode::SUCCESS)
}

/// Add one security key's resident SSH keys to the agent at `socket`;
/// returns how many.
fn load_resident_from(
    ctx: &Context_,
    hid: &mut CtapHid<HidapiTransport>,
    path: &str,
    socket: &Path,
) -> Result<usize> {
    let info = pin::get_info(hid)?;
    if credman::command_byte(&info).is_none() {
        bail!("no credential management, so its resident keys cannot be listed");
    }
    let request = PinRequest {
        action: format!("list the resident keys on {path}"),
        subject: None,
        retries: None,
        problem: None,
    };
    let permissions = pin::Permissions {
        bits: pin::PERMISSION_CREDENTIAL_MANAGEMENT,
        rp_id: None,
    };
    let (protocol, token) =
        pin::pin_token_interactive(hid, ctx.pin_prompt.as_ref(), &request, permissions)?;
    let credentials = credman::enumerate(hid, &info, protocol, &token)?;
    let mut added = 0;
    for credential in &credentials {
        if !credential.rp_id.starts_with("ssh:") {
            tracing::debug!(
                rp = credential.rp_id,
                "skipping a resident credential not for SSH"
            );
            continue;
        }
        let verify = credman::needs_verification(hid, credential)?;
        let (public, body) = sk::resident_key(credential, verify)?;
        client::add_identity(socket, &body)?;
        eprintln!(
            "Resident key added: {} ({} {}{})",
            public.comment(),
            public.algorithm(),
            public.fingerprint(HashAlg::Sha256),
            if verify { ", verify-required" } else { "" }
        );
        added += 1;
    }
    if added == 0 {
        eprintln!("okagent: {path}: no resident SSH keys");
    }
    Ok(added)
}

fn shutdown_flag() -> Result<Arc<AtomicBool>> {
    let flag = Arc::new(AtomicBool::new(false));
    for sig in [
        signal_hook::consts::SIGINT,
        signal_hook::consts::SIGTERM,
        #[cfg(unix)]
        signal_hook::consts::SIGHUP,
    ] {
        signal_hook::flag::register(sig, Arc::clone(&flag))?;
    }
    Ok(flag)
}

fn serve(ctx: &Context_, args: ServeArgs) -> Result<ExitCode> {
    let agent = ctx.agent(&args.identities.base, &args.identities.additional)?;
    let path = args
        .socket
        .or_else(|| ctx.config.socket.clone())
        .unwrap_or_else(agent::default_socket_path);
    if cfg!(not(windows)) {
        if args.pageant {
            bail!("--pageant is only available on Windows");
        }
        // A config shared with a Windows machine may ask for it.
        if ctx.config.pageant == Some(true) {
            tracing::debug!("ignoring `pageant` in the config: Pageant is Windows only");
        }
    }
    // A pipe cannot be handed to another process, so on Windows the
    // background copy binds it itself.
    #[cfg(windows)]
    if args.daemon && std::env::var_os(DETACHED_ENV).is_none() {
        return respawn_detached(&path);
    }
    let (listener, guard) = agent::bind_socket(&path)?;
    if args.daemon {
        #[cfg(unix)]
        daemonize(&path)?;
    } else {
        eprint!("{}", agent_env_snippet(&path, std::process::id()));
    }
    let shutdown = shutdown_flag()?;
    #[cfg(windows)]
    if args.pageant || ctx.config.pageant.unwrap_or(false) {
        serve_as_pageant(&agent, &shutdown);
    }
    agent::serve(listener, agent, shutdown)?;
    drop(guard);
    Ok(ExitCode::SUCCESS)
}

/// Answer PuTTY's tools too, on threads of their own: newer ones on
/// Pageant's pipe, older ones through its window. Either is skipped, with a
/// warning, when a Pageant already has it.
#[cfg(windows)]
fn serve_as_pageant(agent: &Arc<Agent>, shutdown: &Arc<AtomicBool>) {
    let pipe = agent::pageant_pipe_name()
        .map_err(anyhow::Error::from)
        .and_then(|name| Ok(agent::bind_socket(&name)?));
    match pipe {
        Ok((listener, guard)) => {
            let (agent, shutdown) = (Arc::clone(agent), Arc::clone(shutdown));
            std::thread::spawn(move || {
                let _guard = guard;
                if let Err(e) = agent::serve(listener, agent, shutdown) {
                    tracing::error!("Pageant pipe: {e}");
                }
            });
        }
        Err(e) => tracing::warn!("not serving Pageant's pipe: {e:#}"),
    }
    let (agent, shutdown) = (Arc::clone(agent), Arc::clone(shutdown));
    std::thread::spawn(move || {
        if let Err(e) = agent::serve_pageant_window(agent, shutdown) {
            tracing::warn!("not serving Pageant's window: {e}");
        }
    });
}

/// The lines `ssh-agent -s` would print: the socket and the agent's pid,
/// so that `ssh-agent -k` can stop it.
#[cfg(unix)]
fn agent_env_snippet(socket: &Path, pid: u32) -> String {
    format!(
        "SSH_AUTH_SOCK={}; export SSH_AUTH_SOCK;\nSSH_AGENT_PID={pid}; export SSH_AGENT_PID;\n",
        shell_quote(&socket.display().to_string())
    )
}

/// `text` as one shell word: unchanged when it is plain, else single-quoted,
/// so a socket path from `--socket` or the environment cannot run commands
/// under `eval "$(okagent serve --daemon)"`.
#[cfg(unix)]
fn shell_quote(text: &str) -> String {
    let plain = !text.is_empty()
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "/._-+:@%,=".contains(c));
    if plain {
        text.to_owned()
    } else {
        format!("'{}'", text.replace('\'', r"'\''"))
    }
}

/// The PowerShell equivalent, for `okagent serve --daemon | Invoke-Expression`.
#[cfg(windows)]
fn agent_env_snippet(socket: &Path, pid: u32) -> String {
    format!(
        "$env:SSH_AUTH_SOCK = {};\n$env:SSH_AGENT_PID = '{pid}';\n",
        powershell_quote(&socket.display().to_string())
    )
}

/// `text` as a PowerShell string literal that expands nothing. PowerShell
/// also takes the typographic single quotes as quotes, so those are doubled
/// as well.
#[cfg(windows)]
fn powershell_quote(text: &str) -> String {
    let mut quoted = String::with_capacity(text.len() + 2);
    quoted.push('\'');
    for c in text.chars() {
        if matches!(c, '\'' | '\u{2018}' | '\u{2019}' | '\u{201A}' | '\u{201B}') {
            quoted.push(c);
        }
        quoted.push(c);
    }
    quoted.push('\'');
    quoted
}

/// Set in the background copy that `serve --daemon` starts on Windows.
#[cfg(windows)]
const DETACHED_ENV: &str = "OKAGENT_DETACHED";

/// Start this command again as a detached process with no console, wait
/// until it answers on `socket`, then print the PowerShell snippet. Windows
/// has no fork, and the console is what a detached agent must give up.
#[cfg(windows)]
fn respawn_detached(socket: &Path) -> Result<ExitCode> {
    use std::os::windows::io::AsRawHandle;
    use std::os::windows::process::CommandExt;
    use std::process::Stdio;
    use std::time::Instant;
    use windows_sys::Win32::Foundation::{HANDLE_FLAG_INHERIT, SetHandleInformation};
    use windows_sys::Win32::System::Threading::{CREATE_NEW_PROCESS_GROUP, DETACHED_PROCESS};

    if client::connect(socket).is_ok() {
        bail!("an agent is already serving {}", socket.display());
    }
    // A child inherits every inheritable handle, not only the three it is
    // given. Holding on to this process's stdout would keep the pipe of
    // `okagent serve --daemon | Invoke-Expression` open after it exits.
    for handle in [
        std::io::stdin().as_raw_handle(),
        std::io::stdout().as_raw_handle(),
        std::io::stderr().as_raw_handle(),
    ] {
        // SAFETY: changes only the flags of this process's own std handle;
        // a null or invalid one makes the call fail harmlessly.
        unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0) };
    }
    let exe = std::env::current_exe().context("finding okagent's own path")?;
    let mut child = Command::new(exe)
        .args(std::env::args_os().skip(1))
        .env(DETACHED_ENV, "1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP)
        .spawn()
        .context("starting the agent in the background")?;
    let deadline = Instant::now() + Duration::from_secs(10);
    while client::connect(socket).is_err() {
        if let Some(status) = child.try_wait()? {
            bail!("the background agent exited ({status}); run `okagent serve` to see why");
        }
        if Instant::now() > deadline {
            bail!(
                "the background agent (pid {}) did not start serving {}",
                child.id(),
                socket.display()
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    print!("{}", agent_env_snippet(socket, child.id()));
    Ok(ExitCode::SUCCESS)
}

/// Fork into the background. The parent prints the shell snippet and exits;
/// the child detaches from the terminal.
#[cfg(unix)]
fn daemonize(socket: &Path) -> Result<()> {
    // SAFETY: no threads have been spawned yet and the child only continues
    // with async-signal-safe setup before returning to normal execution.
    match unsafe { fork() }.context("fork")? {
        ForkResult::Parent { child } => {
            print!("{}", agent_env_snippet(socket, child.as_raw() as u32));
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

/// Start an agent on a private socket, run `command` with `SSH_AUTH_SOCK`
/// and `SSH_AGENT_PID` set, and stop the agent when it exits.
fn run(ctx: &Context_, identities: &ExtraIdentityArgs, command: Vec<String>) -> Result<ExitCode> {
    let agent = ctx.agent(&identities.base, &identities.additional)?;
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
        .env("SSH_AGENT_PID", std::process::id().to_string())
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

/// Run ssh or mosh against the identity's host with a temporary agent that
/// serves only that key. ssh is told to offer nothing else; mosh gets the
/// same ssh command line through `--ssh`.
fn connect(ctx: &Context_, args: SshArgs, remote: Remote) -> Result<ExitCode> {
    let (identity, port) = Identity::parse_with_port(&args.identity)?;
    let (destination, port) = destination(&identity, port, args.host.as_deref())?;
    let id_args = ExtraIdentityArgs {
        base: IdentityArgs {
            identity: vec![args.identity.clone()],
            pubkey_file: args.pubkey_file.clone(),
        },
        additional: args.additional.clone(),
    };
    let agent = ctx.agent(&id_args.base, &id_args.additional)?;
    let primary = agent
        .entries()
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("no identities given"))?;
    let key = agent.derive_one(&primary)?;
    let dir = tempfile::tempdir()?;
    let pub_path = dir.path().join("id.pub");
    std::fs::write(&pub_path, format!("{}\n", key.to_openssh()?))?;
    let mut ssh = vec![
        "ssh".to_owned(),
        "-o".into(),
        "IdentitiesOnly=yes".into(),
        "-o".into(),
        format!("IdentityFile={}", pub_path.display()),
    ];
    if let Some(port) = port {
        ssh.push("-p".into());
        ssh.push(port.to_string());
    }
    let command = match remote {
        Remote::Ssh => {
            let mut command = ssh;
            if let Some(user) = &destination.user {
                command.push("-l".into());
                command.push(user.clone());
            }
            command.push(destination.host.clone());
            command
        }
        Remote::Mosh => {
            // mosh splits --ssh on whitespace, so the temporary path must
            // not contain any.
            let ssh_line = ssh.join(" ");
            if ssh_line.split_whitespace().count() != ssh.len() {
                bail!(
                    "temporary directory path {} contains whitespace, which mosh --ssh cannot carry",
                    dir.path().display()
                );
            }
            let mut command = vec!["mosh".to_owned(), format!("--ssh={ssh_line}")];
            command.push(destination.to_string());
            command
        }
    };
    let command = command.into_iter().chain(args.args).collect();
    run(ctx, &id_args, command)
}

/// The ssh destination: `--host` when given, else the identity itself. A
/// `--host` without a user keeps the identity's user, so the key's identity
/// and the login name stay independent of the server's address. A `--host`
/// without a port uses the default port; the identity's `:port` belongs to
/// the identity's host and is not carried over.
fn destination(
    identity: &Identity,
    port: Option<u16>,
    host: Option<&str>,
) -> Result<(Identity, Option<u16>)> {
    let (dest, port) = match host {
        None => (identity.clone(), port),
        Some(host) => {
            let (dest, dest_port) = Identity::parse_with_port(host)?;
            let user = dest.user.or_else(|| identity.user.clone());
            (Identity::new(user.as_deref(), &dest.host), dest_port)
        }
    };
    // ssh, mosh and ssh-copy-id would read such a word as an option, such as
    // -oProxyCommand=...
    if dest.host.starts_with('-') || dest.user.as_deref().is_some_and(|u| u.starts_with('-')) {
        bail!("destination {dest} must not start with '-'");
    }
    Ok((dest, port))
}

/// Install the identity's public key on the remote host by running
/// `ssh-copy-id` with a temporary agent that serves only that key.
/// ssh-copy-id reads the key from `ssh-add -L` and uses it both for its trial
/// login and for the install, so no public key file is needed.
fn ssh_copy_id(ctx: &Context_, args: SshCopyIdArgs) -> Result<ExitCode> {
    let (identity, port) = Identity::parse_with_port(&args.identity)?;
    let (destination, port) = destination(&identity, port, args.host.as_deref())?;
    let id_args = ExtraIdentityArgs {
        base: IdentityArgs {
            identity: vec![args.identity.clone()],
            pubkey_file: args.pubkey_file.clone(),
        },
        additional: Vec::new(),
    };
    let command = ssh_copy_id_command(&destination, port, args.args);
    run(ctx, &id_args, command)
}

/// The ssh-copy-id command line: options first, the destination last. The
/// identity's port becomes `-p`, and `extra` is passed through unchanged.
fn ssh_copy_id_command(identity: &Identity, port: Option<u16>, extra: Vec<String>) -> Vec<String> {
    let mut command = vec!["ssh-copy-id".to_owned()];
    if let Some(port) = port {
        command.push("-p".into());
        command.push(port.to_string());
    }
    command.extend(extra);
    command.push(identity.to_string());
    command
}

fn debug_sign(ctx: &Context_, args: DebugSignArgs) -> Result<ExitCode> {
    let spec = ctx.key(&args.identity)?;
    let message: Vec<u8> = (0..args.len).map(|i| i as u8).collect();
    let mut device = OnlyKey::open_with_timeouts(ctx.timeouts)?;
    let key = device.ssh_public_key(&spec)?;
    println!("{}", key.to_openssh()?);
    let hash = match args.hash.to_ascii_lowercase().as_str() {
        "sha256" => HashAlg::Sha256,
        "sha512" => HashAlg::Sha512,
        other => bail!("unknown hash {other:?}; use sha256 or sha512"),
    };
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
            key("<ssh://ferris@example.com|ed25519>"),
            key("ferris@laptop"),
            key("<ssh://ferris@example.com|nist256p1>"),
            key("<ssh://git@github.com|ed25519|ECC3>"),
            key("<ssh://ferris@example.com|ed25519>"),
        ];
        let entries = entries_from_keys(&keys);
        let labels: Vec<String> = entries.iter().map(KeySpec::label).collect();
        assert_eq!(
            labels,
            [
                "<ssh://ferris@example.com|ed25519>",
                "<ssh://git@github.com|ed25519|ECC3>"
            ]
        );
        assert!(entries_from_keys(&[]).is_empty());
    }

    #[test]
    fn ssh_copy_id_command_puts_options_before_destination() {
        let id: Identity = "user@example.com".parse().unwrap();
        assert_eq!(
            ssh_copy_id_command(&id, Some(2222), vec!["-f".to_owned()]),
            vec!["ssh-copy-id", "-p", "2222", "-f", "user@example.com"]
        );
        let id: Identity = "example.com".parse().unwrap();
        assert_eq!(
            ssh_copy_id_command(&id, None, Vec::new()),
            vec!["ssh-copy-id", "example.com"]
        );
    }

    #[cfg(unix)]
    #[test]
    fn env_snippet_matches_ssh_agent_output() {
        assert_eq!(
            agent_env_snippet(Path::new("/run/a.sock"), 42),
            "SSH_AUTH_SOCK=/run/a.sock; export SSH_AUTH_SOCK;\nSSH_AGENT_PID=42; export SSH_AGENT_PID;\n"
        );
    }

    #[test]
    fn remote_commands_accept_pubkey_file() {
        for cmd in ["ssh", "mosh"] {
            let cli = Cli::try_parse_from([
                "okagent",
                cmd,
                "--pubkey-file",
                "keys.pub",
                "user@example.com",
                "-o",
                "BatchMode=yes",
            ])
            .unwrap();
            match cli.command {
                Cmd::Ssh(args) | Cmd::Mosh(args) => {
                    assert_eq!(args.pubkey_file.as_deref(), Some(Path::new("keys.pub")));
                    assert_eq!(args.identity, "user@example.com");
                    assert_eq!(args.args, vec!["-o".to_owned(), "BatchMode=yes".to_owned()]);
                }
                other => panic!("unexpected command {other:?}"),
            }
        }

        let cli = Cli::try_parse_from([
            "okagent",
            "ssh-copy-id",
            "--pubkey-file",
            "keys.pub",
            "example.com",
        ])
        .unwrap();
        match cli.command {
            Cmd::SshCopyId(args) => {
                assert_eq!(args.pubkey_file.as_deref(), Some(Path::new("keys.pub")));
                assert_eq!(args.identity, "example.com");
            }
            other => panic!("unexpected command {other:?}"),
        }
    }

    /// A path the shell would split or expand is single-quoted, so `eval`
    /// sets it literally.
    #[cfg(unix)]
    #[test]
    fn env_snippet_quotes_a_path_the_shell_would_change() {
        let path = "/tmp/a b;$(touch x)'q";
        let snippet = agent_env_snippet(Path::new(path), 42);
        assert!(snippet.starts_with(r"SSH_AUTH_SOCK='/tmp/a b;$(touch x)'\''q';"));
        let out = std::process::Command::new("sh")
            .arg("-c")
            .arg(format!("{snippet}printf %s \"$SSH_AUTH_SOCK\""))
            .output()
            .unwrap();
        assert_eq!(String::from_utf8(out.stdout).unwrap(), path);
    }

    /// On Windows the snippet is PowerShell, and PowerShell sets a path
    /// with quotes or `$(...)` in it literally.
    #[cfg(windows)]
    #[test]
    fn env_snippet_is_powershell_that_sets_the_path_literally() {
        assert_eq!(
            agent_env_snippet(Path::new(r"\\.\pipe\okagent-ferris"), 42),
            "$env:SSH_AUTH_SOCK = '\\\\.\\pipe\\okagent-ferris';\n$env:SSH_AGENT_PID = '42';\n"
        );
        let path = r"\\.\pipe\a b;$(Write-Output x)'q’r";
        let snippet = agent_env_snippet(Path::new(path), 42);
        let out = std::process::Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command"])
            .arg(format!(
                "{snippet}[Console]::OutputEncoding = [Text.Encoding]::UTF8; \
                 [Console]::Out.Write($env:SSH_AUTH_SOCK)"
            ))
            .output()
            .unwrap();
        assert_eq!(String::from_utf8(out.stdout).unwrap(), path);
    }

    /// A destination ssh would read as an option is refused.
    #[test]
    fn a_destination_starting_with_a_dash_is_refused() {
        let identity: Identity = "ferris@example.com".parse().unwrap();
        assert!(destination(&identity, None, Some("-oProxyCommand=x")).is_err());
        assert!(destination(&identity, None, Some("-oProxyCommand=x@host")).is_err());
        if let Ok(identity) = "-oProxyCommand=x".parse::<Identity>() {
            assert!(destination(&identity, None, None).is_err());
        }
        assert!(destination(&identity, None, Some("server-1.example")).is_ok());
    }

    #[test]
    fn host_option_separates_destination_from_identity() {
        let cli = Cli::try_parse_from([
            "okagent",
            "ssh",
            "key@identity.example",
            "--host",
            "ferris@server.example:2222",
            "-o",
            "BatchMode=yes",
        ])
        .unwrap();
        let Cmd::Ssh(args) = cli.command else {
            panic!("unexpected command");
        };
        assert_eq!(args.identity, "key@identity.example");
        assert_eq!(args.host.as_deref(), Some("ferris@server.example:2222"));
        assert_eq!(args.args, vec!["-o".to_owned(), "BatchMode=yes".to_owned()]);

        let identity: Identity = "key@identity.example".parse().unwrap();
        let (dest, port) = destination(&identity, None, args.host.as_deref()).unwrap();
        assert_eq!(dest.to_string(), "ferris@server.example");
        assert_eq!(port, Some(2222));

        // A --host without a user keeps the identity's user, but a --host
        // without a port uses the default port: the identity's :port is not
        // carried over.
        let (dest, port) = destination(&identity, None, Some("server.example")).unwrap();
        assert_eq!(dest.to_string(), "key@server.example");
        assert_eq!(port, None);
        let (dest, port) = destination(&identity, Some(2222), Some("server.example")).unwrap();
        assert_eq!(dest.to_string(), "key@server.example");
        assert_eq!(port, None);

        // Without --host the identity is the destination, port and all.
        let (dest, port) = destination(&identity, Some(2222), None).unwrap();
        assert_eq!(dest, identity);
        assert_eq!(port, Some(2222));

        // A bad port in --host is reported against the override.
        assert!(destination(&identity, None, Some("server.example:0")).is_err());

        let cli = Cli::try_parse_from([
            "okagent",
            "ssh-copy-id",
            "key@identity.example",
            "--host",
            "server.example",
        ])
        .unwrap();
        let Cmd::SshCopyId(args) = cli.command else {
            panic!("unexpected command");
        };
        assert_eq!(args.identity, "key@identity.example");
        assert_eq!(args.host.as_deref(), Some("server.example"));
    }

    #[test]
    fn pubkey_file_skips_blanks_and_comments() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keys.pub");
        let line = key("<ssh://ferris@example.com|ed25519>")
            .to_openssh()
            .unwrap();
        std::fs::write(&path, format!("# exported\n\n{line}\n")).unwrap();
        let keys = read_pubkey_file(&path).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].comment(), "<ssh://ferris@example.com|ed25519>");
        std::fs::write(&path, "not a key\n").unwrap();
        assert!(read_pubkey_file(&path).is_err());
        assert!(read_pubkey_file(&dir.path().join("missing")).is_err());
    }

    fn context(config: Config) -> Context_ {
        Context_ {
            config,
            curve: Curve::default(),
            curve_given: false,
            slot: None,
            sink: Arc::new(TtyPrompt),
            timeouts: Timeouts::default(),
            fido_device: None,
            pin_prompt: Arc::new(ChainPin::default()),
            pin_cache: Duration::ZERO,
            key_lifetime: None,
        }
    }

    #[test]
    fn ssh_accepts_additional_identities_before_the_identity() {
        for cmd in ["ssh", "mosh"] {
            let cli = Cli::try_parse_from([
                "okagent",
                cmd,
                "-i",
                "git@github.com",
                "--identity",
                "other@example.com",
                "ferris@example.com",
            ])
            .unwrap();
            match cli.command {
                Cmd::Ssh(args) | Cmd::Mosh(args) => {
                    assert_eq!(args.identity, "ferris@example.com");
                    assert_eq!(args.additional, ["git@github.com", "other@example.com"]);
                }
                other => panic!("unexpected command {other:?}"),
            }
        }
    }

    #[test]
    fn ssh_identity_flag_is_parsed_or_passed_through_after_dash_dash() {
        // The flag is recognised even after the identity.
        let cli = Cli::try_parse_from([
            "okagent",
            "ssh",
            "ferris@example.com",
            "-i",
            "git@github.com",
        ])
        .unwrap();
        let Cmd::Ssh(args) = cli.command else {
            panic!("unexpected command");
        };
        assert_eq!(args.identity, "ferris@example.com");
        assert_eq!(args.additional, ["git@github.com"]);
        assert!(args.args.is_empty());

        // After "--" a literal -i can still be handed to ssh.
        let cli = Cli::try_parse_from([
            "okagent",
            "ssh",
            "ferris@example.com",
            "--",
            "-i",
            "~/.ssh/id_rsa",
        ])
        .unwrap();
        let Cmd::Ssh(args) = cli.command else {
            panic!("unexpected command");
        };
        assert!(args.additional.is_empty());
        assert_eq!(args.args, ["-i", "~/.ssh/id_rsa"]);
    }

    #[test]
    fn agent_commands_accept_additional_identities() {
        let argvs = [
            vec![
                "okagent",
                "run",
                "-i",
                "extra@example.com",
                "base@example.com",
                "--",
                "true",
            ],
            vec![
                "okagent",
                "shell",
                "-i",
                "extra@example.com",
                "base@example.com",
            ],
            vec![
                "okagent",
                "serve",
                "-i",
                "extra@example.com",
                "base@example.com",
            ],
        ];
        for argv in argvs {
            let cli = Cli::try_parse_from(argv).unwrap();
            let (base, additional) = match cli.command {
                Cmd::Run(args) => (args.identities.base, args.identities.additional),
                Cmd::Shell(args) => (args.identities.base, args.identities.additional),
                Cmd::Serve(args) => (args.identities.base, args.identities.additional),
                other => panic!("unexpected command {other:?}"),
            };
            assert_eq!(base.identity, ["base@example.com"]);
            assert_eq!(additional, ["extra@example.com"]);
        }
    }

    #[test]
    fn load_resident_takes_a_socket() {
        let cli =
            Cli::try_parse_from(["okagent", "load-resident", "--socket", "/tmp/a.sock"]).unwrap();
        let Cmd::LoadResident(args) = cli.command else {
            panic!("unexpected command");
        };
        assert_eq!(args.socket.as_deref(), Some(Path::new("/tmp/a.sock")));
    }

    /// Commands take only the options they use.
    #[test]
    fn commands_reject_options_they_do_not_use() {
        for argv in [
            &["okagent", "devices", "--curve", "ed25519"][..],
            &["okagent", "status", "--pin-cache", "5"],
            &["okagent", "completions", "bash", "--slot", "ECC1"],
            &["okagent", "load-resident", "--key-lifetime", "5"],
            &["okagent", "load-resident", "--curve", "ed25519"],
            &["okagent", "pubkey", "--notify-command", "x"],
            &["okagent", "--curve", "ed25519", "serve"],
        ] {
            assert!(Cli::try_parse_from(argv).is_err(), "{argv:?} parsed");
        }
    }

    #[test]
    fn option_groups_parse_on_the_commands_that_use_them() {
        let cli = Cli::try_parse_from([
            "okagent",
            "load-resident",
            "--fido-device",
            "hidraw7",
            "--askpass",
            "ask",
        ])
        .unwrap();
        let (_, opts) = cli.command.options();
        assert_eq!(opts.sk.fido_device.as_deref(), Some("hidraw7"));
        assert_eq!(opts.sk.askpass.as_deref(), Some("ask"));

        let cli = Cli::try_parse_from([
            "okagent",
            "serve",
            "--curve",
            "nistp256",
            "--notify-command",
            "notify-send OnlyKey",
            "--pin-cache",
            "30",
        ])
        .unwrap();
        let (key, opts) = cli.command.options();
        assert_eq!(key.curve, Some(Curve::NistP256));
        assert_eq!(opts.notify_command.as_deref(), Some("notify-send OnlyKey"));
        assert_eq!(opts.pin_cache, Some(30));

        // Global options still go before the command.
        let cli = Cli::try_parse_from(["okagent", "-v", "--config", "c.toml", "devices"]).unwrap();
        assert_eq!(cli.verbose, 1);
        assert_eq!(cli.config.as_deref(), Some(Path::new("c.toml")));
    }

    /// `--slot` after the identity is okagent's, not passed on to ssh.
    #[test]
    fn ssh_takes_slot_after_the_identity() {
        let cli = Cli::try_parse_from([
            "okagent",
            "ssh",
            "ferris@legacy.example.com",
            "--slot",
            "ECC3",
        ])
        .unwrap();
        let Cmd::Ssh(args) = cli.command else {
            panic!("unexpected command");
        };
        assert_eq!(args.key.slot, Some("ECC3".parse().unwrap()));
        assert!(args.args.is_empty());
    }

    #[test]
    fn devices_parses_filters() {
        let cli = Cli::try_parse_from(["okagent", "devices", "--fido"]).unwrap();
        let Cmd::Devices(args) = cli.command else {
            panic!("unexpected command");
        };
        assert!(args.fido && !args.onlykey);
    }

    #[test]
    fn device_lines_show_kind_path_ids_and_name() {
        let solo = DeviceEntry {
            kind: DeviceKind::Fido,
            path: "/dev/hidraw7".into(),
            vendor_id: 0x1209,
            product_id: 0xbeee,
            manufacturer: Some("SoloKeys".into()),
            product: Some("Solo 4".into()),
            is_onlykey: false,
        };
        assert_eq!(
            format_entry(&solo, 13),
            "fido     /dev/hidraw7   1209:beee  SoloKeys Solo 4"
        );
        let onlykey_fido = DeviceEntry {
            path: "/dev/hidraw5".into(),
            vendor_id: 0x1d50,
            product_id: 0x60fc,
            manufacturer: None,
            product: None,
            is_onlykey: true,
            ..solo.clone()
        };
        assert_eq!(
            format_entry(&onlykey_fido, 12),
            "fido     /dev/hidraw5  1d50:60fc (OnlyKey FIDO interface)"
        );
        let onlykey = DeviceEntry {
            kind: DeviceKind::OnlyKey,
            product: Some("ONLYKEY".into()),
            ..onlykey_fido
        };
        assert_eq!(
            format_entry(&onlykey, 12),
            "onlykey  /dev/hidraw5  1d50:60fc  ONLYKEY"
        );
    }

    #[test]
    fn pubkey_rejects_additional_identity_flag() {
        assert!(Cli::try_parse_from(["okagent", "pubkey", "-i", "extra@example.com"]).is_err());
    }

    #[test]
    fn additional_identities_extend_the_list() {
        let config = Config::parse("[[identity]]\nname = \"config@example.com\"\n").unwrap();
        let ctx = context(config);
        let extra = ["extra@example.com".to_owned()];

        // With no positional identities, -i extends the config list.
        let entries = ctx.entries(&IdentityArgs::default(), &extra, &[]).unwrap();
        let labels: Vec<String> = entries.iter().map(KeySpec::label).collect();
        assert_eq!(
            labels,
            [
                "<ssh://config@example.com|ed25519>",
                "<ssh://extra@example.com|ed25519>"
            ]
        );

        // Positional identities replace the config list; -i is still appended.
        let base = IdentityArgs {
            identity: vec!["pos@example.com".to_owned()],
            pubkey_file: None,
        };
        let entries = ctx.entries(&base, &extra, &[]).unwrap();
        let labels: Vec<String> = entries.iter().map(KeySpec::label).collect();
        assert_eq!(
            labels,
            [
                "<ssh://pos@example.com|ed25519>",
                "<ssh://extra@example.com|ed25519>"
            ]
        );
    }

    #[test]
    fn slot_applies_to_additional_identities() {
        let ctx = Context_ {
            slot: Some("ECC3".parse().unwrap()),
            ..context(Config::default())
        };

        // With only -i, --slot is allowed and applies to the -i identity.
        let entries = ctx
            .entries(
                &IdentityArgs::default(),
                &["stored@example.com".to_owned()],
                &[],
            )
            .unwrap();
        assert_eq!(
            entries[0].kind,
            KeyKind::StoredEcc {
                slot: "ECC3".parse().unwrap(),
                curve: Curve::default()
            }
        );

        // With no command-line identities at all, --slot still errors.
        assert!(ctx.entries(&IdentityArgs::default(), &[], &[]).is_err());
    }

    #[test]
    fn no_identities_yields_an_empty_keyless_list() {
        let ctx = context(Config::default());
        let entries = ctx.entries(&IdentityArgs::default(), &[], &[]).unwrap();
        assert!(entries.is_empty());
    }
}
