use clap::Parser;
mod cli;
mod config;

use cli::Cli;
use std::io::IsTerminal;
use std::process::ExitCode;
use tracing_subscriber::EnvFilter;

fn main() -> ExitCode {
    let cli = Cli::parse();
    let level = match cli.verbose {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };
    let filter = EnvFilter::try_from_env("OKAGENT_LOG").unwrap_or_else(|_| EnvFilter::new(level));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_ansi(std::io::stderr().is_terminal())
        .with_target(false)
        .init();

    match cli::main(cli) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("okagent: {e:#}");
            ExitCode::FAILURE
        }
    }
}
