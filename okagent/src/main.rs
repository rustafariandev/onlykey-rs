use clap::Parser;
mod cli;
mod config;

use cli::Cli;
use std::process::ExitCode;

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli::main(cli) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("okagent: {e:#}");
            ExitCode::FAILURE
        }
    }
}
