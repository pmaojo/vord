//! Composition root for local scans. `main` only parses arguments, invokes
//! the scan use-case and renders the result — a testing dead-zone by design.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use yunq_cli::output;
use yunq_rules_engine::Severity;

#[derive(Parser)]
#[command(name = "yunq", about = "yunq static analysis", version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Analyze a directory or file and report issues.
    Scan {
        path: PathBuf,
        #[arg(long, value_enum, default_value_t = Format::Text)]
        format: Format,
        /// Exit with a non-zero status if any issue at or above this severity is found.
        #[arg(long)]
        fail_on: Option<String>,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum Format {
    Text,
    Json,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> anyhow::Result<ExitCode> {
    match cli.command {
        Command::Scan { path, format, fail_on } => {
            let threshold = fail_on
                .map(|raw| {
                    Severity::parse(&raw).ok_or_else(|| {
                        anyhow::anyhow!("invalid severity {raw:?} (info|minor|major|critical|blocker)")
                    })
                })
                .transpose()?;

            let report = futures::executor::block_on(yunq_cli::scan(&path))?;

            match format {
                Format::Text => print!("{}", output::render_text(&report)),
                Format::Json => println!("{}", output::render_json(&report)?),
            }

            let breached = threshold
                .zip(report.max_severity())
                .is_some_and(|(threshold, max)| max >= threshold);
            Ok(if breached { ExitCode::from(2) } else { ExitCode::SUCCESS })
        }
    }
}
