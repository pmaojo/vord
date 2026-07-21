//! Composition root for local scans. `main` only parses arguments, invokes
//! the scan use-case and renders the result — a testing dead-zone by design.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use yunq_cli::output;
use yunq_infra_fs::{BaselineStore, FileAnalysisCache};
use yunq_rules_engine::{Baseline, NewCodeAnalysis, Severity};

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
        /// Disable the incremental analysis cache (.yunq-cache.json).
        #[arg(long)]
        no_cache: bool,
        /// Exit with status 3 when the quality gate fails.
        #[arg(long)]
        enforce_gate: bool,
        /// Do not read or update the New Code baseline (.yunq-baseline.json).
        #[arg(long)]
        no_baseline: bool,
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
        Command::Scan { path, format, fail_on, no_cache, enforce_gate, no_baseline } => {
            let threshold = fail_on
                .map(|raw| {
                    Severity::parse(&raw).ok_or_else(|| {
                        anyhow::anyhow!("invalid severity {raw:?} (info|minor|major|critical|blocker)")
                    })
                })
                .transpose()?;

            let cache = (!no_cache && path.is_dir())
                .then(|| std::sync::Arc::new(FileAnalysisCache::open(path.join(".yunq-cache.json"))));
            let report =
                futures::executor::block_on(yunq_cli::scan_with_cache(&path, cache.clone()))?;
            if let Some(cache) = &cache
                && let Err(e) = cache.persist()
            {
                eprintln!("warning: could not persist analysis cache: {e}");
            }

            // New Code (previous-analysis mode): classify against the stored
            // baseline, then advance the baseline to this analysis.
            let baseline_store = (!no_baseline && path.is_dir())
                .then(|| BaselineStore::new(path.join(".yunq-baseline.json")));
            let new_code = baseline_store
                .as_ref()
                .and_then(|store| store.load())
                .map(|baseline| NewCodeAnalysis::classify(&report, &baseline));
            if let Some(store) = &baseline_store
                && let Err(e) = store.save(&Baseline::from_report(&report))
            {
                eprintln!("warning: could not persist New Code baseline: {e}");
            }

            // Gate conditions may target overall (`blocker_issues`) or new
            // code (`new_blocker_issues`) measures.
            let gate = yunq_cli::default_quality_gate().evaluate(|key| {
                new_code
                    .as_ref()
                    .and_then(|nc| nc.measure(key))
                    .or_else(|| report.measure(key))
            });

            match format {
                Format::Text => print!("{}", output::render_text(&report, &gate, new_code.as_ref())),
                Format::Json => println!("{}", output::render_json(&report, &gate, new_code.as_ref())?),
            }

            let breached = threshold
                .zip(report.max_severity())
                .is_some_and(|(threshold, max)| max >= threshold);
            Ok(if breached {
                ExitCode::from(2)
            } else if enforce_gate && gate.status() == yunq_rules_engine::GateStatus::Failed {
                ExitCode::from(3)
            } else {
                ExitCode::SUCCESS
            })
        }
    }
}
