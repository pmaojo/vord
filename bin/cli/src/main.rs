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
        /// LCOV coverage report to ingest (enables the coverage gate condition).
        #[arg(long)]
        coverage: Option<PathBuf>,
        /// Git commit SHA for reporting ALM commit status.
        #[arg(long)]
        commit_sha: Option<String>,
        /// GitHub API token (defaults to GITHUB_TOKEN env var).
        #[arg(long)]
        github_token: Option<String>,
        /// GitHub repository in owner/repo format (defaults to GITHUB_REPOSITORY env var).
        #[arg(long)]
        github_repo: Option<String>,
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
        Command::Scan {
            path,
            format,
            fail_on,
            no_cache,
            enforce_gate,
            no_baseline,
            coverage,
            commit_sha,
            github_token,
            github_repo,
        } => {
            let threshold = fail_on
                .map(|raw| {
                    Severity::parse(&raw).ok_or_else(|| {
                        anyhow::anyhow!("invalid severity {raw:?} (info|minor|major|critical|blocker)")
                    })
                })
                .transpose()?;

            let cache = (!no_cache && path.is_dir())
                .then(|| std::sync::Arc::new(FileAnalysisCache::open(path.join(".yunq-cache.json"))));
            let mut report =
                futures::executor::block_on(yunq_cli::scan_with_cache(&path, cache.clone()))?;
            if let Some(lcov_path) = coverage {
                let raw = std::fs::read_to_string(&lcov_path)
                    .map_err(|e| anyhow::anyhow!("cannot read {}: {e}", lcov_path.display()))?;
                report.set_coverage(yunq_infra_fs::parse_lcov(&raw)?);
            }
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

            // Report status to GitHub if SHA and GitHub configuration/env are provided
            let target_sha = commit_sha.or_else(|| std::env::var("GITHUB_SHA").ok());
            if let Some(sha_str) = target_sha {
                if let Ok(sha) = yunq_rules_engine::CommitSha::new(&sha_str) {
                    let reporter = if let (Some(token), Some(repo)) = (github_token, github_repo) {
                        let (owner, name) = repo.split_once('/').unwrap_or(("local", &repo));
                        Some(yunq_infra_github::GitHubStatusReporter::new(token, owner, name))
                    } else {
                        yunq_infra_github::GitHubStatusReporter::from_env()
                    };

                    if let Some(reporter) = reporter {
                        use yunq_rules_engine::{AlmStatusReporter, CommitStatus, CommitStatusState};
                        let state = if gate.status() == yunq_rules_engine::GateStatus::Passed {
                            CommitStatusState::Success
                        } else {
                            CommitStatusState::Failure
                        };
                        let gate_label = match gate.status() {
                            yunq_rules_engine::GateStatus::Passed => "passed",
                            yunq_rules_engine::GateStatus::Failed => "failed",
                        };
                        let desc = format!(
                            "Gate {gate_label}: {} issues found",
                            report.issues().len()
                        );
                        let status = CommitStatus::new(state, desc);
                        if let Err(e) = futures::executor::block_on(reporter.report_commit_status(&sha, &status)) {
                            eprintln!("warning: could not report commit status to GitHub: {e}");
                        }
                    }
                }
            }

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
