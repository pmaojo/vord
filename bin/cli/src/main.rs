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
        /// Cobertura XML coverage report to ingest.
        #[arg(long)]
        cobertura: Option<PathBuf>,
        /// JaCoCo XML coverage report to ingest.
        #[arg(long)]
        jacoco: Option<PathBuf>,
        /// llvm-cov JSON export coverage report to ingest.
        #[arg(long = "llvm-cov")]
        llvm_cov: Option<PathBuf>,
        /// JUnit XML test report to ingest (printed as a test summary).
        #[arg(long)]
        junit: Option<PathBuf>,
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
    /// Generate an AI remediation fix for a target issue or file.
    Fix {
        /// File path containing the issue to fix.
        path: PathBuf,
        /// Issue ID / Rule ID to propose a fix for.
        #[arg(long)]
        issue: String,
        /// Model name for OpenAI-compatible LLM endpoint (e.g. gpt-4o, ollama/llama3).
        #[arg(long)]
        model: Option<String>,
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
            cobertura,
            jacoco,
            llvm_cov,
            junit,
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

            if let Some(config) = yunq_infra_fs::YunqConfig::load_from_dir(&path) {
                if let Some(key) = &config.project.key {
                    eprintln!("📋 Loaded project config ({key})");
                }
            }

            let cache = (!no_cache && path.is_dir())
                .then(|| std::sync::Arc::new(FileAnalysisCache::open(path.join(".yunq-cache.json"))));
            let mut report =
                futures::executor::block_on(yunq_cli::scan_with_cache(&path, cache.clone()))?;
            let mut coverage_summary: Option<yunq_rules_engine::CoverageSummary> = None;
            let mut merge_coverage = |parsed: yunq_rules_engine::CoverageSummary| {
                match &mut coverage_summary {
                    Some(acc) => {
                        let _ = acc.add(parsed.covered_lines(), parsed.coverable_lines());
                    }
                    None => coverage_summary = Some(parsed),
                }
            };
            if let Some(path) = coverage {
                let raw = std::fs::read_to_string(&path)
                    .map_err(|e| anyhow::anyhow!("cannot read {}: {e}", path.display()))?;
                merge_coverage(yunq_infra_fs::parse_lcov(&raw)?);
            }
            if let Some(path) = cobertura {
                let raw = std::fs::read_to_string(&path)
                    .map_err(|e| anyhow::anyhow!("cannot read {}: {e}", path.display()))?;
                merge_coverage(yunq_infra_fs::parse_cobertura(&raw)?);
            }
            if let Some(path) = jacoco {
                let raw = std::fs::read_to_string(&path)
                    .map_err(|e| anyhow::anyhow!("cannot read {}: {e}", path.display()))?;
                merge_coverage(yunq_infra_fs::parse_jacoco(&raw)?);
            }
            if let Some(path) = llvm_cov {
                let raw = std::fs::read_to_string(&path)
                    .map_err(|e| anyhow::anyhow!("cannot read {}: {e}", path.display()))?;
                merge_coverage(yunq_infra_fs::parse_llvm_cov(&raw)?);
            }
            if let Some(summary) = coverage_summary {
                report.set_coverage(summary);
            }
            let test_report = junit
                .map(|path| {
                    let raw = std::fs::read_to_string(&path)
                        .map_err(|e| anyhow::anyhow!("cannot read {}: {e}", path.display()))?;
                    yunq_infra_fs::parse_junit(&raw).map_err(anyhow::Error::from)
                })
                .transpose()?;
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
                Format::Text => {
                    print!("{}", output::render_text(&report, &gate, new_code.as_ref(), test_report.as_ref()))
                }
                Format::Json => {
                    println!("{}", output::render_json(&report, &gate, new_code.as_ref(), test_report.as_ref())?)
                }
            }

            let breached = threshold
                .zip(report.max_severity())
                .is_some_and(|(threshold, max)| max >= threshold);

            let gate_failed = enforce_gate && gate.status() == yunq_rules_engine::GateStatus::Failed;

            if breached || gate_failed {
                Ok(ExitCode::from(3))
            } else {
                Ok(ExitCode::SUCCESS)
            }
        }
        Command::Fix { path, issue, model } => {
            println!("🤖 Requesting AI remediation for issue '{issue}' in {}...", path.display());
            let base_url = std::env::var("YUNQ_LLM_BASE_URL").unwrap_or_else(|_| "http://localhost:11434/v1".to_string());
            let api_key = std::env::var("YUNQ_LLM_API_KEY").ok();
            let model_name = model.unwrap_or_else(|| std::env::var("YUNQ_LLM_MODEL").unwrap_or_else(|_| "llama3".to_string()));

            let adapter = yunq_infra_llm::OpenAiCompatibleAdapter::new(base_url, model_name, api_key.unwrap_or_default());
            let code = std::fs::read_to_string(&path).unwrap_or_default();
            let prompt = yunq_remediation::FixPrompt {
                rule_id: issue,
                issue_message: "Static analysis rule violation".to_string(),
                file_path: path,
                start_line: 1,
                end_line: 100,
                source_snippet: code.clone(),
                full_source: code,
            };

            match futures::executor::block_on(yunq_remediation::LlmProvider::generate_fix(&adapter, &prompt)) {
                Ok(proposal) => {
                    println!("\n💡 Proposed Remediation Fix:\n");
                    println!("{}", proposal.replacement_snippet);
                    println!("\nExplanation: {}", proposal.explanation);
                    Ok(ExitCode::SUCCESS)
                }
                Err(e) => {
                    eprintln!("❌ Remediation generation failed: {e}");
                    Ok(ExitCode::FAILURE)
                }
            }
        }
    }
}
