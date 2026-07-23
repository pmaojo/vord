//! Composition root for local scans. `main` only parses arguments, invokes
//! the scan use-case and renders the result — a testing dead-zone by design.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use yunq_cli::output;
use yunq_infra_fs::{BaselineStore, FileAnalysisCache};
use yunq_infra_memory::{InMemoryIssueStorage, InMemoryMetricsTracker};
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
        /// Istanbul native JSON coverage report (`coverage-final.json`) to ingest.
        #[arg(long)]
        istanbul: Option<PathBuf>,
        /// Coverage report in any supported format (LCOV, Cobertura, JaCoCo,
        /// llvm-cov, Istanbul), auto-detected from content unless
        /// `--coverage-format` is given.
        #[arg(long)]
        coverage_report: Option<PathBuf>,
        /// Format for `--coverage-report` (lcov|cobertura|jacoco|llvm-cov|istanbul).
        /// Auto-detected when omitted.
        #[arg(long)]
        coverage_format: Option<String>,
        /// Unified diff (e.g. `git diff <ref>...HEAD --unified=0`) naming the
        /// "new" lines coverage is restricted to for the coverage-on-new-code
        /// measure. Only takes effect when a coverage report is also given.
        #[arg(long)]
        coverage_diff: Option<PathBuf>,
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
        /// Print a ready-to-paste prompt handing the findings to an AI coding agent.
        #[arg(long)]
        agent_prompt: bool,
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

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli).await {
        Ok(code) => code,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> anyhow::Result<ExitCode> {
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
            istanbul,
            coverage_report,
            coverage_format,
            coverage_diff,
            junit,
            commit_sha,
            github_token,
            github_repo,
            agent_prompt,
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
                yunq_cli::scan_with_cache(&path, cache.clone()).await?;
            // `_report` variants carry per-file/per-line detail (needed for
            // coverage-on-new-code below) alongside the flat totals; the
            // detail is merged into `coverage_detail` while the totals feed
            // the plain `CoverageSummary` the rest of the pipeline already
            // understands (`coverage`/`branch_coverage` measures, gate).
            let mut coverage_summary: Option<yunq_rules_engine::CoverageSummary> = None;
            let mut coverage_detail: Option<yunq_rules_engine::CoverageReport> = None;
            let mut merge_coverage = |parsed: yunq_rules_engine::CoverageReport| -> anyhow::Result<()> {
                let summary = parsed.summary()?;
                match &mut coverage_summary {
                    Some(acc) => {
                        acc.add(summary.covered_lines(), summary.coverable_lines())?;
                        acc.add_branches(summary.covered_branches(), summary.coverable_branches())?;
                    }
                    None => coverage_summary = Some(summary),
                }
                match &mut coverage_detail {
                    Some(acc) => acc.merge(parsed),
                    None => coverage_detail = Some(parsed),
                }
                Ok(())
            };
            if let Some(path) = coverage {
                let raw = std::fs::read_to_string(&path)
                    .map_err(|e| anyhow::anyhow!("cannot read {}: {e}", path.display()))?;
                merge_coverage(yunq_infra_fs::parse_lcov_report(&raw)?)?;
            }
            if let Some(path) = cobertura {
                let raw = std::fs::read_to_string(&path)
                    .map_err(|e| anyhow::anyhow!("cannot read {}: {e}", path.display()))?;
                merge_coverage(yunq_infra_fs::parse_cobertura_report(&raw)?)?;
            }
            if let Some(path) = jacoco {
                let raw = std::fs::read_to_string(&path)
                    .map_err(|e| anyhow::anyhow!("cannot read {}: {e}", path.display()))?;
                merge_coverage(yunq_infra_fs::parse_jacoco_report(&raw)?)?;
            }
            if let Some(path) = llvm_cov {
                let raw = std::fs::read_to_string(&path)
                    .map_err(|e| anyhow::anyhow!("cannot read {}: {e}", path.display()))?;
                merge_coverage(yunq_infra_fs::parse_llvm_cov_report(&raw)?)?;
            }
            if let Some(path) = istanbul {
                let raw = std::fs::read_to_string(&path)
                    .map_err(|e| anyhow::anyhow!("cannot read {}: {e}", path.display()))?;
                merge_coverage(yunq_infra_fs::parse_istanbul_report(&raw)?)?;
            }
            if let Some(path) = coverage_report {
                let raw = std::fs::read_to_string(&path)
                    .map_err(|e| anyhow::anyhow!("cannot read {}: {e}", path.display()))?;
                let format = coverage_format
                    .map(|raw| match raw.to_ascii_lowercase().as_str() {
                        "lcov" => Ok(yunq_infra_fs::CoverageFormat::Lcov),
                        "cobertura" => Ok(yunq_infra_fs::CoverageFormat::Cobertura),
                        "jacoco" => Ok(yunq_infra_fs::CoverageFormat::Jacoco),
                        "llvm-cov" | "llvmcov" => Ok(yunq_infra_fs::CoverageFormat::LlvmCov),
                        "istanbul" => Ok(yunq_infra_fs::CoverageFormat::Istanbul),
                        other => Err(anyhow::anyhow!(
                            "unknown --coverage-format {other:?} (lcov|cobertura|jacoco|llvm-cov|istanbul)"
                        )),
                    })
                    .transpose()?;
                merge_coverage(yunq_infra_fs::parse_coverage_report(&raw, format)?)?;
            }
            if let Some(summary) = coverage_summary {
                report.set_coverage(summary);
            }
            if let Some(detail) = coverage_detail {
                report.set_coverage_report(detail);
            }
            // Coverage-on-new-code: restricts the ingested coverage detail to
            // the lines a supplied unified diff marks as added/modified.
            // Basic by design — no git invocation here, the caller supplies
            // the diff (e.g. `git diff main...HEAD --unified=0 > diff.txt`).
            let coverage_new_code = coverage_diff
                .map(|path| {
                    std::fs::read_to_string(&path)
                        .map_err(|e| anyhow::anyhow!("cannot read {}: {e}", path.display()))
                })
                .transpose()?
                .map(|raw| yunq_infra_fs::changed_lines_from_unified_diff(&raw))
                .and_then(|changed| report.coverage_on_new_code(&changed));
            let test_report = junit
                .map(|path| {
                    let raw = std::fs::read_to_string(&path)
                        .map_err(|e| anyhow::anyhow!("cannot read {}: {e}", path.display()))?;
                    yunq_infra_fs::parse_junit(&raw).map_err(anyhow::Error::from)
                })
                .transpose()?;
            if let Some(summary) = &test_report {
                report.set_test_report(summary.clone());
            }
            if let Some(cache) = &cache
                && let Err(e) = cache.persist()
            {
                eprintln!("warning: could not persist analysis cache: {e}");
            }

            // New Code (previous-analysis mode): classify against the stored
            // baseline, then advance the baseline to this analysis. Line
            // hashes are read from the real source tree so tracking survives
            // a message that drifted (e.g. a complexity count changing)
            // without the underlying issue moving or disappearing.
            let baseline_store = (!no_baseline && path.is_dir())
                .then(|| BaselineStore::new(path.join(".yunq-baseline.json")));
            let line_hashes = yunq_cli::FileLineHashes::new(&path);
            let new_code = baseline_store
                .as_ref()
                .and_then(|store| store.load())
                .map(|baseline| {
                    NewCodeAnalysis::classify_with_source(&report, &baseline, |file, line| {
                        line_hashes.hash(file, line)
                    })
                });
            if let Some(store) = &baseline_store
                && let Err(e) = store.save(&Baseline::from_report_with_source(&report, |file, line| {
                    line_hashes.hash(file, line)
                }))
            {
                eprintln!("warning: could not persist New Code baseline: {e}");
            }

            // Gate conditions may target overall (`blocker_issues`), new-issue
            // (`new_blocker_issues`) or coverage-on-new-code
            // (`coverage_new_code`) measures.
            let gate = yunq_cli::default_quality_gate().evaluate(|key| {
                if key.as_str() == "coverage_new_code" {
                    return coverage_new_code;
                }
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
                        use yunq_rules_engine::{AlmStatusReporter, AlmPullRequestReporter, CommitStatus, CommitStatusState};
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
                        let status = CommitStatus::new(state, desc.clone());
                        if let Err(e) = reporter.report_commit_status(&sha, &status).await {
                            eprintln!("warning: could not report commit status to GitHub: {e}");
                        }

                        // PR Review Comments
                        if let Ok(github_ref) = std::env::var("GITHUB_REF") {
                            // GITHUB_REF format: refs/pull/42/merge
                            if let Some(pr_str) = github_ref.strip_prefix("refs/pull/").and_then(|s| s.split('/').next()) {
                                if let Ok(pr_num) = pr_str.parse::<u32>() {
                                    if let Ok(pr_number) = yunq_rules_engine::PullRequestNumber::new(pr_num) {
                                        let new_issues = new_code.as_ref().map(|nc| nc.new_issues()).unwrap_or(&[]);

                                        if let Err(e) = reporter.report_pull_request_review(
                                            pr_number,
                                            new_issues,
                                            &desc,
                                        ).await {
                                            eprintln!("warning: could not report pull request review to GitHub: {e}");
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            match format {
                Format::Text => {
                    print!(
                        "{}",
                        output::render_text(
                            &report,
                            &gate,
                            new_code.as_ref(),
                            test_report.as_ref(),
                            coverage_new_code,
                        )
                    )
                }
                Format::Json => {
                    println!(
                        "{}",
                        output::render_json(
                            &report,
                            &gate,
                            new_code.as_ref(),
                            test_report.as_ref(),
                            coverage_new_code,
                        )?
                    )
                }
            }

            if agent_prompt {
                println!("\n{}", output::render_agent_prompt(&report, &gate, &path.display().to_string()));
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

            let path = path
                .canonicalize()
                .map_err(|e| anyhow::anyhow!("cannot read {}: {e}", path.display()))?;
            let git_root = find_git_root(&path).ok_or_else(|| {
                anyhow::anyhow!(
                    "{} is not inside a Git worktree — the Remediation Agent needs one to sandbox and verify the fix",
                    path.display()
                )
            })?;

            let source_code = std::fs::read_to_string(&path)?;
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            let language = yunq_ast::LanguageIdentifier::from_extension(ext)
                .ok_or_else(|| anyhow::anyhow!("unrecognized file extension for {}", path.display()))?;
            let rel_path = path.strip_prefix(&git_root).unwrap_or(&path).to_string_lossy().to_string();
            let source_file = yunq_ast::SourceFile::new(rel_path, source_code.clone(), language)
                .map_err(|e| anyhow::anyhow!("invalid file path: {e}"))?;

            let service = yunq_cli::default_service(InMemoryIssueStorage::new(), InMemoryMetricsTracker::new());
            let report = service.analyze_files(std::slice::from_ref(&source_file)).await?;
            let target_issue = report
                .issues()
                .iter()
                .find(|found| found.rule().as_str() == issue)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("no issue for rule '{issue}' found in {}", path.display()))?;
            let base_url = std::env::var("YUNQ_LLM_BASE_URL").unwrap_or_else(|_| "http://localhost:11434/v1".to_string());
            let api_key = std::env::var("YUNQ_LLM_API_KEY").ok();
            let model_name = model.unwrap_or_else(|| std::env::var("YUNQ_LLM_MODEL").unwrap_or_else(|_| "llama3".to_string()));
            let adapter = yunq_infra_llm::OpenAiCompatibleAdapter::new(base_url, model_name, api_key.unwrap_or_default());
            let sandbox = yunq_infra_fs::WorktreeSandbox::new(&git_root)?;
            let engine = yunq_remediation::RemediationEngine::new(adapter, sandbox);

            let verdict = engine
                .attempt_remediation(&target_issue, &path, &source_code, &service)
                .await?;

            match verdict {
                yunq_remediation::RemediationVerdict::Accepted { proposal } => {
                    println!("\n✅ Verified fix applied to {} (issue gone, no regressions):\n", path.display());
                    println!("{}", proposal.replacement_snippet);
                    println!("\nExplanation: {}", proposal.explanation);
                    Ok(ExitCode::SUCCESS)
                }
                yunq_remediation::RemediationVerdict::Rejected { reason } => {
                    eprintln!("❌ Remediation Agent could not produce a verified fix: {reason}");
                    Ok(ExitCode::FAILURE)
                }
            }
        }
    }
}

/// Walks up from `start` looking for a `.git` directory, so the Remediation
/// Agent can sandbox its verification in the real worktree the file lives
/// in rather than mutating the caller's file directly with no rollback.
fn find_git_root(start: &Path) -> Option<PathBuf> {
    let mut dir = if start.is_dir() { start.to_path_buf() } else { start.parent()?.to_path_buf() };
    loop {
        if dir.join(".git").exists() {
            return Some(dir);
        }
        if !dir.pop() {
            return None;
        }
    }
}
