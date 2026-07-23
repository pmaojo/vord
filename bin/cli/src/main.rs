//! Composition root for local scans. `main` only parses arguments, invokes
//! the scan use-case and renders the result — a testing dead-zone by design.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use yunq_cli::output;
use yunq_infra_fs::{BaselineStore, FileAnalysisCache};
use yunq_rules_engine::{Baseline, NewCodeAnalysis, Severity};

mod wizard;

#[derive(Parser)]
#[command(name = "yunq", about = "yunq static analysis", version)]
struct Cli {
    /// No subcommand launches the interactive wizard in a TTY.
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Analyze a directory or file and report issues.
    // Boxed: `ScanArgs` is far larger than every other variant, so leaving it
    // inline would size the whole enum (and every `Option<Command>`) to its
    // largest member.
    Scan(Box<ScanArgs>),
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
    /// Launch the interactive wizard (same as running `yunq` with no subcommand).
    Wizard,
    /// Install the yunq GitHub Action workflow into this repository.
    Init {
        /// Write the workflow without asking for confirmation.
        #[arg(long)]
        yes: bool,
    },
}

#[derive(clap::Args)]
struct ScanArgs {
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
        None | Some(Command::Wizard) => wizard::run().await,
        Some(Command::Init { yes }) => wizard::install_ci(&std::env::current_dir()?, yes),
        Some(Command::Scan(args)) => run_scan(*args).await,
        Some(Command::Fix { path, issue, model }) => run_fix(path, issue, model).await,
    }
}

async fn run_fix(path: PathBuf, issue: String, model: Option<String>) -> anyhow::Result<ExitCode> {
    println!("🤖 Requesting AI remediation for issue '{issue}' in {}...", path.display());

    let (path, verdict) = yunq_cli::remediate_issue(&path, &issue, model).await?;

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

fn parse_fail_on_threshold(fail_on: Option<String>) -> anyhow::Result<Option<Severity>> {
    fail_on
        .map(|raw| {
            Severity::parse(&raw)
                .ok_or_else(|| anyhow::anyhow!("invalid severity {raw:?} (info|minor|major|critical|blocker)"))
        })
        .transpose()
}

/// `yunq.toml`'s `[analysis] sources`/`exclusions`, or empty when there's
/// no project config (a bare directory/file scan).
fn load_project_scope(path: &std::path::Path) -> (Vec<String>, Vec<String>) {
    yunq_infra_fs::YunqConfig::load_from_dir(path)
        .map(|config| {
            if let Some(key) = &config.project.key {
                eprintln!("📋 Loaded project config ({key})");
            }
            (config.analysis.sources.unwrap_or_default(), config.analysis.exclusions.unwrap_or_default())
        })
        .unwrap_or_default()
}

fn parse_coverage_format(raw: Option<String>) -> anyhow::Result<Option<yunq_infra_fs::CoverageFormat>> {
    raw.map(|raw| match raw.to_ascii_lowercase().as_str() {
        "lcov" => Ok(yunq_infra_fs::CoverageFormat::Lcov),
        "cobertura" => Ok(yunq_infra_fs::CoverageFormat::Cobertura),
        "jacoco" => Ok(yunq_infra_fs::CoverageFormat::Jacoco),
        "llvm-cov" | "llvmcov" => Ok(yunq_infra_fs::CoverageFormat::LlvmCov),
        "istanbul" => Ok(yunq_infra_fs::CoverageFormat::Istanbul),
        other => {
            Err(anyhow::anyhow!("unknown --coverage-format {other:?} (lcov|cobertura|jacoco|llvm-cov|istanbul)"))
        }
    })
    .transpose()
}

fn read_report_file(path: &std::path::Path) -> anyhow::Result<String> {
    std::fs::read_to_string(path).map_err(|e| anyhow::anyhow!("cannot read {}: {e}", path.display()))
}

/// Merges every coverage report format the CLI accepts (LCOV, Cobertura,
/// JaCoCo, llvm-cov, Istanbul, or an auto-detected `--coverage-report`)
/// into one running total plus per-file detail. `_report` parse functions
/// carry the per-file/per-line detail needed for coverage-on-new-code
/// alongside the flat totals; the detail is merged into `detail` while the
/// totals feed the plain `CoverageSummary` the rest of the pipeline
/// already understands (`coverage`/`branch_coverage` measures, gate).
#[derive(Default)]
struct CoverageAccumulator {
    summary: Option<yunq_rules_engine::CoverageSummary>,
    detail: Option<yunq_rules_engine::CoverageReport>,
}

impl CoverageAccumulator {
    fn merge(&mut self, parsed: yunq_rules_engine::CoverageReport) -> anyhow::Result<()> {
        let summary = parsed.summary()?;
        match &mut self.summary {
            Some(acc) => {
                acc.add(summary.covered_lines(), summary.coverable_lines())?;
                acc.add_branches(summary.covered_branches(), summary.coverable_branches())?;
            }
            None => self.summary = Some(summary),
        }
        match &mut self.detail {
            Some(acc) => acc.merge(parsed),
            None => self.detail = Some(parsed),
        }
        Ok(())
    }

    fn apply_to(self, report: &mut yunq_rules_engine::AnalysisReport) {
        if let Some(summary) = self.summary {
            report.set_coverage(summary);
        }
        if let Some(detail) = self.detail {
            report.set_coverage_report(detail);
        }
    }
}

fn ingest_coverage(args: &ScanArgs) -> anyhow::Result<CoverageAccumulator> {
    let mut acc = CoverageAccumulator::default();
    if let Some(path) = &args.coverage {
        acc.merge(yunq_infra_fs::parse_lcov_report(&read_report_file(path)?)?)?;
    }
    if let Some(path) = &args.cobertura {
        acc.merge(yunq_infra_fs::parse_cobertura_report(&read_report_file(path)?)?)?;
    }
    if let Some(path) = &args.jacoco {
        acc.merge(yunq_infra_fs::parse_jacoco_report(&read_report_file(path)?)?)?;
    }
    if let Some(path) = &args.llvm_cov {
        acc.merge(yunq_infra_fs::parse_llvm_cov_report(&read_report_file(path)?)?)?;
    }
    if let Some(path) = &args.istanbul {
        acc.merge(yunq_infra_fs::parse_istanbul_report(&read_report_file(path)?)?)?;
    }
    if let Some(path) = &args.coverage_report {
        let raw = read_report_file(path)?;
        let format = parse_coverage_format(args.coverage_format.clone())?;
        acc.merge(yunq_infra_fs::parse_coverage_report(&raw, format)?)?;
    }
    Ok(acc)
}

/// Coverage-on-new-code: restricts the ingested coverage detail to the
/// lines a supplied unified diff marks as added/modified. Basic by
/// design — no git invocation here, the caller supplies the diff (e.g.
/// `git diff main...HEAD --unified=0 > diff.txt`).
fn coverage_new_code_measure(
    coverage_diff: Option<PathBuf>,
    report: &yunq_rules_engine::AnalysisReport,
) -> anyhow::Result<Option<f64>> {
    Ok(coverage_diff
        .map(|path| read_report_file(&path))
        .transpose()?
        .map(|raw| yunq_infra_fs::changed_lines_from_unified_diff(&raw))
        .and_then(|changed| report.coverage_on_new_code(&changed)))
}

fn load_test_report(junit: Option<PathBuf>) -> anyhow::Result<Option<yunq_rules_engine::TestReportSummary>> {
    junit
        .map(|path| yunq_infra_fs::parse_junit(&read_report_file(&path)?).map_err(anyhow::Error::from))
        .transpose()
}

/// New Code (previous-analysis mode): classifies against the stored
/// baseline, then advances the baseline to this analysis. Line hashes are
/// read from the real source tree so tracking survives a message that
/// drifted (e.g. a complexity count changing) without the underlying
/// issue moving or disappearing.
fn classify_new_code(
    path: &std::path::Path,
    no_baseline: bool,
    report: &yunq_rules_engine::AnalysisReport,
) -> Option<NewCodeAnalysis> {
    let baseline_store =
        (!no_baseline && path.is_dir()).then(|| BaselineStore::new(path.join(".yunq-baseline.json")))?;
    let line_hashes = yunq_cli::FileLineHashes::new(path);
    let hash_fn = |file: &str, line: u32| line_hashes.hash(file, line);
    let new_code = baseline_store
        .load()
        .map(|baseline| NewCodeAnalysis::classify_with_source(report, &baseline, hash_fn));
    if let Err(e) = baseline_store.save(&Baseline::from_report_with_source(report, hash_fn)) {
        eprintln!("warning: could not persist New Code baseline: {e}");
    }
    new_code
}

async fn report_pull_request_review(
    reporter: &yunq_infra_github::GitHubStatusReporter,
    new_code: Option<&NewCodeAnalysis>,
    desc: &str,
) {
    use yunq_rules_engine::AlmPullRequestReporter;
    let Ok(github_ref) = std::env::var("GITHUB_REF") else { return };
    // GITHUB_REF format: refs/pull/42/merge
    let Some(pr_str) = github_ref.strip_prefix("refs/pull/").and_then(|s| s.split('/').next()) else { return };
    let Ok(pr_num) = pr_str.parse::<u32>() else { return };
    let Ok(pr_number) = yunq_rules_engine::PullRequestNumber::new(pr_num) else { return };

    let new_issues = new_code.map(|nc| nc.new_issues()).unwrap_or(&[]);
    if let Err(e) = reporter.report_pull_request_review(pr_number, new_issues, desc).await {
        eprintln!("warning: could not report pull request review to GitHub: {e}");
    }
}

/// Reports the scan's commit status (and, on a PR ref, a review) to GitHub
/// when a commit SHA and GitHub credentials/env are available.
async fn report_to_github(
    args: &ScanArgs,
    report: &yunq_rules_engine::AnalysisReport,
    gate: &yunq_rules_engine::GateEvaluation,
    new_code: Option<&NewCodeAnalysis>,
) {
    use yunq_rules_engine::{AlmStatusReporter, CommitStatus, CommitStatusState};

    let Some(sha_str) = args.commit_sha.clone().or_else(|| std::env::var("GITHUB_SHA").ok()) else { return };
    let Ok(sha) = yunq_rules_engine::CommitSha::new(&sha_str) else { return };

    let reporter = match (&args.github_token, &args.github_repo) {
        (Some(token), Some(repo)) => {
            let (owner, name) = repo.split_once('/').unwrap_or(("local", repo));
            Some(yunq_infra_github::GitHubStatusReporter::new(token.clone(), owner, name))
        }
        _ => yunq_infra_github::GitHubStatusReporter::from_env(),
    };
    let Some(reporter) = reporter else { return };

    let state = if gate.status() == yunq_rules_engine::GateStatus::Passed {
        CommitStatusState::Success
    } else {
        CommitStatusState::Failure
    };
    let gate_label = match gate.status() {
        yunq_rules_engine::GateStatus::Passed => "passed",
        yunq_rules_engine::GateStatus::Failed => "failed",
    };
    let desc = format!("Gate {gate_label}: {} issues found", report.issues().len());
    let status = CommitStatus::new(state, desc.clone());
    if let Err(e) = reporter.report_commit_status(&sha, &status).await {
        eprintln!("warning: could not report commit status to GitHub: {e}");
    }

    report_pull_request_review(&reporter, new_code, &desc).await;
}

fn render_output(
    args: &ScanArgs,
    report: &yunq_rules_engine::AnalysisReport,
    gate: &yunq_rules_engine::GateEvaluation,
    new_code: Option<&NewCodeAnalysis>,
    test_report: Option<&yunq_rules_engine::TestReportSummary>,
    coverage_new_code: Option<f64>,
) -> anyhow::Result<()> {
    match args.format {
        Format::Text => {
            print!("{}", output::render_text(report, gate, new_code, test_report, coverage_new_code))
        }
        Format::Json => {
            println!("{}", output::render_json(report, gate, new_code, test_report, coverage_new_code)?)
        }
    }
    if args.agent_prompt {
        println!("\n{}", output::render_agent_prompt(report, gate, &args.path.display().to_string()));
    }
    Ok(())
}

fn exit_code(
    threshold: Option<Severity>,
    report: &yunq_rules_engine::AnalysisReport,
    enforce_gate: bool,
    gate: &yunq_rules_engine::GateEvaluation,
) -> ExitCode {
    let breached = threshold.zip(report.max_severity()).is_some_and(|(threshold, max)| max >= threshold);
    let gate_failed = enforce_gate && gate.status() == yunq_rules_engine::GateStatus::Failed;
    if breached || gate_failed { ExitCode::from(3) } else { ExitCode::SUCCESS }
}

async fn run_scan(args: ScanArgs) -> anyhow::Result<ExitCode> {
    let threshold = parse_fail_on_threshold(args.fail_on.clone())?;
    let (source_dirs, exclusions) = load_project_scope(&args.path);

    let cache = (!args.no_cache && args.path.is_dir())
        .then(|| std::sync::Arc::new(FileAnalysisCache::open(args.path.join(".yunq-cache.json"))));
    let mut report =
        yunq_cli::scan_with_project_config(&args.path, cache.clone(), &source_dirs, &exclusions).await?;

    ingest_coverage(&args)?.apply_to(&mut report);
    let coverage_new_code = coverage_new_code_measure(args.coverage_diff.clone(), &report)?;

    let test_report = load_test_report(args.junit.clone())?;
    if let Some(summary) = &test_report {
        report.set_test_report(summary.clone());
    }
    if let Some(cache) = &cache
        && let Err(e) = cache.persist()
    {
        eprintln!("warning: could not persist analysis cache: {e}");
    }

    let new_code = classify_new_code(&args.path, args.no_baseline, &report);

    // Gate conditions may target overall (`blocker_issues`), new-issue
    // (`new_blocker_issues`) or coverage-on-new-code (`coverage_new_code`)
    // measures.
    let gate = yunq_cli::default_quality_gate().evaluate(|key| {
        if key.as_str() == "coverage_new_code" {
            return coverage_new_code;
        }
        new_code.as_ref().and_then(|nc| nc.measure(key)).or_else(|| report.measure(key))
    });

    report_to_github(&args, &report, &gate, new_code.as_ref()).await;
    render_output(&args, &report, &gate, new_code.as_ref(), test_report.as_ref(), coverage_new_code)?;

    Ok(exit_code(threshold, &report, args.enforce_gate, &gate))
}
