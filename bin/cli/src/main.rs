//! Composition root for local scans. `main` only parses arguments, invokes
//! the scan use-case and renders the result — a testing dead-zone by design.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use yunq_cli::output;
use yunq_infra_fs::{BaselineStore, FileAnalysisCache};
use yunq_rules_engine::{Baseline, NewCodeAnalysis, Severity};

mod blame;
mod ci_detect;
mod crap;
mod hook_install;
mod monorepo_scan;
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
    /// Agentic guardrail: gate an autonomous agent's writes against the
    /// Agent Permission Policy (`yunq-policy.toml`).
    Hook {
        #[command(subcommand)]
        action: HookAction,
    },
    /// yunq's own coding agent: edits this repository under the same policy
    /// `yunq hook` enforces on third-party agents, and reports a task
    /// complete only when the analyzer agrees.
    Agent {
        #[command(subcommand)]
        action: AgentAction,
    },
}

#[derive(Subcommand)]
enum AgentAction {
    /// Run one headless session against a task. Exits 0 (the analyzer agrees),
    /// 3 (incomplete), 4 (budget exhausted), 5 (circuit breaker tripped),
    /// 6 (the agent looped) or 1 (yunq itself failed).
    Run {
        /// What the agent should do.
        #[arg(long)]
        task: String,
        /// Path the analyzer takes its baseline over and re-scans to decide
        /// completion.
        #[arg(long, default_value = ".")]
        scope: String,
        /// A rule the task must eliminate; the task cannot complete while it
        /// still fires anywhere in scope.
        #[arg(long)]
        rule: Option<String>,
        /// Model turns this run may take (overrides `yunq.toml`'s `[agent]`).
        #[arg(long)]
        max_turns: Option<u32>,
        /// Tokens this run may spend (overrides `yunq.toml`'s `[agent]`).
        #[arg(long)]
        max_tokens: Option<u64>,
        /// Model name, overriding the provider's configured default.
        #[arg(long)]
        model: Option<String>,
    },
    /// Wait out the late-feedback window on a pull request: poll with
    /// backoff, collect one review batch as one batch, and report quiet, new
    /// feedback, a bot all-clear, or inconclusive. Exits 0 (quiet or
    /// all-clear), 3 (new feedback to triage) or 1 (could not look).
    WatchPr {
        /// Pull request number.
        #[arg(long)]
        pr: u64,
        /// `owner/repo`; defaults to `GITHUB_REPOSITORY`.
        #[arg(long)]
        repo: Option<String>,
        /// Total seconds to keep watching before calling it quiet.
        #[arg(long)]
        window_secs: Option<u64>,
    },
}

#[derive(Subcommand)]
enum HookAction {
    /// Claude Code hook entry point. Reads the hook payload on stdin and
    /// writes its verdict as JSON on stdout — not run by hand; `yunq hook
    /// install` wires it into `.claude/settings.json`.
    ClaudeCode,
    /// Judge one file against the policy. The host-agnostic entry point, for
    /// hosts without file-write hooks (Codex CLI), `pre-commit`, and CI.
    /// Exits 0 (allowed), 2 (denied by policy) or 1 (yunq itself failed).
    Check {
        /// File to judge, as the agent would write it.
        file: PathBuf,
        /// `text` prints prose to stderr (the default); `json` prints the structured verdict to
        /// stdout for automated callers.
        #[arg(long, value_enum, default_value = "text")]
        format: Format,
    },
    /// Wire the guardrail into this repository: write `yunq-policy.toml` and
    /// merge the hooks into `.claude/settings.json`.
    Install {
        /// Override the command the hooks invoke (defaults to `yunq hook
        /// claude-code`, which must be on PATH).
        #[arg(long)]
        command: Option<String>,
    },
    /// Clear the circuit breaker's persisted per-rule failure counts — the human-intervention
    /// step after a trip. Review what the agent could not resolve, then run this before letting
    /// it continue.
    ResetCircuitBreaker,
    /// Approve an escalated write after human review — the token comes from the denial text or
    /// `hook check --format json`'s `escalation_token` field. Single-use: it authorizes exactly
    /// one retry of the identical write, not a standing exemption for the rule.
    Approve {
        /// The escalation token to approve.
        token: String,
    },
    /// Clear the loop alarm's persisted "last write" streak — the human-intervention step after
    /// a trip, same shape as `reset-circuit-breaker`.
    ResetLoopGuard,
    /// Show the audit log of every non-silent verdict this guardrail has issued
    /// (`.yunq-audit.jsonl`).
    Audit {
        /// Show only the most recent N entries.
        #[arg(long, default_value_t = 20)]
        limit: usize,
        /// `text` prints one line per entry (the default); `json` prints the raw entries as a
        /// JSON array.
        #[arg(long, value_enum, default_value = "text")]
        format: Format,
    },
}

#[derive(clap::Args)]
struct CoverageArgs {
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
}

#[derive(clap::Args)]
struct GithubArgs {
    /// Git commit SHA for reporting ALM commit status (auto-detected from
    /// CI env vars — GitHub Actions/GitLab CI — when omitted).
    #[arg(long)]
    commit_sha: Option<String>,
    /// GitHub API token (defaults to GITHUB_TOKEN env var).
    #[arg(long)]
    github_token: Option<String>,
    /// GitHub repository in owner/repo format (defaults to GITHUB_REPOSITORY
    /// env var, or CI auto-detection).
    #[arg(long)]
    github_repo: Option<String>,
    /// Pull/merge request number this analysis is for — marks this as a PR
    /// analysis for ALM status reporting (auto-detected from CI env vars,
    /// e.g. GitHub Actions' `GITHUB_REF`/event payload or GitLab CI's
    /// `CI_MERGE_REQUEST_IID`, when omitted).
    #[arg(long)]
    pr: Option<u32>,
}

/// Reports produced by *other* tools that this scan folds in. Grouped
/// because they share one shape — an optional path to a file yunq parses
/// but never generates — and one lifecycle: read after the analysis, merged
/// into the same report, surfaced through the same gate. `CoverageArgs` is
/// the fourth member of this family, kept separate only because coverage
/// alone spans eight flags.
#[derive(clap::Args)]
struct ReportArgs {
    /// JUnit XML test report to ingest (printed as a test summary).
    #[arg(long)]
    junit: Option<PathBuf>,
    /// Mutation-testing report to ingest (Stryker's Mutation Testing
    /// Elements JSON schema — StrykerJS, Stryker.NET, or Infection exported
    /// in that format). Enables the `mutation_score` measure and gate
    /// condition; yunq runs no mutants itself, it only aggregates the
    /// verdicts another tool already produced.
    #[arg(long = "mutation-report")]
    mutation_report: Option<PathBuf>,
    /// SARIF 2.x report from another analyzer (ruff, ESLint, clippy, gosec,
    /// bandit, semgrep, CodeQL, …) whose findings are merged into this
    /// scan's issues — they count toward the severity totals and the
    /// quality gate exactly like yunq's own. Repeatable.
    #[arg(long, value_name = "PATH")]
    sarif: Vec<PathBuf>,
}

/// Which project(s) the scanned path resolves to, and what to label the
/// results with. These three decide the *identity* of what is being
/// measured — `--monorepo` because it turns one path into many projects,
/// each of which then needs its own key and branch the same way.
#[derive(clap::Args)]
struct ProjectScopeArgs {
    /// Explicit project identifier (defaults to yunq.toml's `[project] key`,
    /// then the scanned directory's name).
    #[arg(long)]
    project: Option<String>,
    /// Branch this analysis is attached to (auto-detected from CI env vars
    /// when omitted).
    #[arg(long)]
    branch: Option<String>,
    /// Treat `path` as a monorepo root: discover every yunq.toml-configured
    /// project under it and scan each independently, reporting results per
    /// project instead of merging them into one report.
    #[arg(long)]
    monorepo: bool,
}

/// Where the findings go once the analysis is done — none of these change
/// what gets analyzed or whether the scan passes, only what is emitted.
#[derive(clap::Args)]
struct OutputArgs {
    #[arg(long, value_enum, default_value_t = Format::Text)]
    format: Format,
    /// Print a ready-to-paste prompt handing the findings to an AI coding agent.
    #[arg(long)]
    agent_prompt: bool,
    /// Capture per-line SCM blame (author/commit) for files with issues and
    /// write it as JSON to this path — consumable by anything that wants to
    /// show "who introduced this" alongside an issue.
    #[arg(long)]
    blame_output: Option<PathBuf>,
}

#[derive(clap::Args)]
struct ScanArgs {
    path: PathBuf,
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
    #[command(flatten)]
    coverage: CoverageArgs,
    #[command(flatten)]
    reports: ReportArgs,
    #[command(flatten)]
    github: GithubArgs,
    #[command(flatten)]
    scope: ProjectScopeArgs,
    #[command(flatten)]
    output: OutputArgs,
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
        Some(Command::Hook { action }) => run_hook(action).await,
        Some(Command::Agent { action }) => run_agent(action).await,
    }
}

/// `yunq agent`'s entry points. Unlike the hook, these do **not** fail open:
/// a run that could not judge, could not analyse or could not reach the model
/// exits 1, distinct from every verdict, because an agent that reports
/// success when it could not check is worse than one that reports nothing.
async fn run_agent(action: AgentAction) -> anyhow::Result<ExitCode> {
    let root = std::env::current_dir()?;
    match action {
        AgentAction::Run { task, scope, rule, max_turns, max_tokens, model } => {
            let args = yunq_cli::agent::AgentArgs { task, scope, rule, max_turns, max_tokens, model };
            let outcome = yunq_cli::agent::run(&root, args).await?;
            yunq_cli::agent::report(&outcome);
            Ok(ExitCode::from(outcome.exit_code()))
        }
        AgentAction::WatchPr { pr, repo, window_secs } => {
            let outcome = yunq_cli::agent::watch_pull_request(repo, pr, window_secs).await?;
            yunq_cli::agent::report_feedback(&outcome);
            Ok(ExitCode::from(outcome.exit_code()))
        }
    }
}

/// The guardrail's three entry points. `ClaudeCode` deliberately swallows
/// its own errors into a success exit inside `run_claude_code` (failing open
/// keeps a yunq bug from wedging the agent loop); the other two report
/// errors normally through `main`'s handler.
async fn run_hook(action: HookAction) -> anyhow::Result<ExitCode> {
    match action {
        HookAction::ClaudeCode => yunq_cli::hook::run_claude_code().await,
        HookAction::Check { file, format } => {
            let format = match format {
                Format::Text => yunq_cli::hook::HookOutputFormat::Text,
                Format::Json => yunq_cli::hook::HookOutputFormat::Json,
            };
            yunq_cli::hook::run_check(file, format).await
        }
        HookAction::Install { command } => {
            let root = std::env::current_dir()?;
            let command = command.unwrap_or_else(|| hook_install::DEFAULT_HOOK_COMMAND.to_string());
            hook_install::install(&root, &command)?;
            Ok(ExitCode::SUCCESS)
        }
        HookAction::ResetCircuitBreaker => {
            let root = std::env::current_dir()?;
            yunq_cli::hook::reset_circuit_breaker(&root)?;
            println!("yunq: circuit breaker state cleared.");
            Ok(ExitCode::SUCCESS)
        }
        HookAction::Approve { token } => {
            let root = std::env::current_dir()?;
            yunq_cli::hook::approve_escalation(&root, &token)?;
            println!("yunq: escalation token {token} approved — the agent may retry the identical write once.");
            Ok(ExitCode::SUCCESS)
        }
        HookAction::ResetLoopGuard => {
            let root = std::env::current_dir()?;
            yunq_cli::hook::reset_loop_guard(&root)?;
            println!("yunq: loop alarm state cleared.");
            Ok(ExitCode::SUCCESS)
        }
        HookAction::Audit { limit, format } => {
            let root = std::env::current_dir()?;
            let entries = yunq_cli::hook::read_audit_log(&root, Some(limit));
            match format {
                Format::Text => print!("{}", yunq_cli::hook::render_audit_text(&entries)),
                Format::Json => println!("{}", serde_json::to_string_pretty(&entries)?),
            }
            Ok(ExitCode::SUCCESS)
        }
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

/// `yunq.toml`'s `[analysis] sources`/`exclusions`/`[project] key`, or all
/// empty when there's no project config (a bare directory/file scan).
fn load_project_scope(
    path: &std::path::Path,
) -> (
    Vec<String>,
    Vec<String>,
    Option<String>,
    yunq_infra_fs::DuplicationSettings,
    yunq_infra_fs::ArchitectureSettings,
) {
    yunq_infra_fs::YunqConfig::load_from_dir(path)
        .map(|config| {
            if let Some(key) = &config.project.key {
                eprintln!("📋 Loaded project config ({key})");
            }
            (
                config.analysis.sources.unwrap_or_default(),
                config.analysis.exclusions.unwrap_or_default(),
                config.project.key,
                config.duplication,
                config.architecture,
            )
        })
        .unwrap_or_default()
}

/// Resolved scan identity/target: `--project`/`--branch`/`--pr`/
/// `--commit-sha`/`--github-repo`, each an explicit flag if given, else the
/// CI-auto-detected value, else (for `project` only) a directory-name
/// fallback. Threaded through both ALM status reporting and the rendered
/// output's `context` so a downstream consumer sees the same identity the
/// scan itself used.
struct ResolvedContext {
    project: Option<String>,
    branch: Option<String>,
    pr: Option<u32>,
    commit_sha: Option<String>,
    github_repo: Option<String>,
}

impl ResolvedContext {
    fn to_dto(&self) -> output::ScanContextDto {
        output::ScanContextDto { project: self.project.clone(), branch: self.branch.clone(), pull_request: self.pr }
    }
}

/// Reads real CI environment variables (`GITHUB_ACTIONS`/`GITLAB_CI`/...
/// and friends) into a [`ci_detect::CiContext`] — the one place `main`
/// touches `std::env` for CI detection; [`ci_detect::detect_ci_context`]
/// itself is pure and injected with this closure so it stays unit-testable.
/// Also covers the one CI signal that needs a file read rather than an env
/// var: GitHub Actions' `GITHUB_EVENT_PATH` payload, consulted only when
/// `GITHUB_REF` didn't already yield a PR number.
fn resolve_ci_context() -> ci_detect::CiContext {
    let env_lookup = |key: &str| std::env::var(key).ok();
    let mut ctx = ci_detect::detect_ci_context(&env_lookup);
    if ctx.pr.is_none()
        && ctx.provider == Some(ci_detect::CiProvider::GithubActions)
        && let Ok(event_path) = std::env::var("GITHUB_EVENT_PATH")
        && let Ok(raw) = std::fs::read_to_string(event_path)
    {
        ctx.pr = ci_detect::parse_pr_number_from_github_event(&raw);
    }
    ctx
}

/// Combines explicit `--project`/`--branch`/`--pr`/`--commit-sha`/
/// `--github-repo` flags with CI auto-detection (explicit always wins) and
/// `yunq.toml`'s `[project] key` / the scan path's directory name as the
/// last-resort project fallback.
fn resolve_context(args: &ScanArgs, config_project_key: Option<String>, ci: &ci_detect::CiContext) -> ResolvedContext {
    let project = args
        .scope
        .project
        .clone()
        .or(config_project_key)
        .or_else(|| args.path.file_name().map(|n| n.to_string_lossy().to_string()));
    ResolvedContext {
        project,
        branch: args.scope.branch.clone().or_else(|| ci.branch.clone()),
        pr: args.github.pr.or(ci.pr),
        commit_sha: args.github.commit_sha.clone().or_else(|| ci.commit_sha.clone()),
        github_repo: args.github.github_repo.clone().or_else(|| ci.github_repo.clone()),
    }
}

/// Builds the GitHub status reporter from explicit `--github-token`/
/// `--github-repo` (falling back to `context`'s CI-resolved repo) or the
/// environment (`GitHubStatusReporter::from_env`) — shared by the
/// single-project and `--monorepo` reporting paths so there's exactly one
/// place that decides how a reporter gets built.
fn github_reporter(
    args: &ScanArgs,
    context: &ResolvedContext,
) -> Option<yunq_infra_github::GitHubStatusReporter> {
    match (&args.github.github_token, &context.github_repo) {
        (Some(token), Some(repo)) => {
            let (owner, name) = repo.split_once('/').unwrap_or(("local", repo));
            Some(yunq_infra_github::GitHubStatusReporter::new(token.clone(), owner, name))
        }
        _ => yunq_infra_github::GitHubStatusReporter::from_env(),
    }
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
    if let Some(path) = &args.coverage.coverage {
        acc.merge(yunq_infra_fs::parse_lcov_report(&read_report_file(path)?)?)?;
    }
    if let Some(path) = &args.coverage.cobertura {
        acc.merge(yunq_infra_fs::parse_cobertura_report(&read_report_file(path)?)?)?;
    }
    if let Some(path) = &args.coverage.jacoco {
        acc.merge(yunq_infra_fs::parse_jacoco_report(&read_report_file(path)?)?)?;
    }
    if let Some(path) = &args.coverage.llvm_cov {
        acc.merge(yunq_infra_fs::parse_llvm_cov_report(&read_report_file(path)?)?)?;
    }
    if let Some(path) = &args.coverage.istanbul {
        acc.merge(yunq_infra_fs::parse_istanbul_report(&read_report_file(path)?)?)?;
    }
    if let Some(path) = &args.coverage.coverage_report {
        let raw = read_report_file(path)?;
        let format = parse_coverage_format(args.coverage.coverage_format.clone())?;
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

/// `--sarif`: merges another analyzer's findings into this scan's report.
/// One importer, every tool that speaks SARIF — the coverage of ruff,
/// ESLint, clippy, gosec, bandit, semgrep and CodeQL without yunq
/// implementing any of their rules.
///
/// Paths in the report are re-based onto the scan root so imported issues
/// key by the same relative path yunq's own issues do (`Issue::file()`),
/// which is what lets the two sets coexist in one report, one gate and one
/// New Code baseline.
fn ingest_sarif(args: &ScanArgs, report: &mut yunq_rules_engine::AnalysisReport) -> anyhow::Result<()> {
    if args.reports.sarif.is_empty() {
        return Ok(());
    }

    // Report URIs are relative to the project root, which for a single-file
    // scan is the file's directory rather than the file itself.
    let root = if args.path.is_dir() {
        args.path.clone()
    } else {
        args.path.parent().unwrap_or(std::path::Path::new(".")).to_path_buf()
    };

    let (mut imported, mut skipped) = (0usize, 0usize);
    let mut tools: Vec<String> = Vec::new();
    for path in &args.reports.sarif {
        let raw = read_report_file(path)?;
        let import = yunq_infra_fs::parse_sarif_relative_to(&raw, &root)
            .map_err(|e| anyhow::anyhow!("cannot import SARIF from {}: {e}", path.display()))?;
        imported += import.issues.len();
        skipped += import.skipped;
        for tool in import.tools {
            if !tools.contains(&tool) {
                tools.push(tool);
            }
        }
        report.add_external_issues(import.issues);
    }

    let tools = if tools.is_empty() { "unknown tool".to_string() } else { tools.join(", ") };
    println!(
        "📥 Imported {imported} issue(s) from {} SARIF report(s) [{tools}]{}",
        args.reports.sarif.len(),
        if skipped > 0 { format!(" — {skipped} result(s) skipped (passing, suppressed or location-less)") } else { String::new() }
    );
    Ok(())
}

fn load_test_report(junit: Option<PathBuf>) -> anyhow::Result<Option<yunq_rules_engine::TestReportSummary>> {
    junit
        .map(|path| yunq_infra_fs::parse_junit(&read_report_file(&path)?).map_err(anyhow::Error::from))
        .transpose()
}

fn load_mutation_report(
    mutation_report: Option<PathBuf>,
) -> anyhow::Result<Option<yunq_rules_engine::MutationSummary>> {
    mutation_report
        .map(|path| yunq_infra_fs::parse_mutation_report(&read_report_file(&path)?).map_err(anyhow::Error::from))
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

/// Posts a PR review comment summarizing new issues, when `pr` (explicit
/// `--pr`, or CI-auto-detected — see [`resolve_context`]) is known. Used to
/// hand-derive the PR number from `GITHUB_REF`/`GITHUB_EVENT_PATH` inline
/// here; that detection now lives in `ci_detect` so it's covered by unit
/// tests instead of only exercised by a real GitHub Actions run.
async fn report_pull_request_review(
    reporter: &yunq_infra_github::GitHubStatusReporter,
    pr: Option<u32>,
    new_code: Option<&NewCodeAnalysis>,
    desc: &str,
) {
    use yunq_rules_engine::AlmPullRequestReporter;
    let Some(pr_num) = pr else { return };
    let Ok(pr_number) = yunq_rules_engine::PullRequestNumber::new(pr_num) else { return };

    let new_issues = new_code.map(|nc| nc.new_issues()).unwrap_or(&[]);
    if let Err(e) = reporter.report_pull_request_review(pr_number, new_issues, desc).await {
        eprintln!("warning: could not report pull request review to GitHub: {e}");
    }
}

/// Reports the scan's commit status (and, on a PR analysis, a review) to
/// GitHub when a commit SHA and GitHub credentials/env are available. The
/// commit SHA, PR number and repo slug all come from `context`
/// ([`resolve_context`]) — explicit `--commit-sha`/`--pr`/`--github-repo`
/// flags win, otherwise CI auto-detection fills them in.
async fn report_to_github(
    args: &ScanArgs,
    context: &ResolvedContext,
    report: &yunq_rules_engine::AnalysisReport,
    gate: &yunq_rules_engine::GateEvaluation,
    new_code: Option<&NewCodeAnalysis>,
) {
    use yunq_rules_engine::{AlmStatusReporter, CommitStatus, CommitStatusState};

    let Some(sha_str) = &context.commit_sha else { return };
    let Ok(sha) = yunq_rules_engine::CommitSha::new(sha_str) else { return };

    let Some(reporter) = github_reporter(args, context) else { return };

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

    report_pull_request_review(&reporter, context.pr, new_code, &desc).await;
}

fn render_output(
    args: &ScanArgs,
    report: &yunq_rules_engine::AnalysisReport,
    gate: &yunq_rules_engine::GateEvaluation,
    new_code: Option<&NewCodeAnalysis>,
    test_report: Option<&yunq_rules_engine::TestReportSummary>,
    coverage_new_code: Option<f64>,
    context: &output::ScanContextDto,
) -> anyhow::Result<()> {
    match args.output.format {
        Format::Text => {
            print!("{}", output::render_text(report, gate, new_code, test_report, coverage_new_code, context))
        }
        Format::Json => {
            println!(
                "{}",
                output::render_json(report, gate, new_code, test_report, coverage_new_code, context.clone())?
            )
        }
    }
    if args.output.agent_prompt {
        println!("\n{}", output::render_agent_prompt(report, gate, &args.path.display().to_string()));
    }
    Ok(())
}

/// `--blame-output`: captures per-line SCM blame for every file the scan
/// found an issue in and writes it as JSON to the given path. Best-effort —
/// a scan target that isn't inside a Git repository (or has no `git`
/// binary available) warns and is otherwise a no-op rather than failing the
/// whole scan, matching the cache/baseline persistence warnings above.
///
/// `Issue::file()` is relative to the *scan root* (`args.path`), but `git
/// blame` needs a path relative to the *Git root* — which can be a parent
/// directory of the scan root (e.g. `yunq scan services/api` inside a
/// larger repo). This re-bases each issue's file onto the Git root before
/// blaming it, then keys the output back by the scan-relative path so it
/// still lines up with `Issue::file()` for any consumer cross-referencing
/// the two.
fn write_blame_output(args: &ScanArgs, report: &yunq_rules_engine::AnalysisReport) {
    let Some(output_path) = &args.output.blame_output else { return };
    let Some(git_root) = yunq_cli::find_git_root(&args.path) else {
        eprintln!(
            "warning: --blame-output given but {} is not inside a Git repository — skipping blame capture",
            args.path.display()
        );
        return;
    };

    let scan_root = args.path.canonicalize().unwrap_or_else(|_| args.path.clone());
    let prefix = scan_root.strip_prefix(&git_root).unwrap_or(std::path::Path::new(""));

    let mut report_files: Vec<String> = report.issues().iter().map(|issue| issue.file().to_string()).collect();
    report_files.sort();
    report_files.dedup();

    // `blame::blame_files` operates purely on paths relative to the Git
    // root; re-key its result back to the scan-relative paths the report
    // itself uses, via this git-relative -> scan-relative lookup.
    let git_relative_to_scan_relative: std::collections::HashMap<String, String> = report_files
        .iter()
        .map(|file| (prefix.join(file).to_string_lossy().replace('\\', "/"), file.clone()))
        .collect();
    let git_relative_files: Vec<String> = git_relative_to_scan_relative.keys().cloned().collect();

    let blame: std::collections::BTreeMap<String, Vec<blame::BlameLine>> =
        blame::blame_files(&git_root, &git_relative_files)
            .into_iter()
            .filter_map(|(git_relative, lines)| {
                git_relative_to_scan_relative.get(&git_relative).cloned().map(|scan_relative| (scan_relative, lines))
            })
            .collect();

    match serde_json::to_string_pretty(&blame) {
        Ok(json) => match std::fs::write(output_path, json) {
            Ok(()) => println!("📝 Wrote SCM blame for {} file(s) to {}", blame.len(), output_path.display()),
            Err(e) => eprintln!("warning: could not write blame output to {}: {e}", output_path.display()),
        },
        Err(e) => eprintln!("warning: could not serialize blame output: {e}"),
    }
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
    if args.scope.monorepo {
        return monorepo_scan::run(&args).await;
    }

    let threshold = parse_fail_on_threshold(args.fail_on.clone())?;
    let (source_dirs, exclusions, config_project_key, duplication, architecture) =
        load_project_scope(&args.path);
    let ci = resolve_ci_context();
    let context = resolve_context(&args, config_project_key, &ci);

    let cache = (!args.no_cache && args.path.is_dir())
        .then(|| std::sync::Arc::new(FileAnalysisCache::open(args.path.join(".yunq-cache.json"))));
    let mut report = yunq_cli::scan_with_project_config(
        &args.path,
        cache.clone(),
        &source_dirs,
        &exclusions,
        &duplication,
        &architecture,
    )
    .await?;

    // Before the gate and the New Code baseline: imported findings are
    // ordinary issues from here on, so both must see them.
    ingest_sarif(&args, &mut report)?;
    ingest_coverage(&args)?.apply_to(&mut report);
    let coverage_new_code = coverage_new_code_measure(args.coverage.coverage_diff.clone(), &report)?;
    crap::apply(&mut report);

    let test_report = load_test_report(args.reports.junit.clone())?;
    if let Some(summary) = &test_report {
        report.set_test_report(summary.clone());
    }
    if let Some(mutation) = load_mutation_report(args.reports.mutation_report.clone())? {
        report.set_mutation(mutation);
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

    report_to_github(&args, &context, &report, &gate, new_code.as_ref()).await;
    write_blame_output(&args, &report);
    render_output(&args, &report, &gate, new_code.as_ref(), test_report.as_ref(), coverage_new_code, &context.to_dto())?;

    Ok(exit_code(threshold, &report, args.enforce_gate, &gate))
}
