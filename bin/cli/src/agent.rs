//! Composition root for `yunq agent` — the runtime that writes code and
//! cannot approve its own work (roadmap A).
//!
//! `core/agent` holds the loop and every decision in it; this module supplies
//! the four adapters it runs on and nothing else. Two of them are the whole
//! point of the workstream:
//!
//! - [`HookWriteJudge`] is not a second implementation of the guardrail. It
//!   calls [`crate::hook::judge`] — the exact function `yunq hook
//!   claude-code` calls for a third-party agent — so `yunq agent` inherits
//!   the same `yunq-policy.toml`, the same provenance ledger, the same
//!   Gherkin evidence requirement, the same single-use approvals, the same
//!   persisted circuit breaker and the same audit log. An agent that shared
//!   only the *idea* of the policy would drift from it by the second release.
//! - [`RepoAnalyzer`] is the same analyzer `yunq scan` runs, over the same
//!   profile. "Done" means what the CI gate means by it.
//!
//! The one thing this module deliberately does *not* do is decide anything.
//! Every verdict in a run comes from `core/agent`, `core/agent-policy` or
//! `core/rules-engine`.

use std::path::{Path, PathBuf};

use yunq_agent::completion::LocatedFinding;
use yunq_agent::feedback::{FeedbackOutcome, FeedbackWatch, TriageLedger, Watch, WatchPolicy};
use yunq_agent::runtime::{
    AgentRuntime, AnalysisError, Analyzer, JudgeError, RunConfig, RunOutcome, WriteJudge,
};
use yunq_agent::{Budget, CommandAllowlist};
use yunq_agent_policy::{AgentPolicy, Evaluation};
use yunq_infra_fs::{RepoWorkspace, YunqConfig};
use yunq_infra_github::PullRequestFeedbackReader;
use yunq_infra_llm::LlmProviderConfig;
use yunq_rules_engine::RuleId;

use crate::hook;

/// Judges every proposed write through `yunq hook`'s own path.
pub struct HookWriteJudge {
    root: PathBuf,
    policy: AgentPolicy,
}

impl HookWriteJudge {
    pub fn new(root: impl Into<PathBuf>, policy: AgentPolicy) -> Self {
        Self { root: root.into(), policy }
    }
}

impl WriteJudge for HookWriteJudge {
    async fn judge(&self, path: &str, content: &str) -> Result<Evaluation, JudgeError> {
        let absolute = self.root.join(path);
        let verdict = hook::judge(&self.policy, &self.root, &absolute, Some(content))
            .await
            .map_err(|e| JudgeError(e.to_string()))?;
        // The same three side effects a hook-hosted write has, in the same
        // order: the persisted breaker, the persisted loop alarm, the audit
        // line. `core/agent` keeps its own session-scoped copies of the first
        // two as stopping conditions; these are the repository's record,
        // shared with every other agent yunq guards.
        let breaker = hook::track_circuit_breaker(&self.root, &verdict);
        let loop_report = hook::track_loop_guard(&self.root, path, Some(content));
        hook::append_audit_log(&self.root, "AgentWrite", &verdict, &breaker, &loop_report);
        Ok(verdict.into_evaluation())
    }
}

/// The analyzer, over the repository, with the project's own `yunq.toml`
/// sources and exclusions applied — so the agent is judged against the tree
/// the CI gate judges, not a wider one.
pub struct RepoAnalyzer {
    root: PathBuf,
    sources: Vec<String>,
    exclusions: Vec<String>,
}

impl RepoAnalyzer {
    pub fn new(root: impl Into<PathBuf>, config: Option<&YunqConfig>) -> Self {
        let analysis = config.map(|c| &c.analysis);
        Self {
            root: root.into(),
            sources: analysis.and_then(|a| a.sources.clone()).unwrap_or_default(),
            exclusions: analysis.and_then(|a| a.exclusions.clone()).unwrap_or_default(),
        }
    }
}

impl Analyzer for RepoAnalyzer {
    async fn scan(&self, path: &str) -> Result<Vec<LocatedFinding>, AnalysisError> {
        let target = self.root.join(path);
        // `sources` scopes a whole-repository scan; asking for one subtree
        // already *is* the scope, and intersecting the two would silently
        // return nothing whenever the subtree is not itself a source dir.
        let sources: &[String] = if path == "." { &self.sources } else { &[] };
        let report = crate::scan_with_project_config(
            &target,
            None,
            sources,
            &self.exclusions,
            &Default::default(),
            &Default::default(),
        )
        .await
        .map_err(|e| AnalysisError(e.to_string()))?;
        Ok(report_findings(&report))
    }
}

/// Issues *and* hotspots, for the same reason [`crate::hook::analyze_content`]
/// includes both: several rules are hotspot-only by design, and a completion
/// check that ignored them would call a task done that `yunq scan` still
/// objects to.
fn report_findings(report: &yunq_rules_engine::AnalysisReport) -> Vec<LocatedFinding> {
    let profile = yunq_rules_engine::default_profile();
    let issues = report.issues().iter().map(|issue| LocatedFinding {
        file: issue.file().to_string(),
        rule: issue.rule().clone(),
        severity: issue.severity(),
        message: issue.message().to_string(),
        line: issue.span().start_line,
    });
    let hotspots = report.hotspots().iter().map(|hotspot| LocatedFinding {
        file: hotspot.file().to_string(),
        rule: hotspot.rule().clone(),
        severity: profile.severity_of(hotspot.rule()).unwrap_or(yunq_rules_engine::Severity::Major),
        message: hotspot.message().to_string(),
        line: hotspot.span().start_line,
    });
    issues.chain(hotspots).collect()
}

/// Everything `yunq agent run` was asked for on the command line.
pub struct AgentArgs {
    pub task: String,
    pub scope: String,
    pub rule: Option<String>,
    pub max_turns: Option<u32>,
    pub max_tokens: Option<u64>,
    pub model: Option<String>,
}

/// Builds the run's configuration from the CLI arguments layered over
/// `yunq.toml`'s `[agent]` table, which is layered over the built-in
/// defaults. A flag always wins; an absent flag never resets a configured
/// value to the default.
fn run_config(args: &AgentArgs, settings: &yunq_infra_fs::AgentSettings) -> anyhow::Result<RunConfig> {
    let defaults = Budget::default();
    let target_rule = match &args.rule {
        Some(raw) => Some(RuleId::new(raw).map_err(|_| anyhow::anyhow!("invalid rule id {raw:?}"))?),
        None => None,
    };
    let allowlist = match &settings.allowed_commands {
        Some(commands) => CommandAllowlist::new(commands.clone()),
        None => CommandAllowlist::default(),
    };
    Ok(RunConfig {
        task: args.task.clone(),
        scope: args.scope.clone(),
        target_rule,
        budget: Budget {
            max_turns: args.max_turns.or(settings.max_turns).unwrap_or(defaults.max_turns),
            max_tokens: args.max_tokens.or(settings.max_tokens).unwrap_or(defaults.max_tokens),
        },
        allowlist,
        max_rejections: settings.max_rejections.unwrap_or(RunConfig::new("").max_rejections),
    })
}

/// Runs one headless session. Returns the outcome rather than an exit code so
/// the caller owns rendering — `yunq swarm` (workstream B) drives this same
/// function and wants the structured verdict, not a number.
pub async fn run(root: &Path, args: AgentArgs) -> anyhow::Result<RunOutcome> {
    let config_file = YunqConfig::load_from_dir(root);
    let settings = config_file.as_ref().map(|c| c.agent.clone()).unwrap_or_default();
    let config = run_config(&args, &settings)?;
    let policy = hook::load_policy(root)?;

    let mut provider = LlmProviderConfig::from_env();
    if let Some(model) = args.model {
        provider.model = model;
    }
    if provider.api_key.is_empty() && provider.kind == yunq_infra_llm::LlmProviderKind::Anthropic {
        anyhow::bail!("no API key: set ANTHROPIC_API_KEY (or YUNQ_ANTHROPIC_API_KEY)");
    }

    let workspace = match settings.command_timeout_secs {
        Some(seconds) => RepoWorkspace::new(root).with_timeout(std::time::Duration::from_secs(seconds)),
        None => RepoWorkspace::new(root),
    };
    let runtime = AgentRuntime::new(
        provider.build_chat_model(),
        workspace,
        HookWriteJudge::new(root, policy),
        RepoAnalyzer::new(root, config_file.as_ref()),
        config,
    );
    Ok(runtime.run().await)
}

// ---------------------------------------------------------------------------
// A5 — late feedback
// ---------------------------------------------------------------------------

/// Filename of the triage ledger: every feedback item `yunq agent watch-pr`
/// has already reported, keyed by pull request. Alongside the guardrail's
/// other soft state in the repository root, and just as disposable — losing
/// it re-reports items that were already handled, which is noisy but never
/// wrong.
pub const TRIAGE_FILE: &str = ".yunq-triage.json";

type TriageStore = std::collections::BTreeMap<String, Vec<String>>;

fn load_triage(root: &Path, key: &str) -> TriageLedger {
    let Ok(raw) = std::fs::read_to_string(root.join(TRIAGE_FILE)) else { return TriageLedger::default() };
    let store: TriageStore = serde_json::from_str(&raw).unwrap_or_default();
    TriageLedger::from_ids(store.get(key).cloned().unwrap_or_default())
}

fn save_triage(root: &Path, key: &str, ledger: &TriageLedger) {
    let path = root.join(TRIAGE_FILE);
    let mut store: TriageStore = std::fs::read_to_string(&path)
        .ok()
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .unwrap_or_default();
    store.insert(key.to_string(), ledger.ids().cloned().collect());
    match serde_json::to_string_pretty(&store) {
        Ok(raw) => {
            if let Err(e) = std::fs::write(&path, raw) {
                eprintln!("yunq agent: could not persist the triage ledger at {}: {e}", path.display());
            }
        }
        Err(e) => eprintln!("yunq agent: could not serialize the triage ledger: {e}"),
    }
}

/// Resolves `owner/repo` from the flag or `GITHUB_REPOSITORY`.
fn resolve_repository(repo: Option<String>) -> anyhow::Result<(String, String)> {
    let raw = match repo {
        Some(raw) => raw,
        None => std::env::var("GITHUB_REPOSITORY")
            .map_err(|_| anyhow::anyhow!("no repository: pass --repo owner/name or set GITHUB_REPOSITORY"))?,
    };
    let (owner, name) = raw
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("expected owner/name, got {raw:?}"))?;
    Ok((owner.to_string(), name.to_string()))
}

/// Waits out the late-feedback window on a pull request.
///
/// The sleeping happens here and the deciding happens in
/// `yunq_agent::feedback` — this function judges nothing. It honours the
/// delays the watch hands back, and hands the watch what the adapter saw.
pub async fn watch_pull_request(
    repo: Option<String>,
    number: u64,
    window_secs: Option<u64>,
) -> anyhow::Result<FeedbackOutcome> {
    let root = std::env::current_dir()?;
    let (owner, name) = resolve_repository(repo)?;
    let token = std::env::var("GITHUB_TOKEN")
        .map_err(|_| anyhow::anyhow!("no GITHUB_TOKEN — `watch-pr` needs one to read the pull request"))?;
    let reader = PullRequestFeedbackReader::new(token, &owner, &name).with_api_base(
        std::env::var("YUNQ_GITHUB_API_BASE").unwrap_or_else(|_| "https://api.github.com".to_string()),
    );

    let key = format!("{owner}/{name}#{number}");
    let policy = match window_secs {
        Some(seconds) => WatchPolicy { window: std::time::Duration::from_secs(seconds), ..Default::default() },
        None => WatchPolicy::default(),
    };
    let mut watch = FeedbackWatch::new(policy, load_triage(&root, &key));
    loop {
        match watch.observe(reader.poll(number).await) {
            Watch::WaitFor(delay) => tokio::time::sleep(delay).await,
            Watch::Settled(outcome) => {
                save_triage(&root, &key, watch.ledger());
                return Ok(outcome);
            }
        }
    }
}

pub fn report_feedback(outcome: &FeedbackOutcome) {
    let line = format!("yunq agent watch-pr: {}", outcome.describe());
    match outcome {
        FeedbackOutcome::Quiet | FeedbackOutcome::BotAllClear { .. } => println!("{line}"),
        _ => eprintln!("{line}"),
    }
}

/// One line per outcome, on stdout for a success and stderr otherwise —
/// so a CI step's log shows the failure without `2>&1`.
pub fn report(outcome: &RunOutcome) {
    let line = format!("yunq agent: {} (after {} turns)", outcome.describe(), outcome.turns());
    match outcome {
        RunOutcome::Completed { .. } => println!("{line}"),
        _ => eprintln!("{line}"),
    }
}

#[cfg(test)]
mod tests {
    use yunq_infra_fs::AgentSettings;

    use super::*;

    fn args() -> AgentArgs {
        AgentArgs {
            task: "fix it".to_string(),
            scope: ".".to_string(),
            rule: None,
            max_turns: None,
            max_tokens: None,
            model: None,
        }
    }

    #[test]
    fn an_unconfigured_run_uses_the_built_in_budget() {
        let config = run_config(&args(), &AgentSettings::default()).unwrap();
        assert_eq!(config.budget, Budget::default());
        assert_eq!(config.allowlist, CommandAllowlist::default());
        assert_eq!(config.target_rule, None);
    }

    #[test]
    fn yunq_toml_overrides_the_built_in_budget() {
        let settings = AgentSettings { max_turns: Some(5), max_tokens: Some(99), ..AgentSettings::default() };
        let config = run_config(&args(), &settings).unwrap();
        assert_eq!(config.budget, Budget { max_turns: 5, max_tokens: 99 });
    }

    #[test]
    fn a_flag_outranks_yunq_toml() {
        let settings = AgentSettings { max_turns: Some(5), ..AgentSettings::default() };
        let config = run_config(&AgentArgs { max_turns: Some(11), ..args() }, &settings).unwrap();
        assert_eq!(config.budget.max_turns, 11);
    }

    #[test]
    fn an_absent_flag_does_not_reset_a_configured_value() {
        let settings = AgentSettings { max_tokens: Some(77), ..AgentSettings::default() };
        let config = run_config(&AgentArgs { max_turns: Some(3), ..args() }, &settings).unwrap();
        assert_eq!(config.budget.max_tokens, 77);
    }

    #[test]
    fn a_configured_allowlist_replaces_the_default_one() {
        let settings =
            AgentSettings { allowed_commands: Some(vec!["just".to_string()]), ..AgentSettings::default() };
        let config = run_config(&args(), &settings).unwrap();
        assert_eq!(config.allowlist.programs(), ["just"]);
    }

    #[test]
    fn a_target_rule_is_parsed_and_a_malformed_one_is_rejected() {
        let config = run_config(&AgentArgs { rule: Some("owasp:xss".into()), ..args() }, &Default::default())
            .unwrap();
        assert_eq!(config.target_rule.map(|r| r.to_string()).as_deref(), Some("owasp:xss"));
        assert!(run_config(&AgentArgs { rule: Some("not a rule id".into()), ..args() }, &Default::default())
            .is_err());
    }

    #[tokio::test]
    async fn the_analyzer_adapter_reports_findings_with_their_file() {
        let root = std::env::temp_dir().join(format!("yunq-agent-analyzer-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(root.join("src/a.py"), "import subprocess\nsubprocess.run(cmd, shell=True)\n").unwrap();

        let findings = RepoAnalyzer::new(&root, None).scan(".").await.unwrap();

        assert!(
            findings.iter().any(|f| f.file.ends_with("a.py")),
            "expected a finding in a.py, got {findings:?}"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn the_write_judge_denies_a_blocking_rule_and_leaves_an_audit_line() {
        let root = std::env::temp_dir().join(format!("yunq-agent-judge-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();

        let judge = HookWriteJudge::new(&root, AgentPolicy::default());
        let evaluation = judge.judge("src/a.py", "import subprocess\nsubprocess.run(cmd, shell=True)\n").await.unwrap();

        assert!(evaluation.is_denied(), "a default blocking rule must deny: {evaluation:?}");
        let audit = std::fs::read_to_string(root.join(hook::AUDIT_LOG_FILE)).unwrap();
        assert!(audit.contains("\"event\":\"AgentWrite\""), "{audit}");
        assert!(audit.contains("\"outcome\":\"deny\""), "{audit}");
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn the_write_judge_allows_a_clean_write() {
        let root = std::env::temp_dir().join(format!("yunq-agent-judge-clean-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();

        let judge = HookWriteJudge::new(&root, AgentPolicy::default());
        let evaluation = judge.judge("src/a.py", "def add(a, b):\n    return a + b\n").await.unwrap();

        assert!(!evaluation.is_denied(), "{evaluation:?}");
        std::fs::remove_dir_all(&root).ok();
    }
}
