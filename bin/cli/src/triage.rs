//! Composition root for `vord triage` (roadmap C —
//! `docs/design/issue-triage-factory.md`): the one place that turns
//! `core/triage`'s pure state machine into work against a real GitHub
//! issue, the same way `crate::swarm` turns `core/swarm`'s pure decisions
//! into worktrees, agent runs and handoffs.
//!
//! Every stage below is either verified by a fact this module observed
//! directly (an exit code) or by `crate::agent::run_with_policy`'s own
//! analyzer-as-done gate, which already refuses to call a session complete
//! if it introduced a regression — no stage here ever advances on a
//! model's unverified self-report. What isn't covered by this module's own
//! test suite is the live agent call itself: `run_with_policy` always
//! sources a real LLM provider from the environment
//! (`vord_infra_llm::LlmProviderConfig::from_env`), with no seam to inject
//! a fake one, so [`run_diagnose_stage`] and [`run_fix_stage`] are exercised
//! by the pure classification helpers they delegate their verdicts to
//! ([`fix_verdict`]) plus manual review, not an automated end-to-end test —
//! unlike [`run_reproduce_stage`], which needs no LLM at all and is fully
//! integration-tested below.

use std::path::Path;

use vord_agent::runtime::{RunOutcome, Workspace};
use vord_infra_fs::{RepoWorkspace, RoleSettings, VordConfig};
use vord_infra_github::IssueTriageGateway;
use vord_swarm::WorktreePlan;
use vord_triage::{
    FixVerdict, TriageEvent, TriageLabel, next_triage_state, repro_event_from_exit_code,
};

use crate::agent::{self, AgentArgs};
use crate::swarm;

/// What [`advance`] should do next for an issue currently labeled
/// `current`. Pure — no I/O — so the branching itself is unit-testable
/// without a GitHub mock server; only the I/O each variant drives lives in
/// [`advance`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NextAction {
    /// The pipeline has nothing left to do on its own.
    Terminal,
    /// No role is active on this label — advance past the wait state.
    Start,
    /// The Reproducer's regression test needs to run.
    RunRepro,
    /// The Diagnostician needs to reason about the issue's root cause.
    RunDiagnose,
    /// The Fixer needs to fix the bug and have it verified.
    RunFix,
    /// `TriageLabel::active_role` named a role this module has no stage
    /// for. Can only happen on a `vord-triage`/`vord-cli` version skew —
    /// reported as an ordinary error rather than a panic, since a stale
    /// binary hitting this is an operational fact, not a programmer bug to
    /// crash over.
    UnknownRole(&'static str),
}

fn next_action_for(current: TriageLabel) -> NextAction {
    if current.is_terminal() {
        return NextAction::Terminal;
    }
    match current.active_role() {
        None => NextAction::Start,
        Some("reproducer") => NextAction::RunRepro,
        Some("diagnostician") => NextAction::RunDiagnose,
        Some("fixer") => NextAction::RunFix,
        Some(other) => NextAction::UnknownRole(other),
    }
}

/// What one `advance` call did, for the CLI to report.
#[derive(Debug)]
pub struct AdvanceReport {
    pub issue: u64,
    pub from: TriageLabel,
    pub to: Option<TriageLabel>,
    pub message: String,
}

/// Advances `issue` by exactly one step, reading GitHub credentials from
/// the environment `GITHUB_TOKEN`/`GITHUB_REPOSITORY` — the thin real
/// entry point. [`advance_with_gateway`] is the testable core: everything
/// this function does beyond sourcing the gateway.
pub async fn advance(
    root: &Path,
    issue: u64,
    repro_command: Option<&str>,
) -> anyhow::Result<AdvanceReport> {
    let gateway = IssueTriageGateway::from_env().ok_or_else(|| {
        anyhow::anyhow!(
            "GITHUB_TOKEN and GITHUB_REPOSITORY must be set — the same environment GitHub Actions provides"
        )
    })?;
    advance_with_gateway(&gateway, root, issue, repro_command).await
}

/// Advances `issue` by exactly one step: reads its current `triage:*`
/// label, decides what that label calls for, does it, and writes the
/// resulting label back. Never advances more than one step — a caller
/// (a GitHub Actions workflow on a label-change webhook, or a human running
/// this by hand) re-invokes it for the next step, the same way
/// `core/triage`'s label-as-state-machine is meant to be driven. Takes the
/// gateway by reference rather than sourcing it from the environment
/// itself, so a test can point it at a mock server without mutating
/// process-global env vars (and racing every other test that also would).
pub async fn advance_with_gateway(
    gateway: &IssueTriageGateway,
    root: &Path,
    issue: u64,
    repro_command: Option<&str>,
) -> anyhow::Result<AdvanceReport> {
    let current = gateway
        .current_label(issue)
        .await?
        .unwrap_or(TriageLabel::New);

    match next_action_for(current) {
        NextAction::Terminal => Ok(terminal_report(issue, current)),
        NextAction::Start => start_next_stage(gateway, issue, current).await,
        NextAction::RunRepro => {
            run_reproduce_stage(gateway, root, issue, current, repro_command).await
        }
        NextAction::RunDiagnose => run_diagnose_stage(gateway, root, issue, current).await,
        NextAction::RunFix => run_fix_stage(gateway, root, issue, current, repro_command).await,
        NextAction::UnknownRole(role) => Err(anyhow::anyhow!(
            "issue #{issue} is `{current}` (role: {role:?}) — this vord-cli build has no stage for \
             that role; check for a vord-triage/vord-cli version mismatch"
        )),
    }
}

fn terminal_report(issue: u64, current: TriageLabel) -> AdvanceReport {
    AdvanceReport {
        issue,
        from: current,
        to: None,
        message: format!("issue #{issue} is at `{current}` — nothing left for the pipeline to do"),
    }
}

/// Computes the next label from `event`, writes it, posts the comment
/// `message` builds (given the resolved next label), and assembles the
/// report — the tail every stage below ends with. Factored out once vord's
/// own `smells:duplicate-code` flagged the fourth near-identical copy of
/// it, dogfooding the same rule this project ships to everyone else.
async fn advance_and_report(
    gateway: &IssueTriageGateway,
    issue: u64,
    current: TriageLabel,
    event: TriageEvent,
    message: impl FnOnce(TriageLabel) -> String,
) -> anyhow::Result<AdvanceReport> {
    let next = next_triage_state(current, event)?;
    gateway.set_label(issue, next).await?;
    let message = message(next);
    gateway.post_comment(issue, &message).await?;
    Ok(AdvanceReport {
        issue,
        from: current,
        to: Some(next),
        message,
    })
}

/// A wait state (`New`/`Reproduced`/`Diagnosed`/`GateRejected`) advancing on
/// `TriageEvent::Start` — no verification needed, just spinning up the next
/// role's worktree.
async fn start_next_stage(
    gateway: &IssueTriageGateway,
    issue: u64,
    current: TriageLabel,
) -> anyhow::Result<AdvanceReport> {
    advance_and_report(gateway, issue, current, TriageEvent::Start, |next| {
        format!("issue #{issue}: `{current}` → `{next}`")
    })
    .await
}

/// Both Reproduce and Fix need `--repro-command` and refuse to guess one —
/// same guard, different reason why it's required, so the reason is the
/// only thing each call site supplies.
fn require_repro_command<'a>(
    repro_command: Option<&'a str>,
    issue: u64,
    current: TriageLabel,
    reason: &str,
) -> anyhow::Result<&'a str> {
    repro_command.ok_or_else(|| {
        anyhow::anyhow!(
            "issue #{issue} is `{current}` — pass --repro-command \"<shell command>\" ({reason})"
        )
    })
}

/// The Reproduce stage: run the caller-supplied repro command, classify its
/// exit code, and advance on that fact alone.
async fn run_reproduce_stage(
    gateway: &IssueTriageGateway,
    root: &Path,
    issue: u64,
    current: TriageLabel,
    repro_command: Option<&str>,
) -> anyhow::Result<AdvanceReport> {
    let command = require_repro_command(
        repro_command,
        issue,
        current,
        "an agent that derives the repro from the issue body on its own is not built yet",
    )?;
    let output = run_repro_command(root, command)?;
    let event = repro_event_from_exit_code(output.exit_code);
    advance_and_report(gateway, issue, current, event, |next| {
        format!(
            "issue #{issue}: repro command `{command}` exited {:?} — `{current}` → `{next}`\n\n```\n{}\n```",
            output.exit_code,
            output.render()
        )
    })
    .await
}

/// The Diagnose stage: an agent session reasons about the issue's root
/// cause in the diagnostician's worktree, no fix attempted. Always
/// advances to `Diagnosed` on completion — `grounded_in_finding` (whether
/// `vord scan` already flags something in the touched worktree) is
/// informational, per `core/triage`'s own docs on that field, not a gate.
/// If the session itself didn't complete (budget exhausted, circuit
/// breaker tripped, ...), that is reported in the comment honestly rather
/// than hidden, even though the state machine still advances — diagnosis
/// has no "rejected" outcome to route to today.
async fn run_diagnose_stage(
    gateway: &IssueTriageGateway,
    root: &Path,
    issue: u64,
    current: TriageLabel,
) -> anyhow::Result<AdvanceReport> {
    let summary = gateway.issue_summary(issue).await?;
    let task = format!(
        "Diagnose the root cause of this bug report. Do not attempt a fix yet — \
         just explain what's wrong and point at the responsible file(s).\n\n\
         Title: {}\n\n{}",
        summary.title, summary.body
    );
    let (outcome, plan) = run_role_task(root, "diagnostician", task).await?;
    let grounded_in_finding = !crate::scan(&plan.path).await?.issues().is_empty();

    let event = TriageEvent::DiagnosisAttempted {
        grounded_in_finding,
    };
    advance_and_report(gateway, issue, current, event, |next| {
        format!(
            "issue #{issue}: diagnosis — {} (grounded in an existing vord finding: {grounded_in_finding}) — `{current}` → `{next}`",
            outcome.describe()
        )
    })
    .await
}

/// The Fix stage: an agent session fixes the bug in the fixer's worktree.
/// Verified two ways, neither the agent's own opinion — the session's own
/// analyzer-as-done gate (no regressions, already enforced *inside*
/// `run_with_policy` before it can report `Completed`) and, specific to
/// triage, a re-run of the same `--repro-command` from Reproduce, which
/// must now exit `0`. [`fix_verdict`] is the pure decision between the two
/// signals — see the module docs for why that split exists.
async fn run_fix_stage(
    gateway: &IssueTriageGateway,
    root: &Path,
    issue: u64,
    current: TriageLabel,
    repro_command: Option<&str>,
) -> anyhow::Result<AdvanceReport> {
    let command = require_repro_command(
        repro_command,
        issue,
        current,
        "the same command from the Reproduce stage, so the fix can be verified",
    )?;
    let summary = gateway.issue_summary(issue).await?;
    let task = format!(
        "Fix this bug so that running `{command}` succeeds (exit code 0).\n\n\
         Title: {}\n\n{}",
        summary.title, summary.body
    );
    let (outcome, plan) = run_role_task(root, "fixer", task).await?;
    let agent_completed = matches!(outcome, RunOutcome::Completed { .. });

    let repro_exit_code = if agent_completed {
        let workspace = RepoWorkspace::new(plan.path.as_path());
        workspace
            .run("sh", &["-c".to_string(), command.to_string()])?
            .exit_code
    } else {
        None
    };
    let verdict = fix_verdict(agent_completed, repro_exit_code);
    let event = TriageEvent::FixAttempted { verdict };
    advance_and_report(gateway, issue, current, event, |next| {
        format!(
            "issue #{issue}: fix attempt — agent {} — `{current}` → `{next}`",
            outcome.describe()
        )
    })
    .await
}

/// Whether a fix attempt is accepted: the agent session must have
/// completed (its own regression gate already passed) *and* the regression
/// command must now exit cleanly. Split out from [`run_fix_stage`] so this
/// decision has a unit test that needs no live agent or subprocess.
fn fix_verdict(agent_completed: bool, repro_exit_code: Option<i32>) -> FixVerdict {
    if agent_completed && repro_exit_code == Some(0) {
        FixVerdict::Accepted
    } else {
        FixVerdict::Rejected
    }
}

/// Resolves `role_name`'s configured role and worktree plan, creating the
/// worktree if this is the first stage to touch it. Shared by every stage
/// below — reproducer, diagnostician and fixer each have a different job,
/// but all three start from the same worktree-per-role setup.
fn role_worktree(root: &Path, role_name: &str) -> anyhow::Result<(RoleSettings, WorktreePlan)> {
    let role = swarm::configured_roles(root)
        .into_iter()
        .find(|r| r.name == role_name)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "no [[swarm.role]] named {role_name:?} in vord.toml — add one (topology = \"triage-pack\")"
            )
        })?;
    let config = VordConfig::load_from_dir(root);
    let plan = swarm::worktree_plan(root, config.as_ref(), &role);
    swarm::ensure_worktree(root, &plan)?;
    Ok((role, plan))
}

/// Runs `command` (via `sh -c`, so a caller can pass ordinary shell syntax —
/// pipes, `&&`, arguments with spaces) inside the reproducer role's
/// worktree, creating it first if this is the first step to touch it.
fn run_repro_command(
    root: &Path,
    command: &str,
) -> anyhow::Result<vord_agent::runtime::CommandOutput> {
    let (_role, plan) = role_worktree(root, "reproducer")?;
    let workspace = RepoWorkspace::new(plan.path.as_path());
    Ok(workspace.run("sh", &["-c".to_string(), command.to_string()])?)
}

/// Runs `task` as one headless `vord agent` turn inside `role_name`'s
/// worktree, under that role's own scoped policy — the same mechanism
/// `crate::swarm::topology_run` uses per role in a pipeline, reused here to
/// drive a single role at a time. Returns the worktree plan alongside the
/// outcome so a caller can act on the worktree afterward (re-scan it,
/// re-run a command in it) without resolving it a second time.
async fn run_role_task(
    root: &Path,
    role_name: &str,
    task: String,
) -> anyhow::Result<(RunOutcome, WorktreePlan)> {
    let (role, plan) = role_worktree(root, role_name)?;
    let policy = swarm::scoped_policy(&plan.path, &role)?;
    let args = AgentArgs {
        task,
        scope: ".".to_string(),
        rule: None,
        max_turns: None,
        max_tokens: None,
        model: None,
    };
    let outcome = agent::run_with_policy(&plan.path, args, policy).await?;
    Ok((outcome, plan))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_terminal_label_needs_nothing() {
        assert_eq!(
            next_action_for(TriageLabel::NeedsInfo),
            NextAction::Terminal
        );
        assert_eq!(next_action_for(TriageLabel::FixReady), NextAction::Terminal);
    }

    #[test]
    fn a_wait_state_starts_the_next_stage() {
        assert_eq!(next_action_for(TriageLabel::New), NextAction::Start);
        assert_eq!(next_action_for(TriageLabel::Reproduced), NextAction::Start);
        assert_eq!(next_action_for(TriageLabel::Diagnosed), NextAction::Start);
        assert_eq!(
            next_action_for(TriageLabel::GateRejected),
            NextAction::Start
        );
    }

    #[test]
    fn reproducing_asks_for_the_repro_command() {
        assert_eq!(
            next_action_for(TriageLabel::Reproducing),
            NextAction::RunRepro
        );
    }

    #[test]
    fn diagnosing_asks_for_a_diagnosis() {
        assert_eq!(
            next_action_for(TriageLabel::Diagnosing),
            NextAction::RunDiagnose
        );
    }

    #[test]
    fn fixing_asks_for_a_fix() {
        assert_eq!(next_action_for(TriageLabel::Fixing), NextAction::RunFix);
    }

    #[test]
    fn a_fix_is_accepted_only_when_the_agent_completed_and_the_repro_now_passes() {
        assert_eq!(fix_verdict(true, Some(0)), FixVerdict::Accepted);
    }

    #[test]
    fn an_incomplete_agent_session_rejects_the_fix_even_if_a_repro_check_looks_clean() {
        assert_eq!(fix_verdict(false, Some(0)), FixVerdict::Rejected);
    }

    #[test]
    fn a_completed_session_whose_repro_still_fails_is_rejected() {
        assert_eq!(fix_verdict(true, Some(1)), FixVerdict::Rejected);
        assert_eq!(fix_verdict(true, None), FixVerdict::Rejected);
    }

    #[test]
    fn no_repro_check_at_all_is_rejected_not_assumed_clean() {
        assert_eq!(fix_verdict(false, None), FixVerdict::Rejected);
    }
}

/// End-to-end coverage for [`advance_with_gateway`]: a real temp git repo
/// with a `reproducer` role, a real `sh -c` subprocess, and a mock GitHub
/// server — the one path in this module that wires worktree creation,
/// sandboxed command execution and the state machine together, so it is
/// the one path worth more than the pure branching `mod tests` above
/// already covers.
#[cfg(test)]
mod integration_tests {
    use std::process::Command;
    use std::sync::{Arc, Mutex};
    use std::time::{SystemTime, UNIX_EPOCH};

    use axum::extract::{Path as AxumPath, State};
    use axum::http::StatusCode;
    use axum::routing::{delete, get, post};
    use axum::{Json, Router};

    use super::*;

    fn init_repo(name: &str) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!(
            "vord-triage-cli-{name}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let git = |args: &[&str]| {
            let status = Command::new("git")
                .arg("-C")
                .arg(&root)
                .args(args)
                .status()
                .unwrap();
            assert!(status.success(), "git {args:?} failed");
        };
        git(&["init", "--template=", "-q", "-b", "main"]);
        git(&["config", "user.email", "triage@vord.test"]);
        git(&["config", "user.name", "vord triage test"]);
        std::fs::write(
            root.join("vord.toml"),
            "[[swarm.role]]\nname = \"reproducer\"\n",
        )
        .unwrap();
        git(&["add", "vord.toml"]);
        git(&["commit", "-q", "-m", "init"]);
        root.canonicalize().unwrap_or(root)
    }

    #[derive(Clone, Default)]
    struct Captured {
        posts: Arc<Mutex<Vec<serde_json::Value>>>,
    }

    #[derive(Clone, Default)]
    struct ServerState {
        labels: Arc<Vec<serde_json::Value>>,
        captured: Captured,
    }

    async fn get_labels(
        State(state): State<ServerState>,
        AxumPath((_owner, _repo, _issue)): AxumPath<(String, String, u64)>,
    ) -> Json<serde_json::Value> {
        Json(serde_json::Value::Array((*state.labels).clone()))
    }

    async fn get_issue(
        AxumPath((_owner, _repo, _issue)): AxumPath<(String, String, u64)>,
    ) -> Json<serde_json::Value> {
        Json(serde_json::json!({"title": "it crashes", "body": "steps: ..."}))
    }

    async fn post_labels_or_comment(
        State(state): State<ServerState>,
        AxumPath(_params): AxumPath<(String, String, u64)>,
        Json(body): Json<serde_json::Value>,
    ) -> StatusCode {
        state.captured.posts.lock().unwrap().push(body);
        StatusCode::CREATED
    }

    async fn delete_label(
        State(_state): State<ServerState>,
        AxumPath(_params): AxumPath<(String, String, u64, String)>,
    ) -> StatusCode {
        StatusCode::OK
    }

    async fn start_mock_server(labels: Vec<serde_json::Value>) -> (IssueTriageGateway, Captured) {
        let state = ServerState {
            labels: Arc::new(labels),
            captured: Captured::default(),
        };
        let captured = state.captured.clone();
        let app = Router::new()
            .route("/repos/{owner}/{repo}/issues/{issue}", get(get_issue))
            .route(
                "/repos/{owner}/{repo}/issues/{issue}/labels",
                get(get_labels).post(post_labels_or_comment),
            )
            .route(
                "/repos/{owner}/{repo}/issues/{issue}/labels/{name}",
                delete(delete_label),
            )
            .route(
                "/repos/{owner}/{repo}/issues/{issue}/comments",
                post(post_labels_or_comment),
            )
            .with_state(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let gateway =
            IssueTriageGateway::new("t", "acme", "widgets").with_api_base(format!("http://{addr}"));
        (gateway, captured)
    }

    #[tokio::test]
    async fn a_failing_repro_command_moves_reproducing_to_reproduced() {
        let root = init_repo("repro-fail");
        let (gateway, captured) =
            start_mock_server(vec![serde_json::json!({"name": "triage:reproducing"})]).await;

        let report = advance_with_gateway(&gateway, &root, 42, Some("exit 1"))
            .await
            .expect("advance succeeds");

        std::fs::remove_dir_all(&root).ok();

        assert_eq!(report.from, TriageLabel::Reproducing);
        assert_eq!(report.to, Some(TriageLabel::Reproduced));
        let posts = captured.posts.lock().unwrap();
        assert!(
            posts
                .iter()
                .any(|p| p.get("labels") == Some(&serde_json::json!(["triage:reproduced"]))),
            "expected a label update to triage:reproduced in {posts:?}"
        );
        assert!(
            posts.iter().any(|p| p.get("body").is_some()),
            "expected a comment with the repro output in {posts:?}"
        );
    }

    #[tokio::test]
    async fn a_clean_repro_command_routes_to_needs_info() {
        let root = init_repo("repro-clean");
        let (gateway, _captured) =
            start_mock_server(vec![serde_json::json!({"name": "triage:reproducing"})]).await;

        let report = advance_with_gateway(&gateway, &root, 7, Some("true"))
            .await
            .expect("advance succeeds");

        std::fs::remove_dir_all(&root).ok();

        assert_eq!(report.to, Some(TriageLabel::NeedsInfo));
    }

    #[tokio::test]
    async fn advancing_reproducing_without_a_repro_command_is_a_clear_error() {
        let root = init_repo("repro-missing-command");
        let (gateway, _captured) =
            start_mock_server(vec![serde_json::json!({"name": "triage:reproducing"})]).await;

        let err = advance_with_gateway(&gateway, &root, 7, None)
            .await
            .unwrap_err();

        std::fs::remove_dir_all(&root).ok();

        assert!(err.to_string().contains("--repro-command"), "{err}");
    }

    #[tokio::test]
    async fn advancing_a_wait_state_writes_the_next_label_with_no_command_needed() {
        let root = init_repo("wait-state");
        let (gateway, captured) =
            start_mock_server(vec![serde_json::json!({"name": "triage:new"})]).await;

        let report = advance_with_gateway(&gateway, &root, 3, None)
            .await
            .expect("advance succeeds");

        std::fs::remove_dir_all(&root).ok();

        assert_eq!(report.from, TriageLabel::New);
        assert_eq!(report.to, Some(TriageLabel::Reproducing));
        let posts = captured.posts.lock().unwrap();
        assert!(
            posts
                .iter()
                .any(|p| p.get("labels") == Some(&serde_json::json!(["triage:reproducing"]))),
        );
    }

    #[tokio::test]
    async fn advancing_a_terminal_label_writes_nothing() {
        let root = init_repo("terminal");
        let (gateway, captured) =
            start_mock_server(vec![serde_json::json!({"name": "triage:fix-ready"})]).await;

        let report = advance_with_gateway(&gateway, &root, 9, None)
            .await
            .expect("advance succeeds");

        std::fs::remove_dir_all(&root).ok();

        assert_eq!(report.to, None);
        assert!(captured.posts.lock().unwrap().is_empty());
    }

    // Diagnose and Fix both fail fast, before any live agent call, when
    // their preconditions aren't met — both paths are real coverage of
    // this module's own plumbing (role lookup, flag validation) without
    // needing an LLM provider, unlike the rest of either stage (see the
    // module docs).

    #[tokio::test]
    async fn advancing_diagnosing_without_a_diagnostician_role_is_a_clear_error() {
        let root = init_repo("diagnose-no-role");
        let (gateway, _captured) =
            start_mock_server(vec![serde_json::json!({"name": "triage:diagnosing"})]).await;

        let err = advance_with_gateway(&gateway, &root, 7, None)
            .await
            .unwrap_err();

        std::fs::remove_dir_all(&root).ok();

        assert!(err.to_string().contains("diagnostician"), "{err}");
    }

    #[tokio::test]
    async fn advancing_fixing_without_a_repro_command_is_a_clear_error() {
        let root = init_repo("fix-no-command");
        let (gateway, _captured) =
            start_mock_server(vec![serde_json::json!({"name": "triage:fixing"})]).await;

        let err = advance_with_gateway(&gateway, &root, 7, None)
            .await
            .unwrap_err();

        std::fs::remove_dir_all(&root).ok();

        assert!(err.to_string().contains("--repro-command"), "{err}");
    }
}
