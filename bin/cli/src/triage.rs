//! Composition root for `vord triage` (roadmap C —
//! `docs/design/issue-triage-factory.md`): the one place that turns
//! `core/triage`'s pure state machine into work against a real GitHub
//! issue, the same way `crate::swarm` turns `core/swarm`'s pure decisions
//! into worktrees, agent runs and handoffs.
//!
//! Deliberately incomplete, and honest about it. [`advance`] drives the
//! Reproduce stage end-to-end: run a caller-supplied command in the
//! reproducer's worktree, classify its exit code
//! (`vord_triage::repro_event_from_exit_code`), advance and write the
//! label. Diagnose and Fix still need a live agent session
//! (`crate::agent::run_with_policy`) and `core/remediation`'s
//! `RemediationEngine` wired in behind a real verification step — that is
//! genuine integration work this module refuses to fake with an untested
//! stub, so [`advance`] reports those two stages as not yet implemented
//! rather than silently no-opping or guessing.

use std::path::Path;

use vord_agent::runtime::Workspace;
use vord_infra_fs::{RepoWorkspace, VordConfig};
use vord_infra_github::IssueTriageGateway;
use vord_triage::{TriageEvent, TriageLabel, next_triage_state, repro_event_from_exit_code};

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
    /// A stage this module does not drive yet.
    NotYetImplemented(&'static str),
}

fn next_action_for(current: TriageLabel) -> NextAction {
    if current.is_terminal() {
        return NextAction::Terminal;
    }
    match current.active_role() {
        None => NextAction::Start,
        Some("reproducer") => NextAction::RunRepro,
        Some(other) => NextAction::NotYetImplemented(other),
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
        NextAction::NotYetImplemented(role) => Err(not_yet_implemented_error(issue, current, role)),
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

/// A wait state (`New`/`Reproduced`/`Diagnosed`/`GateRejected`) advancing on
/// `TriageEvent::Start` — no verification needed, just spinning up the next
/// role's worktree.
async fn start_next_stage(
    gateway: &IssueTriageGateway,
    issue: u64,
    current: TriageLabel,
) -> anyhow::Result<AdvanceReport> {
    let next = next_triage_state(current, TriageEvent::Start)?;
    gateway.set_label(issue, next).await?;
    let message = format!("issue #{issue}: `{current}` → `{next}`");
    gateway.post_comment(issue, &message).await?;
    Ok(AdvanceReport {
        issue,
        from: current,
        to: Some(next),
        message,
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
    let command = repro_command.ok_or_else(|| {
        anyhow::anyhow!(
            "issue #{issue} is `triage:reproducing` — pass --repro-command \"<shell command>\" \
             (an agent that derives the repro from the issue body on its own is not built yet)"
        )
    })?;
    let output = run_repro_command(root, command)?;
    let event = repro_event_from_exit_code(output.exit_code);
    let next = next_triage_state(current, event)?;
    gateway.set_label(issue, next).await?;
    let message = format!(
        "issue #{issue}: repro command `{command}` exited {:?} — `{current}` → `{next}`\n\n```\n{}\n```",
        output.exit_code,
        output.render()
    );
    gateway.post_comment(issue, &message).await?;
    Ok(AdvanceReport {
        issue,
        from: current,
        to: Some(next),
        message,
    })
}

fn not_yet_implemented_error(issue: u64, current: TriageLabel, role: &str) -> anyhow::Error {
    anyhow::anyhow!(
        "issue #{issue} is `{current}` (role: {role}) — the {role} stage isn't wired to a live agent \
         yet, see docs/design/issue-triage-factory.md"
    )
}

/// Runs `command` (via `sh -c`, so a caller can pass ordinary shell syntax —
/// pipes, `&&`, arguments with spaces) inside the reproducer role's
/// worktree, creating it first if this is the first step to touch it.
fn run_repro_command(
    root: &Path,
    command: &str,
) -> anyhow::Result<vord_agent::runtime::CommandOutput> {
    let role = swarm::configured_roles(root)
        .into_iter()
        .find(|r| r.name == "reproducer")
        .ok_or_else(|| {
            anyhow::anyhow!(
                "no [[swarm.role]] named \"reproducer\" in vord.toml — add one (topology = \"triage-pack\")"
            )
        })?;
    let config = VordConfig::load_from_dir(root);
    let plan = swarm::worktree_plan(root, config.as_ref(), &role);
    swarm::ensure_worktree(root, &plan)?;

    let workspace = RepoWorkspace::new(plan.path.as_path());
    Ok(workspace.run("sh", &["-c".to_string(), command.to_string()])?)
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
    fn diagnosing_and_fixing_are_reported_as_not_yet_implemented_not_silently_skipped() {
        assert_eq!(
            next_action_for(TriageLabel::Diagnosing),
            NextAction::NotYetImplemented("diagnostician")
        );
        assert_eq!(
            next_action_for(TriageLabel::Fixing),
            NextAction::NotYetImplemented("fixer")
        );
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
}
