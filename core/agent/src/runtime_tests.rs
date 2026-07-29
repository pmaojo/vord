//! The loop's behaviour, proven against fakes.
//!
//! In a file of its own because `runtime.rs` is already the crate's densest
//! module and these tests are the specification of every one of its six
//! terminal states — they deserve to be read as a document, not scrolled past
//! at the bottom of the implementation.
//!
//! The judge here is a *real* `AgentPolicy`, not a stub returning a canned
//! verdict: the point of A2 is that the runtime shares an enforcement engine
//! with the guardrail, and a test that fakes the engine would prove nothing
//! about that.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use yunq_agent_policy::{AgentPolicy, Finding};
use yunq_profiles::Severity;

use super::*;
use crate::session::TokenUsage;

/// The marker a rule fires on, standing in for a real AST vulnerability.
const DANGER: &str = "eval(";

fn rule(raw: &str) -> RuleId {
    RuleId::new(raw).expect("valid rule id")
}

/// A shared in-memory tree, so the workspace the agent writes to and the
/// analyzer that judges it are looking at the same bytes — without that, an
/// "the agent fixed it" test proves only that the fakes were scripted to
/// agree.
#[derive(Clone, Default)]
struct Tree(Arc<Mutex<HashMap<String, String>>>);

impl Tree {
    fn with(files: &[(&str, &str)]) -> Self {
        let tree = Self::default();
        for (path, content) in files {
            tree.0.lock().expect("test mutex is never poisoned").insert((*path).to_string(), (*content).to_string());
        }
        tree
    }

    fn get(&self, path: &str) -> Option<String> {
        self.0.lock().expect("test mutex is never poisoned").get(path).cloned()
    }

    fn snapshot(&self) -> Vec<(String, String)> {
        let mut entries: Vec<(String, String)> =
            self.0.lock().expect("test mutex is never poisoned").iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        entries.sort();
        entries
    }
}

struct FakeWorkspace {
    tree: Tree,
    command: Result<CommandOutput, WorkspaceError>,
    executed: Mutex<Vec<Vec<String>>>,
}

impl FakeWorkspace {
    fn new(tree: Tree) -> Self {
        Self {
            tree,
            command: Ok(CommandOutput { exit_code: Some(0), stdout: "ok".into(), stderr: String::new() }),
            executed: Mutex::new(Vec::new()),
        }
    }

    fn with_command(mut self, command: Result<CommandOutput, WorkspaceError>) -> Self {
        self.command = command;
        self
    }
}

impl Workspace for FakeWorkspace {
    fn read(&self, path: &str) -> Result<String, WorkspaceError> {
        self.tree.get(path).ok_or_else(|| WorkspaceError(format!("no such file `{path}`")))
    }

    fn write(&self, path: &str, content: &str) -> Result<(), WorkspaceError> {
        self.tree.0.lock().expect("test mutex is never poisoned").insert(path.to_string(), content.to_string());
        Ok(())
    }

    fn search(&self, pattern: &str, _path: Option<&str>) -> Result<String, WorkspaceError> {
        Ok(format!("no matches for {pattern}"))
    }

    fn run(&self, program: &str, args: &[String]) -> Result<CommandOutput, WorkspaceError> {
        let mut invocation = vec![program.to_string()];
        invocation.extend_from_slice(args);
        self.executed.lock().expect("test mutex is never poisoned").push(invocation);
        self.command.clone()
    }
}

/// Judges with a real `AgentPolicy`; the findings it feeds the policy are
/// whatever [`DANGER`] appears in the proposed content.
struct MarkerJudge {
    policy: AgentPolicy,
    failing: bool,
}

impl MarkerJudge {
    fn new() -> Self {
        Self { policy: AgentPolicy::default(), failing: false }
    }

    fn failing() -> Self {
        Self { policy: AgentPolicy::default(), failing: true }
    }
}

impl WriteJudge for MarkerJudge {
    async fn judge(&self, path: &str, content: &str) -> Result<Evaluation, JudgeError> {
        if self.failing {
            return Err(JudgeError("policy file is unreadable".into()));
        }
        let findings: Vec<Finding> = content
            .contains(DANGER)
            .then(|| Finding {
                // In the default policy's `blocking_rules`, so it denies at
                // any severity — the same reason a real agent cannot argue
                // its way past this category.
                rule: rule("owasp:eval-usage"),
                severity: Severity::Info,
                message: "eval sink".to_string(),
                line: 1,
            })
            .into_iter()
            .collect();
        Ok(self.policy.evaluate(path, &findings))
    }
}

/// Reports one finding per file still containing [`DANGER`], so the analyzer
/// genuinely disagrees until the agent fixes the file.
struct MarkerAnalyzer {
    tree: Tree,
    failing: bool,
}

impl MarkerAnalyzer {
    fn new(tree: Tree) -> Self {
        Self { tree, failing: false }
    }

    fn failing() -> Self {
        Self { tree: Tree::default(), failing: true }
    }
}

impl Analyzer for MarkerAnalyzer {
    async fn scan(&self, _path: &str) -> Result<Vec<LocatedFinding>, AnalysisError> {
        if self.failing {
            return Err(AnalysisError("no parser for this tree".into()));
        }
        Ok(self
            .tree
            .snapshot()
            .into_iter()
            .filter(|(_, content)| content.contains(DANGER))
            .map(|(file, _)| LocatedFinding {
                file,
                rule: rule("owasp:eval-usage"),
                severity: Severity::Critical,
                message: "eval sink".to_string(),
                line: 1,
            })
            .collect())
    }
}

/// Replays a script of turns. Once the script runs dry it claims completion,
/// which is what a real model does when it thinks it is finished.
struct ScriptedModel {
    turns: Mutex<std::collections::VecDeque<Result<AssistantTurn, ModelError>>>,
    calls: AtomicU32,
    exhausted: AssistantTurn,
}

impl ScriptedModel {
    fn new(turns: Vec<Result<AssistantTurn, ModelError>>) -> Self {
        Self {
            turns: Mutex::new(turns.into()),
            calls: AtomicU32::new(0),
            exhausted: AssistantTurn { text: Some("done".into()), calls: vec![], usage: usage(1) },
        }
    }

    /// Repeats one turn forever — for the budget and loop-guard tests, where
    /// the point is that the *runtime* stops, not that the script ran out.
    fn repeating(turn: AssistantTurn) -> Self {
        Self { turns: Mutex::new(Default::default()), calls: AtomicU32::new(0), exhausted: turn }
    }

    fn call_count(&self) -> u32 {
        self.calls.load(Ordering::Relaxed)
    }
}

impl ChatModel for ScriptedModel {
    async fn next_turn(
        &self,
        _transcript: &Transcript,
        _tools: &[ToolSpec],
    ) -> Result<AssistantTurn, ModelError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        let next = self.turns.lock().expect("test mutex is never poisoned").pop_front();
        next.unwrap_or_else(|| Ok(self.exhausted.clone()))
    }
}

fn usage(total: u64) -> TokenUsage {
    TokenUsage { input: total, output: 0 }
}

fn call(name: &str, input: serde_json::Value) -> ToolCall {
    ToolCall { id: format!("call-{name}"), name: name.to_string(), input }
}

fn turn_calling(name: &str, input: serde_json::Value) -> AssistantTurn {
    AssistantTurn { text: None, calls: vec![call(name, input)], usage: usage(10) }
}

fn write_turn(path: &str, content: &str) -> AssistantTurn {
    turn_calling("write", serde_json::json!({ "path": path, "content": content }))
}

fn config() -> RunConfig {
    RunConfig { scope: ".".to_string(), max_rejections: 1, ..RunConfig::new("remove the eval sink") }
}

fn runtime(
    model: ScriptedModel,
    tree: Tree,
    judge: MarkerJudge,
    config: RunConfig,
) -> AgentRuntime<ScriptedModel, FakeWorkspace, MarkerJudge, MarkerAnalyzer> {
    let workspace = FakeWorkspace::new(tree.clone());
    AgentRuntime::new(model, workspace, judge, MarkerAnalyzer::new(tree), config)
}

#[tokio::test]
async fn a_clean_write_lands_and_the_analyzer_closes_the_task() {
    let tree = Tree::with(&[("src/a.rs", "fn a() { eval(x) }")]);
    let model = ScriptedModel::new(vec![Ok(write_turn("src/a.rs", "fn a() { safe(x) }"))]);
    let outcome = runtime(model, tree.clone(), MarkerJudge::new(), config()).run().await;

    assert!(matches!(outcome, RunOutcome::Completed { .. }), "got {outcome:?}");
    assert_eq!(outcome.exit_code(), 0);
    assert_eq!(tree.get("src/a.rs").as_deref(), Some("fn a() { safe(x) }"));
}

#[tokio::test]
async fn a_denied_write_never_reaches_the_workspace() {
    let tree = Tree::with(&[("src/a.rs", "fn a() {}")]);
    let before = tree.snapshot();
    // One denied write, then the model gives up.
    let model = ScriptedModel::new(vec![Ok(write_turn("src/a.rs", "fn a() { eval(x) }"))]);
    let outcome = runtime(model, tree.clone(), MarkerJudge::new(), config()).run().await;

    assert_eq!(tree.snapshot(), before, "a denied write must not change the tree");
    // The baseline was clean and nothing landed, so nothing regressed: the
    // run completes having done nothing, which is the honest answer.
    assert!(matches!(outcome, RunOutcome::Completed { .. }), "got {outcome:?}");
}

#[tokio::test]
async fn three_consecutive_denials_trip_the_circuit_breaker() {
    let tree = Tree::with(&[("src/a.rs", "fn a() {}")]);
    let model = ScriptedModel::repeating(write_turn("src/a.rs", "fn a() { eval(x) }"));
    let outcome = runtime(model, tree.clone(), MarkerJudge::new(), config()).run().await;

    let RunOutcome::CircuitBreakerTripped { rules, .. } = &outcome else {
        panic!("expected the breaker to trip, got {outcome:?}");
    };
    assert_eq!(rules, &vec![rule("owasp:eval-usage")]);
    assert_eq!(outcome.exit_code(), 5);
    assert_eq!(tree.get("src/a.rs").as_deref(), Some("fn a() {}"));
}

#[tokio::test]
async fn three_identical_allowed_writes_stop_the_run_as_a_loop() {
    // Every write is policy-clean, so the breaker never fires; only the
    // repeat guard can catch this.
    let tree = Tree::with(&[("src/a.rs", "fn a() { eval(x) }")]);
    let model = ScriptedModel::repeating(write_turn("src/a.rs", "fn a() { still_broken(x) }"));
    let mut config = config();
    config.target_rule = Some(rule("owasp:eval-usage"));
    let outcome = runtime(model, tree, MarkerJudge::new(), config).run().await;

    let RunOutcome::Looping { path, .. } = &outcome else { panic!("expected a loop stop, got {outcome:?}") };
    assert_eq!(path, "src/a.rs");
    assert_eq!(outcome.exit_code(), 6);
}

#[tokio::test]
async fn the_turn_budget_ends_the_run_with_its_own_verdict() {
    let tree = Tree::with(&[("src/a.rs", "fn a() { eval(x) }")]);
    let model = ScriptedModel::repeating(turn_calling("read", serde_json::json!({ "path": "src/a.rs" })));
    let mut config = config();
    config.budget = Budget { max_turns: 2, max_tokens: u64::MAX };
    let outcome = runtime(model, tree, MarkerJudge::new(), config).run().await;

    assert_eq!(outcome, RunOutcome::BudgetExhausted { turns: 2, exhaustion: Exhaustion::Turns { limit: 2 } });
    assert_eq!(outcome.exit_code(), 4);
}

#[tokio::test]
async fn the_token_budget_ends_the_run_with_its_own_verdict() {
    let tree = Tree::with(&[("src/a.rs", "fn a() { eval(x) }")]);
    let model = ScriptedModel::repeating(turn_calling("read", serde_json::json!({ "path": "src/a.rs" })));
    let mut config = config();
    config.budget = Budget { max_turns: u32::MAX, max_tokens: 25 };
    let outcome = runtime(model, tree, MarkerJudge::new(), config).run().await;

    assert!(
        matches!(outcome, RunOutcome::BudgetExhausted { exhaustion: Exhaustion::Tokens { .. }, .. }),
        "got {outcome:?}"
    );
}

#[tokio::test]
async fn the_analyzer_sends_the_model_back_and_then_declares_the_task_incomplete() {
    // The model claims completion without touching the file; the analyzer
    // still sees the target rule, so the run must not succeed.
    let tree = Tree::with(&[("src/a.rs", "fn a() { eval(x) }")]);
    let model = ScriptedModel::new(vec![]);
    let mut config = config();
    config.target_rule = Some(rule("owasp:eval-usage"));
    config.max_rejections = 2;
    let runtime = runtime(model, tree, MarkerJudge::new(), config);
    let outcome = runtime.run().await;

    let RunOutcome::Incomplete { completion, .. } = &outcome else {
        panic!("a model's own say-so must not complete a task, got {outcome:?}")
    };
    assert!(matches!(completion, Completion::TargetRemains { .. }));
    assert_eq!(outcome.exit_code(), 3);
}

#[tokio::test]
async fn a_regression_the_agent_introduced_blocks_completion() {
    // Baseline is clean; the agent writes a *policy-clean* file that the
    // analyzer nonetheless flags, which is exactly the "passed the gate,
    // failed the analysis" case A3 exists for. The marker analyzer and the
    // marker judge disagree here only because the judge sees content and the
    // analyzer sees the tree — the same split the real adapters have.
    // A judge that allows everything, so only the analyzer can object.
    async fn run_edit_inserting(text: &str) -> RunOutcome {
        let tree = Tree::with(&[("src/a.rs", "fn a() {}")]);
        let model = ScriptedModel::new(vec![Ok(turn_calling(
            "edit",
            serde_json::json!({ "path": "src/a.rs", "old_string": "{}", "new_string": text }),
        ))]);
        let permissive =
            MarkerJudge { policy: AgentPolicy::parse("[agent]\nenabled = false\n").expect("valid policy"), failing: false };
        let config = RunConfig { max_rejections: 0, ..config() };
        AgentRuntime::new(model, FakeWorkspace::new(tree.clone()), permissive, MarkerAnalyzer::new(tree), config)
            .run()
            .await
    }

    // `EVAL(` does not contain `eval(`, so nothing regresses and the run
    // completes — the control half of this test.
    assert!(matches!(run_edit_inserting("{ EVAL(x) }").await, RunOutcome::Completed { .. }));

    let outcome = run_edit_inserting("{ eval(x) }").await;
    let RunOutcome::Incomplete { completion, .. } = &outcome else {
        panic!("an introduced finding must block completion, got {outcome:?}")
    };
    assert!(matches!(completion, Completion::Regressed { .. }));
}

#[tokio::test]
async fn a_model_failure_is_reported_as_a_failure_not_a_verdict() {
    let tree = Tree::with(&[("src/a.rs", "fn a() {}")]);
    let model = ScriptedModel::new(vec![Err(ModelError("429 rate limited".into()))]);
    let outcome = runtime(model, tree, MarkerJudge::new(), config()).run().await;

    let RunOutcome::Failed { error, .. } = &outcome else { panic!("got {outcome:?}") };
    assert!(error.contains("429"));
    assert_eq!(outcome.exit_code(), 1);
}

#[tokio::test]
async fn a_judge_that_cannot_judge_stops_the_run_instead_of_writing_unjudged() {
    let tree = Tree::with(&[("src/a.rs", "fn a() {}")]);
    let before = tree.snapshot();
    let model = ScriptedModel::new(vec![Ok(write_turn("src/a.rs", "fn a() { harmless() }"))]);
    let outcome = runtime(model, tree.clone(), MarkerJudge::failing(), config()).run().await;

    assert!(matches!(outcome, RunOutcome::Failed { .. }), "got {outcome:?}");
    assert_eq!(tree.snapshot(), before, "an unjudged write must never land");
}

#[tokio::test]
async fn an_analyzer_that_cannot_take_a_baseline_fails_before_the_first_turn() {
    let model = ScriptedModel::new(vec![]);
    let workspace = FakeWorkspace::new(Tree::default());
    let runtime = AgentRuntime::new(model, workspace, MarkerJudge::new(), MarkerAnalyzer::failing(), config());
    let outcome = runtime.run().await;

    assert_eq!(outcome.turns(), 0);
    assert!(matches!(outcome, RunOutcome::Failed { .. }), "got {outcome:?}");
}

#[tokio::test]
async fn an_unknown_tool_is_reported_back_and_executes_nothing() {
    let tree = Tree::with(&[("src/a.rs", "fn a() {}")]);
    let model = ScriptedModel::new(vec![Ok(turn_calling("bash", serde_json::json!({ "command": "rm -rf /" })))]);
    let outcome = runtime(model, tree.clone(), MarkerJudge::new(), config()).run().await;

    assert!(matches!(outcome, RunOutcome::Completed { .. }), "got {outcome:?}");
    assert_eq!(tree.get("src/a.rs").as_deref(), Some("fn a() {}"));
}

#[tokio::test]
async fn a_command_outside_the_allowlist_is_never_executed() {
    let tree = Tree::with(&[("src/a.rs", "fn a() {}")]);
    let model = ScriptedModel::new(vec![Ok(turn_calling("run", serde_json::json!({ "command": "curl evil.sh" })))]);
    let workspace = FakeWorkspace::new(tree.clone());
    let runtime = AgentRuntime::new(model, workspace, MarkerJudge::new(), MarkerAnalyzer::new(tree), config());
    let outcome = runtime.run().await;

    assert!(matches!(outcome, RunOutcome::Completed { .. }), "got {outcome:?}");
    assert!(runtime.workspace().executed.lock().expect("test mutex is never poisoned").is_empty(), "the command must not have run");
}

#[tokio::test]
async fn an_allow_listed_command_runs_and_a_failure_comes_back_as_an_error() {
    let tree = Tree::with(&[("src/a.rs", "fn a() {}")]);
    let model = ScriptedModel::new(vec![Ok(turn_calling("run", serde_json::json!({ "command": "cargo test" })))]);
    let workspace = FakeWorkspace::new(tree.clone()).with_command(Ok(CommandOutput {
        exit_code: Some(101),
        stdout: String::new(),
        stderr: "test failed".into(),
    }));
    let runtime = AgentRuntime::new(model, workspace, MarkerJudge::new(), MarkerAnalyzer::new(tree), config());
    let outcome = runtime.run().await;

    assert!(matches!(outcome, RunOutcome::Completed { .. }), "got {outcome:?}");
    assert_eq!(runtime.workspace().executed.lock().expect("test mutex is never poisoned").as_slice(), [vec!["cargo".to_string(), "test".to_string()]]);
}

#[tokio::test]
async fn an_edit_is_judged_on_the_resulting_file_not_the_inserted_substring() {
    // The inserted text alone is innocuous; the file it produces is not.
    let tree = Tree::with(&[("src/a.rs", "fn a() { ev")]);
    let before = tree.snapshot();
    let model = ScriptedModel::new(vec![Ok(turn_calling(
        "edit",
        serde_json::json!({ "path": "src/a.rs", "old_string": "ev", "new_string": "eval(x) }" }),
    ))]);
    let outcome = runtime(model, tree.clone(), MarkerJudge::new(), config()).run().await;

    assert_eq!(tree.snapshot(), before, "the edit's *result* violates policy and must be denied");
    assert!(matches!(outcome, RunOutcome::Completed { .. }), "got {outcome:?}");
}

#[tokio::test]
async fn an_edit_whose_target_string_is_absent_is_an_error_rather_than_a_write() {
    let tree = Tree::with(&[("src/a.rs", "fn a() {}")]);
    let before = tree.snapshot();
    let model = ScriptedModel::new(vec![Ok(turn_calling(
        "edit",
        serde_json::json!({ "path": "src/a.rs", "old_string": "nowhere", "new_string": "x" }),
    ))]);
    let outcome = runtime(model, tree.clone(), MarkerJudge::new(), config()).run().await;

    assert_eq!(tree.snapshot(), before);
    assert!(matches!(outcome, RunOutcome::Completed { .. }), "got {outcome:?}");
}

#[tokio::test]
async fn the_model_is_asked_again_after_the_analyzer_objects() {
    let tree = Tree::with(&[("src/a.rs", "fn a() { eval(x) }")]);
    let model = ScriptedModel::new(vec![]);
    let mut config = config();
    config.target_rule = Some(rule("owasp:eval-usage"));
    config.max_rejections = 2;
    let workspace = FakeWorkspace::new(tree.clone());
    let runtime = AgentRuntime::new(model, workspace, MarkerJudge::new(), MarkerAnalyzer::new(tree), config);
    runtime.run().await;

    // Three turns: the first claim plus two more after the analyzer sent it
    // back — the model does not get to stop on its own say-so.
    assert_eq!(runtime.model().call_count(), 3);
}

#[test]
fn every_terminal_state_has_its_own_exit_code() {
    let outcomes = [
        RunOutcome::Completed { turns: 1, summary: None },
        RunOutcome::Failed { turns: 1, error: "x".into() },
        RunOutcome::Incomplete { turns: 1, completion: Completion::Done },
        RunOutcome::BudgetExhausted { turns: 1, exhaustion: Exhaustion::Turns { limit: 1 } },
        RunOutcome::CircuitBreakerTripped { turns: 1, rules: vec![] },
        RunOutcome::Looping { turns: 1, path: "a".into() },
    ];
    let mut codes: Vec<u8> = outcomes.iter().map(RunOutcome::exit_code).collect();
    let total = codes.len();
    codes.sort_unstable();
    codes.dedup();
    assert_eq!(codes.len(), total, "two outcomes share an exit code");
    for outcome in &outcomes {
        assert_eq!(outcome.turns(), 1);
        assert!(!outcome.describe().is_empty());
    }
}

#[test]
fn a_command_killed_by_a_signal_is_not_reported_as_a_clean_exit() {
    let output = CommandOutput { exit_code: None, stdout: String::new(), stderr: String::new() };
    assert!(output.render().contains("terminated by signal"));
}
