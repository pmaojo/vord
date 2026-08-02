//! The session loop (roadmap A1), and the place A2–A4 are enforced.
//!
//! Pure orchestration over four ports — a chat model, a workspace, a write
//! judge and an analyzer — so the whole loop, including every stopping
//! condition, is unit-testable against fakes with no network, no filesystem
//! and no clock. The composition root (`bin/cli`'s `agent` module) supplies
//! the real adapters; nothing in this file knows they exist.
//!
//! The invariant this module exists to hold: **no `Workspace::write` call is
//! reachable except through [`AgentRuntime::apply_write`], and that function
//! consults the judge first.** Every other route to disk would be a way for
//! the agent to outrun its own referee.

use std::future::Future;

use vord_agent_policy::{CircuitBreakerState, Evaluation};
use vord_profiles::RuleId;

use crate::budget::{Budget, Exhaustion, Ledger, RepeatGuard};
use crate::completion::{self, Completion, LocatedFinding};
use crate::gate::{advisory_note, denial_feedback};
use crate::observer::{AgentEvent, NoopObserver, Observer};
use crate::prompt::{system_prompt, task_prompt};
use crate::session::{AssistantTurn, ToolCall, ToolResult, Transcript};
use crate::tools::{CommandAllowlist, ToolInvocation, ToolSpec, tool_specs};

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("model error: {0}")]
pub struct ModelError(pub String);

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("workspace error: {0}")]
pub struct WorkspaceError(pub String);

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("policy evaluation error: {0}")]
pub struct JudgeError(pub String);

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("analysis error: {0}")]
pub struct AnalysisError(pub String);

/// What a `run` tool call produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommandOutput {
    /// `None` when the process was killed by a signal — distinct from
    /// `Some(0)`, and the difference is the model's to know.
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

impl CommandOutput {
    pub fn render(&self) -> String {
        let status = match self.exit_code {
            Some(code) => format!("exit {code}"),
            None => "terminated by signal".to_string(),
        };
        format!(
            "{status}\n--- stdout ---\n{}\n--- stderr ---\n{}",
            self.stdout, self.stderr
        )
    }
}

/// Outbound port: the conversation with a tool-calling model.
pub trait ChatModel: Send + Sync {
    fn next_turn(
        &self,
        transcript: &Transcript,
        tools: &[ToolSpec],
    ) -> impl Future<Output = Result<AssistantTurn, ModelError>> + Send;
}

/// Outbound port: the tree the agent edits.
///
/// Synchronous on purpose. These are filesystem and process operations in a
/// single-task CLI run; wrapping them in futures would buy nothing but would
/// cost every test a runtime.
pub trait Workspace: Send + Sync {
    fn read(&self, path: &str) -> Result<String, WorkspaceError>;
    /// Never called directly by the loop — see this module's invariant.
    fn write(&self, path: &str, content: &str) -> Result<(), WorkspaceError>;
    fn search(&self, pattern: &str, path: Option<&str>) -> Result<String, WorkspaceError>;
    fn run(&self, program: &str, args: &[String]) -> Result<CommandOutput, WorkspaceError>;
}

/// Outbound port: the Agent Permission Policy, evaluated on proposed content
/// that has not been written. The adapter is `vord hook`'s own judgement path
/// — same policy file, same provenance ledger, same Gherkin evidence, same
/// approvals — so this runtime cannot drift from the guardrail it ships.
pub trait WriteJudge: Send + Sync {
    fn judge(
        &self,
        path: &str,
        content: &str,
    ) -> impl Future<Output = Result<Evaluation, JudgeError>> + Send;
}

/// Outbound port: the analyzer, over a path on disk.
pub trait Analyzer: Send + Sync {
    fn scan(
        &self,
        path: &str,
    ) -> impl Future<Output = Result<Vec<LocatedFinding>, AnalysisError>> + Send;
}

/// One run's parameters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunConfig {
    pub task: String,
    /// The path the analyzer takes its baseline over and re-scans to decide
    /// completion.
    pub scope: String,
    /// The rule the task must eliminate, when the task names one.
    pub target_rule: Option<RuleId>,
    pub budget: Budget,
    pub allowlist: CommandAllowlist,
    /// How many times the analyzer may send the model back before the run is
    /// declared [`RunOutcome::Incomplete`]. Bounded because an agent that
    /// cannot satisfy the analyzer twice usually cannot satisfy it at all,
    /// and the budget is a blunter instrument than it needs to be here.
    pub max_rejections: u32,
}

impl RunConfig {
    pub fn new(task: impl Into<String>) -> Self {
        Self {
            task: task.into(),
            scope: ".".to_string(),
            target_rule: None,
            budget: Budget::default(),
            allowlist: CommandAllowlist::default(),
            max_rejections: 3,
        }
    }
}

/// How a run ended. Six variants, not two: an operator (and workstream B's
/// orchestrator) has to be able to tell "the analyzer disagreed" from "we ran
/// out of budget" from "vord itself failed", and collapsing them into a
/// boolean is how a fail-open guardrail becomes a fail-blind one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RunOutcome {
    /// The analyzer agrees. The only success.
    Completed {
        turns: u32,
        summary: Option<String>,
    },
    /// The model stopped, the analyzer did not agree, and the model could not
    /// close the gap within `max_rejections`.
    Incomplete {
        turns: u32,
        completion: Completion,
    },
    BudgetExhausted {
        turns: u32,
        exhaustion: Exhaustion,
    },
    /// The circuit breaker tripped: one rule denied the agent three times
    /// running.
    CircuitBreakerTripped {
        turns: u32,
        rules: Vec<RuleId>,
    },
    /// The same bytes written to the same path three times running.
    Looping {
        turns: u32,
        path: String,
    },
    /// vord, the model or the workspace failed. Never conflated with a
    /// verdict — "we could not look" is not "we looked and saw nothing".
    Failed {
        turns: u32,
        error: String,
    },
}

impl RunOutcome {
    /// Distinct exit codes, so a CI step or a swarm supervisor can branch on
    /// the outcome without parsing prose. `1` stays "vord broke", matching
    /// `vord hook check`'s convention.
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::Completed { .. } => 0,
            Self::Failed { .. } => 1,
            Self::Incomplete { .. } => 3,
            Self::BudgetExhausted { .. } => 4,
            Self::CircuitBreakerTripped { .. } => 5,
            Self::Looping { .. } => 6,
        }
    }

    pub fn turns(&self) -> u32 {
        match self {
            Self::Completed { turns, .. }
            | Self::Incomplete { turns, .. }
            | Self::BudgetExhausted { turns, .. }
            | Self::CircuitBreakerTripped { turns, .. }
            | Self::Looping { turns, .. }
            | Self::Failed { turns, .. } => *turns,
        }
    }

    pub fn describe(&self) -> String {
        match self {
            Self::Completed { summary, .. } => {
                format!(
                    "complete — the analyzer agrees. {}",
                    summary.as_deref().unwrap_or("")
                )
            }
            Self::Incomplete { completion, .. } => {
                format!("incomplete — {}", completion.describe())
            }
            Self::BudgetExhausted { exhaustion, .. } => exhaustion.to_string(),
            Self::CircuitBreakerTripped { rules, .. } => crate::gate::circuit_breaker_stop(rules),
            Self::Looping { path, .. } => {
                format!(
                    "stopped: the agent wrote identical content to `{path}` three times running"
                )
            }
            Self::Failed { error, .. } => format!("failed: {error}"),
        }
    }
}

/// Either an answer for the model, or the end of the run.
enum Step {
    Answer(ToolResult),
    Stop(RunOutcome),
}

pub struct AgentRuntime<M, W, J, A> {
    model: M,
    tools: WorkspaceTools<W>,
    judge: J,
    analyzer: A,
    config: RunConfig,
    /// Told what already happened, after every decision — see
    /// [`crate::observer`]'s module docs for why this can never become a
    /// second control path. `NoopObserver` by default, so a headless run
    /// (every caller before A6) pays nothing for the port existing.
    observer: Box<dyn Observer>,
}

impl<M, W, J, A> AgentRuntime<M, W, J, A>
where
    M: ChatModel,
    W: Workspace,
    J: WriteJudge,
    A: Analyzer,
{
    pub fn new(model: M, workspace: W, judge: J, analyzer: A, config: RunConfig) -> Self {
        let tools = WorkspaceTools {
            workspace,
            allowlist: config.allowlist.clone(),
        };
        Self {
            model,
            tools,
            judge,
            analyzer,
            config,
            observer: Box::new(NoopObserver),
        }
    }

    /// Swaps in an observer that watches this run — `vord agent tui`
    /// (roadmap A6) is the first caller, but any `Observer` (a log line, a
    /// test spy) works identically.
    pub fn with_observer(mut self, observer: impl Observer + 'static) -> Self {
        self.observer = Box::new(observer);
        self
    }

    /// Borrowed by the loop's own tests to assert on what the adapters were
    /// actually asked to do — "the command never ran" is not observable from
    /// the outcome alone.
    #[cfg(test)]
    fn model(&self) -> &M {
        &self.model
    }

    #[cfg(test)]
    fn workspace(&self) -> &W {
        &self.tools.workspace
    }

    /// Runs the session to one of the six terminal states. Never panics and
    /// never returns `Err`: every failure mode is a [`RunOutcome`], because a
    /// caller that has to distinguish six endings should not also have to
    /// distinguish "returned an error" as a seventh.
    pub async fn run(&self) -> RunOutcome {
        let baseline = match self.analyzer.scan(&self.config.scope).await {
            Ok(findings) => findings,
            Err(error) => {
                let outcome = RunOutcome::Failed {
                    turns: 0,
                    error: error.to_string(),
                };
                self.observer.on_event(AgentEvent::Finished {
                    outcome: outcome.clone(),
                });
                return outcome;
            }
        };

        let mut state = LoopState::new(&self.config);
        let specs = tool_specs();
        let outcome = loop {
            if let Some(outcome) = self.turn(&baseline, &specs, &mut state).await {
                break outcome;
            }
        };
        self.observer.on_event(AgentEvent::Finished {
            outcome: outcome.clone(),
        });
        outcome
    }

    /// One iteration: spend budget, ask the model, then either adjudicate its
    /// claim of completion or execute what it asked for. `None` means the run
    /// continues.
    async fn turn(
        &self,
        baseline: &[LocatedFinding],
        specs: &[ToolSpec],
        state: &mut LoopState,
    ) -> Option<RunOutcome> {
        if let Some(exhaustion) = state.ledger.exhausted(&self.config.budget) {
            return Some(RunOutcome::BudgetExhausted {
                turns: state.ledger.turns(),
                exhaustion,
            });
        }
        self.observer.on_event(AgentEvent::TurnStarted {
            turn: state.ledger.turns() + 1,
        });
        let turn = match self.model.next_turn(&state.transcript, specs).await {
            Ok(turn) => turn,
            Err(error) => {
                return Some(RunOutcome::Failed {
                    turns: state.ledger.turns(),
                    error: error.to_string(),
                });
            }
        };
        state.ledger.record_turn(turn.usage);
        state.transcript.push_assistant(&turn);
        self.observer
            .on_event(AgentEvent::ModelResponded { turn: turn.clone() });

        if turn.claims_completion() {
            return self.adjudicate(baseline, &turn, state).await;
        }
        match self.execute_turn(&turn, state).await {
            Ok(results) => {
                state.transcript.push_tool_results(results);
                None
            }
            Err(outcome) => Some(outcome),
        }
    }

    /// The model stopped calling tools. Re-scan, compare against the
    /// baseline, and either finish or send it back with the analyzer's
    /// objection — never with a request to grade itself.
    async fn adjudicate(
        &self,
        baseline: &[LocatedFinding],
        turn: &AssistantTurn,
        state: &mut LoopState,
    ) -> Option<RunOutcome> {
        let turns = state.ledger.turns();
        let current = match self.analyzer.scan(&self.config.scope).await {
            Ok(findings) => findings,
            Err(error) => {
                return Some(RunOutcome::Failed {
                    turns,
                    error: error.to_string(),
                });
            }
        };
        let verdict = completion::judge(baseline, &current, self.config.target_rule.as_ref());
        self.observer.on_event(AgentEvent::Adjudicated {
            completion: verdict.clone(),
        });
        if verdict.is_done() {
            return Some(RunOutcome::Completed {
                turns,
                summary: turn.text.clone(),
            });
        }
        state.rejections += 1;
        if state.rejections > self.config.max_rejections {
            return Some(RunOutcome::Incomplete {
                turns,
                completion: verdict,
            });
        }
        state.transcript.push_user(format!(
            "{}\nKeep working: this session does not end until the analyzer agrees.",
            verdict.describe()
        ));
        None
    }

    /// Executes every call in one turn, stopping the whole run the moment a
    /// stopping condition fires rather than finishing the batch.
    async fn execute_turn(
        &self,
        turn: &AssistantTurn,
        state: &mut LoopState,
    ) -> Result<Vec<ToolResult>, RunOutcome> {
        let mut results = Vec::with_capacity(turn.calls.len());
        for call in &turn.calls {
            match self.execute_call(call, state).await {
                Step::Answer(result) => results.push(result),
                Step::Stop(outcome) => return Err(outcome),
            }
        }
        Ok(results)
    }

    async fn execute_call(&self, call: &ToolCall, state: &mut LoopState) -> Step {
        self.observer
            .on_event(AgentEvent::ToolCallStarted { call: call.clone() });
        let step = self.execute_call_inner(call, state).await;
        if let Step::Answer(result) = &step {
            self.observer.on_event(AgentEvent::ToolCallFinished {
                result: result.clone(),
            });
        }
        step
    }

    async fn execute_call_inner(&self, call: &ToolCall, state: &mut LoopState) -> Step {
        let invocation = match ToolInvocation::parse(&call.name, &call.input) {
            Ok(invocation) => invocation,
            Err(error) => return Step::Answer(ToolResult::error(&call.id, error.to_string())),
        };
        match invocation {
            ToolInvocation::Read { path } => Step::Answer(self.tools.read(&call.id, &path)),
            ToolInvocation::Search { pattern, path } => {
                Step::Answer(self.tools.search(&call.id, &pattern, path.as_deref()))
            }
            ToolInvocation::Run { command } => {
                Step::Answer(self.tools.run_command(&call.id, &command))
            }
            ToolInvocation::Scan { path } => Step::Answer(self.scan(&call.id, &path).await),
            ToolInvocation::Write { path, content } => {
                self.apply_write(&call.id, &path, content, state).await
            }
            ToolInvocation::Edit {
                path,
                old_string,
                new_string,
                replace_all,
            } => {
                self.apply_edit(call, &path, (&old_string, &new_string, replace_all), state)
                    .await
            }
        }
    }

    /// An `edit` becomes a `write` of the resulting file — the policy
    /// evaluates files, not diffs, and an edit whose *result* violates policy
    /// must be denied even though the substring it inserted looks harmless in
    /// isolation.
    async fn apply_edit(
        &self,
        call: &ToolCall,
        path: &str,
        replacement: (&str, &str, bool),
        state: &mut LoopState,
    ) -> Step {
        match self.tools.resolve_edit(&call.id, path, replacement) {
            Ok(content) => self.apply_write(&call.id, path, content, state).await,
            Err(result) => Step::Answer(result),
        }
    }

    async fn scan(&self, call_id: &str, path: &str) -> ToolResult {
        match self.analyzer.scan(path).await {
            Ok(findings) if findings.is_empty() => {
                ToolResult::ok(call_id, format!("no findings in `{path}`"))
            }
            Ok(findings) => {
                let lines: Vec<String> = findings.iter().map(LocatedFinding::describe).collect();
                ToolResult::ok(call_id, lines.join("\n"))
            }
            Err(error) => ToolResult::error(call_id, error.to_string()),
        }
    }

    /// The only path to disk. Judge, then write — never the other way round,
    /// and never one without the other.
    async fn apply_write(
        &self,
        call_id: &str,
        path: &str,
        content: String,
        state: &mut LoopState,
    ) -> Step {
        let evaluation = match self.judge.judge(path, &content).await {
            Ok(evaluation) => evaluation,
            // A judge that cannot judge fails the run rather than the write:
            // silently allowing an unjudged write is precisely the failure
            // this runtime exists to make impossible.
            Err(error) => {
                return Step::Stop(RunOutcome::Failed {
                    turns: state.ledger.turns(),
                    error: error.to_string(),
                });
            }
        };
        self.observer.on_event(AgentEvent::WriteJudged {
            path: path.to_string(),
            evaluation: evaluation.clone(),
        });
        let tripped = state.breaker.record(&evaluation);
        if evaluation.is_denied() {
            if !tripped.is_empty() {
                return Step::Stop(RunOutcome::CircuitBreakerTripped {
                    turns: state.ledger.turns(),
                    rules: tripped,
                });
            }
            return Step::Answer(ToolResult::error(
                call_id,
                denial_feedback(path, &evaluation),
            ));
        }
        if state.repeats.record(path, &content) {
            return Step::Stop(RunOutcome::Looping {
                turns: state.ledger.turns(),
                path: path.to_string(),
            });
        }
        match self.tools.workspace.write(path, &content) {
            Ok(()) => Step::Answer(ToolResult::ok(
                call_id,
                format!(
                    "wrote {} bytes to `{path}`{}",
                    content.len(),
                    advisory_note(&evaluation)
                ),
            )),
            Err(error) => Step::Answer(ToolResult::error(call_id, error.to_string())),
        }
    }
}

/// The tools that need nothing but the workspace.
///
/// Split out from [`AgentRuntime`] so the runtime's own methods are exactly
/// the ones that need a judge, an analyzer or the model — which is what makes
/// [`AgentRuntime::apply_write`] the only function in the crate holding both
/// a `Workspace` and a `WriteJudge`, and therefore the only place a write can
/// possibly happen.
struct WorkspaceTools<W> {
    workspace: W,
    allowlist: CommandAllowlist,
}

impl<W: Workspace> WorkspaceTools<W> {
    fn read(&self, call_id: &str, path: &str) -> ToolResult {
        match self.workspace.read(path) {
            Ok(content) => ToolResult::ok(call_id, content),
            Err(error) => ToolResult::error(call_id, error.to_string()),
        }
    }

    fn search(&self, call_id: &str, pattern: &str, path: Option<&str>) -> ToolResult {
        match self.workspace.search(pattern, path) {
            Ok(hits) => ToolResult::ok(call_id, hits),
            Err(error) => ToolResult::error(call_id, error.to_string()),
        }
    }

    /// `run`, narrowed twice: the allowlist decides whether the command may
    /// execute at all, and a non-zero exit comes back flagged as an error so
    /// a failing test suite cannot read as success.
    fn run_command(&self, call_id: &str, command: &str) -> ToolResult {
        let parts = match self.allowlist.admit(command) {
            Ok(parts) => parts,
            Err(rejection) => return ToolResult::error(call_id, rejection.to_string()),
        };
        let (program, args) = parts.split_first().expect("admit rejects an empty command");
        match self.workspace.run(program, args) {
            Ok(output) => {
                let rendered = output.render();
                if output.exit_code == Some(0) {
                    ToolResult::ok(call_id, rendered)
                } else {
                    ToolResult::error(call_id, rendered)
                }
            }
            Err(error) => ToolResult::error(call_id, error.to_string()),
        }
    }

    /// Reads the file and applies the replacement, producing the content the
    /// judge will see. `(old, new, replace_all)` travels as one tuple because
    /// three adjacent strings in a signature is how a caller eventually swaps
    /// two of them.
    fn resolve_edit(
        &self,
        call_id: &str,
        path: &str,
        (old_string, new_string, replace_all): (&str, &str, bool),
    ) -> Result<String, ToolResult> {
        let current = self
            .workspace
            .read(path)
            .map_err(|error| ToolResult::error(call_id, error.to_string()))?;
        if !current.contains(old_string) {
            return Err(ToolResult::error(
                call_id,
                format!("`{path}` does not contain the string to replace"),
            ));
        }
        Ok(if replace_all {
            current.replace(old_string, new_string)
        } else {
            current.replacen(old_string, new_string, 1)
        })
    }
}

/// Everything that changes as the loop turns.
struct LoopState {
    transcript: Transcript,
    ledger: Ledger,
    breaker: CircuitBreakerState,
    repeats: RepeatGuard,
    rejections: u32,
}

impl LoopState {
    fn new(config: &RunConfig) -> Self {
        let mut transcript = Transcript::new(system_prompt(&config.allowlist));
        transcript.push_user(task_prompt(
            &config.task,
            &config.scope,
            config.target_rule.as_ref().map(RuleId::as_str),
        ));
        Self {
            transcript,
            ledger: Ledger::default(),
            breaker: CircuitBreakerState::default(),
            repeats: RepeatGuard::default(),
            rejections: 0,
        }
    }
}

#[cfg(test)]
#[path = "runtime_tests.rs"]
mod tests;
