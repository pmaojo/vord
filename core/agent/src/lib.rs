//! `vord agent` — the runtime that writes code and cannot approve its own
//! work.
//!
//! Every coding agent on the market grades its own homework: the model
//! proposes an edit, the model decides the edit is good, and the verification
//! is a second prompt to the same weights. vord is the one project where the
//! judge already exists as a separate, deterministic artifact that predates
//! the writer — so this runtime is built around two constraints it cannot
//! talk its way out of:
//!
//! 1. **No edit reaches disk without passing `core/agent-policy`.** The same
//!    `vord-policy.toml` that gates a third-party agent through `vord hook`
//!    gates this one, evaluated in-process on the proposed content before the
//!    write syscall ([`gate`], enforced in [`runtime`]).
//! 2. **No task is complete without the analyzer agreeing.** When the model
//!    stops calling tools, the analyzer re-runs and its findings are compared
//!    against the baseline taken before the run started ([`completion`]).
//!    There is no self-assessment turn, ever.
//!
//! Pure by construction, like the rest of `core/`: no filesystem, no network,
//! no clock, no process spawning. The model, the workspace, the policy judge
//! and the analyzer are all outbound ports ([`runtime::ChatModel`],
//! [`runtime::Workspace`], [`runtime::WriteJudge`], [`runtime::Analyzer`]);
//! `bin/cli`'s `agent` module is the composition root that supplies the real
//! ones.

pub mod budget;
pub mod completion;
pub mod feedback;
pub mod gate;
pub mod observer;
pub mod prompt;
pub mod runtime;
pub mod session;
pub mod tools;

pub use budget::{Budget, Exhaustion, Ledger, RepeatGuard};
pub use completion::{Completion, LocatedFinding};
pub use observer::{AgentEvent, NoopObserver, Observer};
pub use runtime::{
    AgentRuntime, AnalysisError, Analyzer, ChatModel, CommandOutput, JudgeError, ModelError,
    RunConfig, RunOutcome, Workspace, WorkspaceError, WriteJudge,
};
pub use session::{AssistantTurn, Message, TokenUsage, ToolCall, ToolResult, Transcript};
pub use tools::{
    CommandAllowlist, CommandRejection, ToolInputError, ToolInvocation, ToolName, ToolSpec,
};
