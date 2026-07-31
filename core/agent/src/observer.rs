//! Live progress reporting (roadmap A6) — the port `yunq agent tui` renders
//! against, and nothing else.
//!
//! An [`Observer`] is purely downstream: it is told what already happened
//! after every decision the loop already made, never consulted before one.
//! That ordering matters because it is what keeps the TUI a spectator rather
//! than a second control path — a run headless (`NoopObserver`) and the same
//! run watched (a TUI's observer) must reach the identical [`RunOutcome`],
//! and the type signature enforces that: [`Observer::on_event`] returns
//! nothing for the loop to branch on.

use crate::completion::Completion;
use crate::runtime::RunOutcome;
use crate::session::{AssistantTurn, ToolCall, ToolResult};
use yunq_agent_policy::Evaluation;

/// Something worth showing a human (or a test spy) about a run in progress.
/// Carries owned data rather than references so an observer may buffer,
/// forward across a channel, or serialize an event without borrowing back
/// into a loop that has already moved on to the next turn.
#[derive(Clone, Debug)]
pub enum AgentEvent {
    /// A new turn is about to ask the model for its next move.
    TurnStarted { turn: u32 },
    /// The model answered — either more tool calls, or a claim of completion.
    ModelResponded { turn: AssistantTurn },
    /// One call from the current turn is about to run.
    ToolCallStarted { call: ToolCall },
    /// A tool call finished, successfully or not.
    ToolCallFinished { result: ToolResult },
    /// A proposed write was judged (not necessarily applied — see
    /// `evaluation.is_denied()`).
    WriteJudged {
        path: String,
        evaluation: Evaluation,
    },
    /// The model claimed completion and the analyzer ruled on the claim.
    Adjudicated { completion: Completion },
    /// The run reached one of its six terminal states.
    Finished { outcome: RunOutcome },
}

/// Outbound port: told what happened, decides nothing. `Send + Sync` so one
/// observer can be shared across the async runtime without the loop caring
/// how it delivers events (a channel, a lock, a no-op).
pub trait Observer: Send + Sync {
    fn on_event(&self, event: AgentEvent);
}

/// The default: a run with nothing watching costs nothing beyond the
/// function call itself.
#[derive(Default)]
pub struct NoopObserver;

impl Observer for NoopObserver {
    fn on_event(&self, _event: AgentEvent) {}
}

/// Any `Fn(AgentEvent)` is an observer — lets a test or a small caller pass a
/// closure instead of naming a type.
impl<F: Fn(AgentEvent) + Send + Sync> Observer for F {
    fn on_event(&self, event: AgentEvent) {
        self(event)
    }
}

/// An `Arc<Observer>` is an observer too, so a caller that needs to keep its
/// own handle (a TUI reading the same events it just forwarded) can clone the
/// `Arc` into [`crate::runtime::AgentRuntime::with_observer`] instead of
/// giving the runtime sole ownership.
impl<T: Observer + ?Sized> Observer for std::sync::Arc<T> {
    fn on_event(&self, event: AgentEvent) {
        T::on_event(self, event)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn a_noop_observer_drops_every_event_silently() {
        let observer = NoopObserver;
        observer.on_event(AgentEvent::TurnStarted { turn: 1 });
    }

    #[test]
    fn a_closure_observer_is_called_with_the_event() {
        let count = Arc::new(AtomicUsize::new(0));
        let counted = count.clone();
        let observer = move |_event: AgentEvent| {
            counted.fetch_add(1, Ordering::SeqCst);
        };
        observer.on_event(AgentEvent::TurnStarted { turn: 1 });
        observer.on_event(AgentEvent::TurnStarted { turn: 2 });
        assert_eq!(count.load(Ordering::SeqCst), 2);
    }
}
