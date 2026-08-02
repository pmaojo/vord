//! The conversation: messages, tool calls, tool results, and the transcript
//! the model sees on every turn.
//!
//! Deliberately provider-shaped-but-not-provider-specific. Anthropic sends
//! `tool_use`/`tool_result` content blocks, OpenAI sends `tool_calls` plus
//! `role: "tool"` messages; both project onto the four [`Message`] variants
//! here, and the mapping is the adapter's problem, not the loop's.

use serde::{Deserialize, Serialize};

/// One tool call the model asked for. `id` is the provider's correlation id,
/// echoed back on the matching [`ToolResult`] — kept as an opaque string
/// because no provider agrees on its shape.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolCall {
    pub id: String,
    pub name: String,
    pub input: serde_json::Value,
}

/// The answer to one [`ToolCall`].
///
/// `is_error` is not decoration: a denied write, a rejected command and an
/// unknown tool all come back through here, and a model told "ok" about a
/// write that never happened will move on leaving the task undone.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolResult {
    pub call_id: String,
    pub content: String,
    pub is_error: bool,
}

impl ToolResult {
    pub fn ok(call_id: impl Into<String>, content: impl Into<String>) -> Self {
        Self {
            call_id: call_id.into(),
            content: content.into(),
            is_error: false,
        }
    }

    pub fn error(call_id: impl Into<String>, content: impl Into<String>) -> Self {
        Self {
            call_id: call_id.into(),
            content: content.into(),
            is_error: true,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Message {
    System(String),
    User(String),
    Assistant {
        text: Option<String>,
        calls: Vec<ToolCall>,
    },
    ToolResults(Vec<ToolResult>),
}

/// Tokens one turn cost. Reported by the adapter from the provider's own
/// usage accounting rather than estimated locally — an estimate that drifts
/// under a budget is worse than no budget at all.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenUsage {
    pub input: u64,
    pub output: u64,
}

impl TokenUsage {
    pub fn total(self) -> u64 {
        self.input.saturating_add(self.output)
    }
}

/// What the model produced on one turn.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AssistantTurn {
    pub text: Option<String>,
    pub calls: Vec<ToolCall>,
    pub usage: TokenUsage,
}

impl AssistantTurn {
    /// A turn with no tool calls is the model's claim that it is finished.
    /// It is only ever a claim — [`crate::completion`] decides.
    pub fn claims_completion(&self) -> bool {
        self.calls.is_empty()
    }
}

/// The full conversation so far.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Transcript {
    messages: Vec<Message>,
}

impl Transcript {
    pub fn new(system: impl Into<String>) -> Self {
        Self {
            messages: vec![Message::System(system.into())],
        }
    }

    pub fn push_user(&mut self, text: impl Into<String>) {
        self.messages.push(Message::User(text.into()));
    }

    /// Records what the model said. Skipped entirely for an empty turn (no
    /// text, no calls), which would otherwise append a message carrying no
    /// information and, on several providers, fail validation on the next
    /// request.
    pub fn push_assistant(&mut self, turn: &AssistantTurn) {
        if turn.text.is_none() && turn.calls.is_empty() {
            return;
        }
        self.messages.push(Message::Assistant {
            text: turn.text.clone(),
            calls: turn.calls.clone(),
        });
    }

    /// Records the answers to the last assistant turn's calls. An empty
    /// batch is dropped rather than appended: a `tool_result` message with no
    /// results answers nothing.
    pub fn push_tool_results(&mut self, results: Vec<ToolResult>) {
        if results.is_empty() {
            return;
        }
        self.messages.push(Message::ToolResults(results));
    }

    pub fn messages(&self) -> &[Message] {
        &self.messages
    }

    pub fn system_prompt(&self) -> Option<&str> {
        match self.messages.first() {
            Some(Message::System(text)) => Some(text),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn call(id: &str) -> ToolCall {
        ToolCall {
            id: id.to_string(),
            name: "read".to_string(),
            input: serde_json::json!({ "path": "a" }),
        }
    }

    #[test]
    fn a_new_transcript_opens_with_its_system_prompt() {
        let transcript = Transcript::new("you are vord agent");
        assert_eq!(transcript.system_prompt(), Some("you are vord agent"));
        assert_eq!(transcript.messages().len(), 1);
    }

    #[test]
    fn a_turn_with_no_calls_claims_completion() {
        let turn = AssistantTurn {
            text: Some("done".into()),
            calls: vec![],
            usage: TokenUsage::default(),
        };
        assert!(turn.claims_completion());
    }

    #[test]
    fn a_turn_with_calls_does_not_claim_completion() {
        let turn = AssistantTurn {
            text: None,
            calls: vec![call("1")],
            usage: TokenUsage::default(),
        };
        assert!(!turn.claims_completion());
    }

    #[test]
    fn an_empty_assistant_turn_is_not_recorded() {
        let mut transcript = Transcript::new("sys");
        transcript.push_assistant(&AssistantTurn::default());
        assert_eq!(transcript.messages().len(), 1);
    }

    #[test]
    fn an_assistant_turn_with_only_calls_is_recorded() {
        let mut transcript = Transcript::new("sys");
        transcript.push_assistant(&AssistantTurn {
            text: None,
            calls: vec![call("1")],
            usage: TokenUsage::default(),
        });
        assert_eq!(transcript.messages().len(), 2);
    }

    #[test]
    fn an_empty_tool_result_batch_is_not_recorded() {
        let mut transcript = Transcript::new("sys");
        transcript.push_tool_results(vec![]);
        assert_eq!(transcript.messages().len(), 1);
    }

    #[test]
    fn tool_results_carry_their_error_flag() {
        assert!(ToolResult::error("1", "denied").is_error);
        assert!(!ToolResult::ok("1", "fine").is_error);
    }

    #[test]
    fn token_usage_totals_both_directions() {
        assert_eq!(
            TokenUsage {
                input: 10,
                output: 5
            }
            .total(),
            15
        );
    }

    #[test]
    fn token_usage_saturates_rather_than_overflowing() {
        assert_eq!(
            TokenUsage {
                input: u64::MAX,
                output: 1
            }
            .total(),
            u64::MAX
        );
    }
}
