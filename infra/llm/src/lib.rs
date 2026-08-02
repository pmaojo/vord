//! Infrastructure LLM Adapters: provider-agnostic implementations of `LlmProvider`.
//!
//! Provides:
//! - `OpenAiCompatibleAdapter`: standard `/v1/chat/completions` API endpoint, fully
//!   compatible with LiteLLM proxy, Ollama, vLLM, OpenAI, Groq, DeepSeek, LocalAI, etc.
//! - `AnthropicAdapter`: native Anthropic Messages API (`/v1/messages`).
//! - `MockLlmAdapter`: deterministic offline testing.
//! - `AnthropicChatModel` / `OpenAiChatModel` (`chat` module): the
//!   tool-calling `vord_agent::ChatModel` port, for `vord agent`'s session
//!   loop rather than the Remediation Agent's one-shot fix prompt.
//! - `LlmProviderConfig` / `AnyLlmProvider` (`provider` module): picks
//!   between the two at runtime, so callers (and per-project BYOK config)
//!   can choose a provider without being generic over its concrete type.

mod anthropic;
mod chat;
mod common;
mod openai_compatible;
mod provider;

pub use anthropic::AnthropicAdapter;
pub use chat::{AnthropicChatModel, AnyChatModel, OpenAiChatModel};
pub use openai_compatible::OpenAiCompatibleAdapter;
pub use provider::{AnyLlmProvider, LlmProviderConfig, LlmProviderKind};

use vord_remediation::{FixPrompt, FixProposal, LlmError, LlmProvider};

/// Deterministic Mock LLM Provider for unit tests and offline evaluation.
pub struct MockLlmAdapter {
    proposal: Option<FixProposal>,
}

impl MockLlmAdapter {
    pub fn new(proposal: FixProposal) -> Self {
        Self {
            proposal: Some(proposal),
        }
    }

    pub fn failing() -> Self {
        Self { proposal: None }
    }
}

impl LlmProvider for MockLlmAdapter {
    async fn generate_fix(&self, _prompt: &FixPrompt) -> Result<FixProposal, LlmError> {
        self.proposal
            .clone()
            .ok_or_else(|| LlmError::ApiFailure("Mock LLM failed as configured".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[tokio::test]
    async fn mock_adapter_returns_configured_proposal() {
        let expected = FixProposal {
            file_path: PathBuf::from("src/lib.rs"),
            explanation: "removed eval call".to_string(),
            original_snippet: "eval(code)".to_string(),
            replacement_snippet: "// safe".to_string(),
        };

        let adapter = MockLlmAdapter::new(expected.clone());
        let prompt = FixPrompt {
            rule_id: "owasp:eval".to_string(),
            issue_message: "eval used".to_string(),
            file_path: PathBuf::from("src/lib.rs"),
            start_line: 1,
            end_line: 1,
            source_snippet: "eval(code)".to_string(),
            full_source: "eval(code)".to_string(),
        };

        let fix = adapter.generate_fix(&prompt).await.unwrap();
        assert_eq!(fix.explanation, expected.explanation);
        assert_eq!(fix.original_snippet, expected.original_snippet);
        assert_eq!(fix.replacement_snippet, expected.replacement_snippet);
    }
}
