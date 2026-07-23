//! Infrastructure LLM Adapters: provider-agnostic implementations of `LlmProvider`.
//!
//! Provides:
//! - `OpenAiCompatibleAdapter`: standard `/v1/chat/completions` API endpoint, fully
//!   compatible with LiteLLM proxy, Ollama, vLLM, OpenAI, Groq, DeepSeek, LocalAI, etc.
//! - `AnthropicAdapter`: native Anthropic Messages API (`/v1/messages`).
//! - `MockLlmAdapter`: deterministic offline testing.

use serde::{Deserialize, Serialize};
use yunq_remediation::{FixPrompt, FixProposal, LlmError, LlmProvider};

const DEFAULT_OPENAI_BASE: &str = "http://localhost:4000/v1";
const DEFAULT_OPENAI_MODEL: &str = "codellama";

/// Standard OpenAI-compatible Chat Completions adapter (`/v1/chat/completions`).
/// Compatible with LiteLLM proxy, Ollama, vLLM, OpenAI, Groq, DeepSeek, LocalAI.
pub struct OpenAiCompatibleAdapter {
    client: reqwest::Client,
    api_base: String,
    api_key: String,
    model: String,
}

impl OpenAiCompatibleAdapter {
    pub fn new(api_base: impl Into<String>, model: impl Into<String>, api_key: impl Into<String>) -> Self {
        Self {
            client: reqwest::Client::new(),
            api_base: api_base.into().trim_end_matches('/').to_string(),
            model: model.into(),
            api_key: api_key.into(),
        }
    }

    /// Builds adapter from environment variables (`YUNQ_LLM_BASE_URL`, `YUNQ_LLM_MODEL`, `YUNQ_LLM_API_KEY`).
    pub fn from_env() -> Self {
        let api_base = std::env::var("YUNQ_LLM_BASE_URL")
            .unwrap_or_else(|_| DEFAULT_OPENAI_BASE.to_string());
        let model = std::env::var("YUNQ_LLM_MODEL")
            .unwrap_or_else(|_| DEFAULT_OPENAI_MODEL.to_string());
        let api_key = std::env::var("YUNQ_LLM_API_KEY")
            .or_else(|_| std::env::var("OPENAI_API_KEY"))
            .unwrap_or_default();
        Self::new(api_base, model, api_key)
    }
}

#[derive(Serialize)]
struct ChatMessage<'a> {
    role: &'a str,
    content: &'a str,
}

#[derive(Serialize)]
struct ChatCompletionRequest<'a> {
    model: &'a str,
    messages: Vec<ChatMessage<'a>>,
    temperature: f32,
}

#[derive(Deserialize)]
struct ChatChoice {
    message: ChatChoiceMessage,
}

#[derive(Deserialize)]
struct ChatChoiceMessage {
    content: String,
}

#[derive(Deserialize)]
struct ChatCompletionResponse {
    choices: Vec<ChatChoice>,
}

#[derive(Deserialize)]
struct FixProposalJson {
    explanation: String,
    original_snippet: String,
    replacement_snippet: String,
}

const SYSTEM_PROMPT: &str = "You are yunq's automated Remediation Agent. Your job is to fix code analysis findings accurately.\n\
    Return ONLY a valid JSON object matching this exact schema, with no markdown code blocks:\n\
    {\n  \"explanation\": \"short rationale\",\n  \"original_snippet\": \"exact lines to replace\",\n  \"replacement_snippet\": \"new lines\"\n}";

fn user_prompt(prompt: &FixPrompt) -> String {
    format!(
        "File: {}\nRule Violated: {}\nIssue Message: {}\nLines: {}-{}\n\nOriginal Code Snippet:\n```\n{}\n```\n\nFull Source Context:\n```\n{}\n```",
        prompt.file_path.display(),
        prompt.rule_id,
        prompt.issue_message,
        prompt.start_line,
        prompt.end_line,
        prompt.source_snippet,
        prompt.full_source
    )
}

/// Strips a leading/trailing ```` ``` ```` or ```` ```json ```` markdown code
/// fence, in case the model wrapped its JSON in one despite being asked not
/// to.
fn strip_code_fence(content: &str) -> &str {
    content
        .strip_prefix("```json")
        .or_else(|| content.strip_prefix("```"))
        .unwrap_or(content)
        .strip_suffix("```")
        .unwrap_or(content)
        .trim()
}

impl OpenAiCompatibleAdapter {
    async fn send_chat_completion(&self, user_prompt: &str) -> Result<String, LlmError> {
        let url = format!("{}/chat/completions", self.api_base);
        let req_body = ChatCompletionRequest {
            model: &self.model,
            messages: vec![
                ChatMessage { role: "system", content: SYSTEM_PROMPT },
                ChatMessage { role: "user", content: user_prompt },
            ],
            temperature: 0.1,
        };

        let mut req = self.client.post(&url).json(&req_body);
        if !self.api_key.is_empty() {
            req = req.bearer_auth(&self.api_key);
        }

        let resp = req
            .send()
            .await
            .map_err(|e| LlmError::ApiFailure(format!("HTTP request failed to {url}: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let err_text = resp.text().await.unwrap_or_default();
            return Err(LlmError::ApiFailure(format!("LLM provider returned {status}: {err_text}")));
        }

        let data: ChatCompletionResponse = resp
            .json()
            .await
            .map_err(|e| LlmError::InvalidOutput(format!("Failed to parse LLM response JSON: {e}")))?;

        data.choices
            .into_iter()
            .next()
            .map(|c| c.message.content.trim().to_string())
            .ok_or_else(|| LlmError::InvalidOutput("Empty choices from LLM API".to_string()))
    }
}

impl LlmProvider for OpenAiCompatibleAdapter {
    async fn generate_fix(&self, prompt: &FixPrompt) -> Result<FixProposal, LlmError> {
        let content = self.send_chat_completion(&user_prompt(prompt)).await?;
        let clean_json = strip_code_fence(&content);

        let parsed: FixProposalJson = serde_json::from_str(clean_json).map_err(|e| {
            LlmError::InvalidOutput(format!("JSON fix proposal schema mismatch: {e}. Raw content: {content}"))
        })?;

        Ok(FixProposal {
            file_path: prompt.file_path.clone(),
            explanation: parsed.explanation,
            original_snippet: parsed.original_snippet,
            replacement_snippet: parsed.replacement_snippet,
        })
    }
}

/// Deterministic Mock LLM Provider for unit tests and offline evaluation.
pub struct MockLlmAdapter {
    proposal: Option<FixProposal>,
}

impl MockLlmAdapter {
    pub fn new(proposal: FixProposal) -> Self {
        Self { proposal: Some(proposal) }
    }

    pub fn failing() -> Self {
        Self { proposal: None }
    }
}

impl LlmProvider for MockLlmAdapter {
    async fn generate_fix(&self, _prompt: &FixPrompt) -> Result<FixProposal, LlmError> {
        self.proposal.clone().ok_or_else(|| {
            LlmError::ApiFailure("Mock LLM failed as configured".to_string())
        })
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
