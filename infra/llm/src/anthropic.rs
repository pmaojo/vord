//! Native Anthropic Messages API adapter (`/v1/messages`). Distinct from
//! `OpenAiCompatibleAdapter` because Anthropic's wire format isn't
//! OpenAI-chat-compatible: the system prompt is a top-level field rather
//! than a message, `max_tokens` is required, and replies come back as a
//! list of typed content blocks instead of a `choices[].message.content`
//! string.

use serde::{Deserialize, Serialize};
use vord_remediation::{FixPrompt, FixProposal, LlmError, LlmProvider};

use crate::common::{SYSTEM_PROMPT, parse_fix_proposal, user_prompt};

const DEFAULT_ANTHROPIC_BASE: &str = "https://api.anthropic.com";
const DEFAULT_ANTHROPIC_MODEL: &str = "claude-sonnet-4-5-20250929";
const ANTHROPIC_VERSION: &str = "2023-06-01";
const MAX_TOKENS: u32 = 4096;

pub struct AnthropicAdapter {
    client: reqwest::Client,
    api_base: String,
    api_key: String,
    model: String,
}

impl AnthropicAdapter {
    pub fn new(
        api_base: impl Into<String>,
        model: impl Into<String>,
        api_key: impl Into<String>,
    ) -> Self {
        Self {
            client: reqwest::Client::new(),
            api_base: api_base.into().trim_end_matches('/').to_string(),
            model: model.into(),
            api_key: api_key.into(),
        }
    }

    /// Builds adapter from environment variables (`VORD_ANTHROPIC_BASE_URL`,
    /// `VORD_ANTHROPIC_MODEL`, `VORD_ANTHROPIC_API_KEY`, falling back to the
    /// conventional `ANTHROPIC_API_KEY`).
    pub fn from_env() -> Self {
        let api_base = std::env::var("VORD_ANTHROPIC_BASE_URL")
            .unwrap_or_else(|_| DEFAULT_ANTHROPIC_BASE.to_string());
        let model = std::env::var("VORD_ANTHROPIC_MODEL")
            .unwrap_or_else(|_| DEFAULT_ANTHROPIC_MODEL.to_string());
        let api_key = std::env::var("VORD_ANTHROPIC_API_KEY")
            .or_else(|_| std::env::var("ANTHROPIC_API_KEY"))
            .unwrap_or_default();
        Self::new(api_base, model, api_key)
    }

    pub fn api_base(&self) -> &str {
        &self.api_base
    }

    pub fn model(&self) -> &str {
        &self.model
    }

    pub fn api_key(&self) -> &str {
        &self.api_key
    }
}

#[derive(Serialize)]
struct AnthropicMessage<'a> {
    role: &'a str,
    content: &'a str,
}

#[derive(Serialize)]
struct MessagesRequest<'a> {
    model: &'a str,
    max_tokens: u32,
    system: &'a str,
    messages: Vec<AnthropicMessage<'a>>,
    temperature: f32,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ContentBlock {
    Text {
        text: String,
    },
    #[serde(other)]
    Other,
}

#[derive(Deserialize)]
struct MessagesResponse {
    content: Vec<ContentBlock>,
}

#[derive(Deserialize)]
struct AnthropicErrorBody {
    error: AnthropicErrorDetail,
}

#[derive(Deserialize)]
struct AnthropicErrorDetail {
    message: String,
}

impl AnthropicAdapter {
    async fn send_message(&self, user_prompt: &str) -> Result<String, LlmError> {
        let url = format!("{}/v1/messages", self.api_base);
        let req_body = MessagesRequest {
            model: &self.model,
            max_tokens: MAX_TOKENS,
            system: SYSTEM_PROMPT,
            messages: vec![AnthropicMessage {
                role: "user",
                content: user_prompt,
            }],
            temperature: 0.1,
        };

        let resp = self
            .client
            .post(&url)
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", ANTHROPIC_VERSION)
            .json(&req_body)
            .send()
            .await
            .map_err(|e| LlmError::ApiFailure(format!("HTTP request failed to {url}: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let err_text = resp.text().await.unwrap_or_default();
            let detail = serde_json::from_str::<AnthropicErrorBody>(&err_text)
                .map(|body| body.error.message)
                .unwrap_or(err_text);
            return Err(LlmError::ApiFailure(format!(
                "Anthropic API returned {status}: {detail}"
            )));
        }

        let data: MessagesResponse = resp.json().await.map_err(|e| {
            LlmError::InvalidOutput(format!("Failed to parse Anthropic response JSON: {e}"))
        })?;

        data.content
            .into_iter()
            .find_map(|block| match block {
                ContentBlock::Text { text } => Some(text.trim().to_string()),
                ContentBlock::Other => None,
            })
            .ok_or_else(|| {
                LlmError::InvalidOutput("No text content block in Anthropic response".to_string())
            })
    }
}

impl LlmProvider for AnthropicAdapter {
    async fn generate_fix(&self, prompt: &FixPrompt) -> Result<FixProposal, LlmError> {
        let content = self.send_message(&user_prompt(prompt)).await?;
        parse_fix_proposal(&content, &prompt.file_path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_request_serializes_system_as_top_level_field() {
        let req = MessagesRequest {
            model: "claude-sonnet-4-5-20250929",
            max_tokens: MAX_TOKENS,
            system: "sys",
            messages: vec![AnthropicMessage {
                role: "user",
                content: "hi",
            }],
            temperature: 0.1,
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["system"], "sys");
        assert_eq!(json["messages"][0]["role"], "user");
        assert_eq!(json["messages"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn messages_response_extracts_first_text_block() {
        let raw = r#"{"content":[{"type":"text","text":"hello"},{"type":"tool_use"}]}"#;
        let parsed: MessagesResponse = serde_json::from_str(raw).unwrap();
        let text = parsed.content.into_iter().find_map(|b| match b {
            ContentBlock::Text { text } => Some(text),
            ContentBlock::Other => None,
        });
        assert_eq!(text.as_deref(), Some("hello"));
    }

    #[test]
    fn from_env_defaults_when_unset() {
        // SAFETY: single-threaded test, no other test reads these keys.
        unsafe {
            std::env::remove_var("VORD_ANTHROPIC_BASE_URL");
            std::env::remove_var("VORD_ANTHROPIC_MODEL");
            std::env::remove_var("VORD_ANTHROPIC_API_KEY");
            std::env::remove_var("ANTHROPIC_API_KEY");
        }
        let adapter = AnthropicAdapter::from_env();
        assert_eq!(adapter.api_base, DEFAULT_ANTHROPIC_BASE);
        assert_eq!(adapter.model, DEFAULT_ANTHROPIC_MODEL);
        assert_eq!(adapter.api_key, "");
    }
}
