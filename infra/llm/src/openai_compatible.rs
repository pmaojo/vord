//! Standard OpenAI-compatible Chat Completions adapter (`/v1/chat/completions`).
//! Compatible with LiteLLM proxy, Ollama, vLLM, OpenAI, Groq, DeepSeek, LocalAI.

use serde::{Deserialize, Serialize};
use vord_remediation::{FixPrompt, FixProposal, LlmError, LlmProvider};

use crate::common::{SYSTEM_PROMPT, parse_fix_proposal, user_prompt};

// Matches what `bin/server` and `bin/cli` have always defaulted to (a local
// Ollama), so consolidating their env-var parsing into `from_env()` doesn't
// silently change a deployment's behavior when no env vars are set.
const DEFAULT_OPENAI_BASE: &str = "http://localhost:11434/v1";
const DEFAULT_OPENAI_MODEL: &str = "llama3";

pub struct OpenAiCompatibleAdapter {
    client: reqwest::Client,
    api_base: String,
    api_key: String,
    model: String,
}

impl OpenAiCompatibleAdapter {
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

    /// Builds adapter from environment variables (`VORD_LLM_BASE_URL`, `VORD_LLM_MODEL`, `VORD_LLM_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY`).
    pub fn from_env() -> Self {
        let is_gemini =
            std::env::var("GEMINI_API_KEY").is_ok() && std::env::var("OPENAI_API_KEY").is_err();
        let default_base = if is_gemini {
            "https://generativelanguage.googleapis.com/v1beta/openai"
        } else {
            DEFAULT_OPENAI_BASE
        };
        let default_model = if is_gemini {
            "gemini-3.5-flash"
        } else {
            DEFAULT_OPENAI_MODEL
        };

        let api_base =
            std::env::var("VORD_LLM_BASE_URL").unwrap_or_else(|_| default_base.to_string());
        let model = std::env::var("VORD_LLM_MODEL").unwrap_or_else(|_| default_model.to_string());
        let api_key = std::env::var("VORD_LLM_API_KEY")
            .or_else(|_| std::env::var("OPENAI_API_KEY"))
            .or_else(|_| std::env::var("GEMINI_API_KEY"))
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

impl OpenAiCompatibleAdapter {
    async fn send_chat_completion(&self, user_prompt: &str) -> Result<String, LlmError> {
        let url = format!("{}/chat/completions", self.api_base);
        let req_body = ChatCompletionRequest {
            model: &self.model,
            messages: vec![
                ChatMessage {
                    role: "system",
                    content: SYSTEM_PROMPT,
                },
                ChatMessage {
                    role: "user",
                    content: user_prompt,
                },
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
            return Err(LlmError::ApiFailure(format!(
                "LLM provider returned {status}: {err_text}"
            )));
        }

        let data: ChatCompletionResponse = resp.json().await.map_err(|e| {
            LlmError::InvalidOutput(format!("Failed to parse LLM response JSON: {e}"))
        })?;

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
        parse_fix_proposal(&content, &prompt.file_path)
    }
}
