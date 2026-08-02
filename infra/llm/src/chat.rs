//! Tool-calling chat adapters: `vord_agent::ChatModel` over the Anthropic
//! Messages API and over OpenAI-compatible Chat Completions.
//!
//! Separate from [`crate::anthropic`] / [`crate::openai_compatible`], which
//! implement the single-shot `LlmProvider::generate_fix` the Remediation
//! Agent uses. That port asks one question and parses one JSON answer; this
//! one carries a growing transcript with tool calls in both directions, and
//! the two wire formats disagree about almost every part of it — Anthropic
//! nests `tool_use`/`tool_result` content blocks inside user and assistant
//! messages, OpenAI puts `tool_calls` on the assistant message and answers
//! them with whole `role: "tool"` messages whose arguments are a JSON string
//! rather than an object.
//!
//! The request-building and response-parsing are free functions, and every
//! one of them is unit-tested without a socket. A transcript that serialises
//! subtly wrong fails as a confusing model refusal three turns later; a
//! failing assertion here is worth a great deal more than one there.

use serde_json::{Value, json};
use vord_agent::runtime::{ChatModel, ModelError};
use vord_agent::session::{AssistantTurn, Message, TokenUsage, ToolCall, ToolResult, Transcript};
use vord_agent::tools::ToolSpec;

const ANTHROPIC_VERSION: &str = "2023-06-01";
/// Generous enough for a multi-file edit in one turn; the agent's own token
/// budget (`vord_agent::Budget`) is what actually bounds a run.
const MAX_TOKENS: u32 = 8192;

// ---------------------------------------------------------------------------
// Anthropic Messages
// ---------------------------------------------------------------------------

fn anthropic_tool(spec: &ToolSpec) -> Value {
    json!({
        "name": spec.name.as_str(),
        "description": spec.description,
        "input_schema": spec.input_schema,
    })
}

fn anthropic_assistant_content(text: Option<&String>, calls: &[ToolCall]) -> Vec<Value> {
    let mut blocks = Vec::new();
    if let Some(text) = text.filter(|t| !t.is_empty()) {
        blocks.push(json!({ "type": "text", "text": text }));
    }
    for call in calls {
        blocks.push(
            json!({ "type": "tool_use", "id": call.id, "name": call.name, "input": call.input }),
        );
    }
    blocks
}

/// Tool results are a *user* message on this API, not a role of their own.
fn anthropic_tool_result_content(results: &[ToolResult]) -> Vec<Value> {
    results
        .iter()
        .map(|result| {
            json!({
                "type": "tool_result",
                "tool_use_id": result.call_id,
                "content": result.content,
                "is_error": result.is_error,
            })
        })
        .collect()
}

fn anthropic_message(message: &Message) -> Option<Value> {
    match message {
        // Carried as the request's top-level `system` field instead.
        Message::System(_) => None,
        Message::User(text) => Some(json!({ "role": "user", "content": text })),
        Message::Assistant { text, calls } => {
            let content = anthropic_assistant_content(text.as_ref(), calls);
            (!content.is_empty()).then(|| json!({ "role": "assistant", "content": content }))
        }
        Message::ToolResults(results) => {
            Some(json!({ "role": "user", "content": anthropic_tool_result_content(results) }))
        }
    }
}

pub(crate) fn anthropic_body(model: &str, transcript: &Transcript, tools: &[ToolSpec]) -> Value {
    json!({
        "model": model,
        "max_tokens": MAX_TOKENS,
        "system": transcript.system_prompt().unwrap_or_default(),
        "tools": tools.iter().map(anthropic_tool).collect::<Vec<_>>(),
        "messages": transcript.messages().iter().filter_map(anthropic_message).collect::<Vec<_>>(),
    })
}

pub(crate) fn parse_anthropic_turn(body: &Value) -> Result<AssistantTurn, ModelError> {
    let blocks = body
        .get("content")
        .and_then(Value::as_array)
        .ok_or_else(|| ModelError("Anthropic response has no `content` array".to_string()))?;

    let mut turn = AssistantTurn {
        usage: TokenUsage {
            input: number_field(body, &["usage", "input_tokens"]),
            output: number_field(body, &["usage", "output_tokens"]),
        },
        ..AssistantTurn::default()
    };
    for block in blocks {
        match block.get("type").and_then(Value::as_str) {
            Some("text") => push_text(&mut turn, block.get("text").and_then(Value::as_str)),
            Some("tool_use") => turn.calls.push(ToolCall {
                id: string_field(block, "id"),
                name: string_field(block, "name"),
                input: block.get("input").cloned().unwrap_or_else(|| json!({})),
            }),
            _ => {}
        }
    }
    Ok(turn)
}

// ---------------------------------------------------------------------------
// OpenAI-compatible Chat Completions
// ---------------------------------------------------------------------------

fn openai_tool(spec: &ToolSpec) -> Value {
    json!({
        "type": "function",
        "function": {
            "name": spec.name.as_str(),
            "description": spec.description,
            "parameters": spec.input_schema,
        },
    })
}

/// Arguments travel as a JSON *string* on this API — a serialised object, not
/// an object. Sending the object works against some proxies and fails against
/// OpenAI itself, which is exactly the kind of divergence that only shows up
/// in production.
fn openai_tool_call(call: &ToolCall) -> Value {
    let mut val = json!({
        "id": call.id,
        "type": "function",
        "function": { "name": call.name, "arguments": call.input.to_string() },
    });
    // Google Gemini 3.5+ requires thought_signature on function call turns when using tools
    val["thought_signature"] = json!("thought_signature");
    val
}

/// One transcript message can become several wire messages here: a batch of
/// tool results is one `role: "tool"` message each.
fn openai_messages(message: &Message) -> Vec<Value> {
    match message {
        Message::System(text) => vec![json!({ "role": "system", "content": text })],
        Message::User(text) => vec![json!({ "role": "user", "content": text })],
        Message::Assistant { text, calls } => {
            let mut value = json!({ "role": "assistant", "content": text.clone().unwrap_or_default() });
            if !calls.is_empty() {
                value["tool_calls"] = Value::Array(calls.iter().map(openai_tool_call).collect());
            }
            vec![value]
        }
        Message::ToolResults(results) => results
            .iter()
            .map(|result| json!({ "role": "tool", "tool_call_id": result.call_id, "content": result.content }))
            .collect(),
    }
}

pub(crate) fn openai_body(model: &str, transcript: &Transcript, tools: &[ToolSpec]) -> Value {
    json!({
        "model": model,
        "messages": transcript.messages().iter().flat_map(openai_messages).collect::<Vec<_>>(),
        "tools": tools.iter().map(openai_tool).collect::<Vec<_>>(),
    })
}

pub(crate) fn parse_openai_turn(body: &Value) -> Result<AssistantTurn, ModelError> {
    let message = body
        .get("choices")
        .and_then(Value::as_array)
        .and_then(|choices| choices.first())
        .and_then(|choice| choice.get("message"))
        .ok_or_else(|| ModelError("OpenAI response has no `choices[0].message`".to_string()))?;

    let mut turn = AssistantTurn {
        usage: TokenUsage {
            input: number_field(body, &["usage", "prompt_tokens"]),
            output: number_field(body, &["usage", "completion_tokens"]),
        },
        ..AssistantTurn::default()
    };
    push_text(&mut turn, message.get("content").and_then(Value::as_str));
    for call in message
        .get("tool_calls")
        .and_then(Value::as_array)
        .unwrap_or(&Vec::new())
    {
        let function = call.get("function").unwrap_or(&Value::Null);
        turn.calls.push(ToolCall {
            id: string_field(call, "id"),
            name: string_field(function, "name"),
            input: parse_arguments(function.get("arguments")),
        });
    }
    Ok(turn)
}

/// Tolerates the two shapes providers actually send: the specified JSON
/// string, and the bare object several OpenAI-compatible servers emit
/// instead. An unparseable string becomes an empty object rather than an
/// error, so the tool's own missing-field message reaches the model — which
/// it can act on — instead of the run dying on a wire-format quibble.
fn parse_arguments(raw: Option<&Value>) -> Value {
    match raw {
        Some(Value::String(text)) => serde_json::from_str(text).unwrap_or_else(|_| json!({})),
        Some(Value::Object(map)) => Value::Object(map.clone()),
        _ => json!({}),
    }
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

fn string_field(value: &Value, field: &str) -> String {
    value
        .get(field)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

fn number_field(value: &Value, path: &[&str]) -> u64 {
    let mut current = value;
    for segment in path {
        match current.get(segment) {
            Some(next) => current = next,
            None => return 0,
        }
    }
    current.as_u64().unwrap_or(0)
}

/// Appends a text block, joining rather than replacing — a provider may emit
/// several, and keeping only the last silently drops the model's reasoning.
fn push_text(turn: &mut AssistantTurn, text: Option<&str>) {
    let Some(text) = text.filter(|t| !t.is_empty()) else {
        return;
    };
    match &mut turn.text {
        Some(existing) => {
            existing.push('\n');
            existing.push_str(text);
        }
        None => turn.text = Some(text.to_string()),
    }
}

// ---------------------------------------------------------------------------
// Adapters
// ---------------------------------------------------------------------------

/// `ChatModel` over the Anthropic Messages API.
pub struct AnthropicChatModel {
    client: reqwest::Client,
    api_base: String,
    api_key: String,
    model: String,
}

impl AnthropicChatModel {
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
}

impl ChatModel for AnthropicChatModel {
    async fn next_turn(
        &self,
        transcript: &Transcript,
        tools: &[ToolSpec],
    ) -> Result<AssistantTurn, ModelError> {
        let url = format!("{}/v1/messages", self.api_base);
        let response = self
            .client
            .post(&url)
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", ANTHROPIC_VERSION)
            .json(&anthropic_body(&self.model, transcript, tools))
            .send()
            .await
            .map_err(|e| ModelError(format!("request to {url} failed: {e}")))?;
        parse_anthropic_turn(&checked_json(response, "Anthropic").await?)
    }
}

/// `ChatModel` over OpenAI-compatible Chat Completions (OpenAI, Groq,
/// DeepSeek, vLLM, Ollama, a LiteLLM proxy).
pub struct OpenAiChatModel {
    client: reqwest::Client,
    api_base: String,
    api_key: String,
    model: String,
}

impl OpenAiChatModel {
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
}

impl ChatModel for OpenAiChatModel {
    async fn next_turn(
        &self,
        transcript: &Transcript,
        tools: &[ToolSpec],
    ) -> Result<AssistantTurn, ModelError> {
        let url = format!("{}/chat/completions", self.api_base);
        let mut request = self
            .client
            .post(&url)
            .json(&openai_body(&self.model, transcript, tools));
        if !self.api_key.is_empty() {
            request = request.bearer_auth(&self.api_key);
        }
        let response = request
            .send()
            .await
            .map_err(|e| ModelError(format!("request to {url} failed: {e}")))?;
        parse_openai_turn(&checked_json(response, "OpenAI-compatible provider").await?)
    }
}

/// Status-checks before parsing. An error body arrives on the same channel as
/// data, so a response deserialised without checking the status reports a
/// rate-limit page as an empty turn — which the loop would read as the model
/// claiming completion.
async fn checked_json(response: reqwest::Response, provider: &str) -> Result<Value, ModelError> {
    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|e| ModelError(format!("{provider} response unreadable: {e}")))?;
    if !status.is_success() {
        return Err(ModelError(format!("{provider} returned {status}: {body}")));
    }
    serde_json::from_str(&body)
        .map_err(|e| ModelError(format!("{provider} sent unparseable JSON: {e}")))
}

/// Either concrete chat adapter. Same reason [`crate::AnyLlmProvider`]
/// exists: `ChatModel::next_turn` returns `impl Future`, so the trait is not
/// object-safe and `Box<dyn ChatModel>` does not exist.
pub enum AnyChatModel {
    Anthropic(AnthropicChatModel),
    OpenAiCompatible(OpenAiChatModel),
}

impl ChatModel for AnyChatModel {
    async fn next_turn(
        &self,
        transcript: &Transcript,
        tools: &[ToolSpec],
    ) -> Result<AssistantTurn, ModelError> {
        match self {
            Self::Anthropic(model) => model.next_turn(transcript, tools).await,
            Self::OpenAiCompatible(model) => model.next_turn(transcript, tools).await,
        }
    }
}

impl crate::LlmProviderConfig {
    /// Builds the tool-calling chat adapter this config describes — the
    /// `ChatModel` counterpart to [`crate::LlmProviderConfig::build`].
    pub fn build_chat_model(&self) -> AnyChatModel {
        match self.kind {
            crate::LlmProviderKind::Anthropic => AnyChatModel::Anthropic(AnthropicChatModel::new(
                self.base_url
                    .clone()
                    .unwrap_or_else(|| "https://api.anthropic.com".to_string()),
                self.model.clone(),
                self.api_key.clone(),
            )),
            crate::LlmProviderKind::OpenAiCompatible => {
                AnyChatModel::OpenAiCompatible(OpenAiChatModel::new(
                    self.base_url
                        .clone()
                        .unwrap_or_else(|| "http://localhost:11434/v1".to_string()),
                    self.model.clone(),
                    self.api_key.clone(),
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use vord_agent::tools::tool_specs;

    use super::*;

    fn transcript_with_a_tool_round_trip() -> Transcript {
        let mut transcript = Transcript::new("be careful");
        transcript.push_user("fix the eval call");
        transcript.push_assistant(&AssistantTurn {
            text: Some("reading first".to_string()),
            calls: vec![ToolCall {
                id: "call_1".to_string(),
                name: "read".to_string(),
                input: json!({ "path": "src/a.rs" }),
            }],
            usage: TokenUsage::default(),
        });
        transcript.push_tool_results(vec![ToolResult::error("call_1", "denied")]);
        transcript
    }

    #[test]
    fn anthropic_puts_the_system_prompt_at_the_top_level_not_in_messages() {
        let body = anthropic_body(
            "claude",
            &transcript_with_a_tool_round_trip(),
            &tool_specs(),
        );
        assert_eq!(body["system"], "be careful");
        let roles: Vec<&str> = body["messages"]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| m["role"].as_str().unwrap())
            .collect();
        assert_eq!(
            roles,
            ["user", "assistant", "user"],
            "tool results are a user message on this API"
        );
    }

    #[test]
    fn anthropic_serialises_tool_use_and_tool_result_as_content_blocks() {
        let body = anthropic_body(
            "claude",
            &transcript_with_a_tool_round_trip(),
            &tool_specs(),
        );
        let assistant = &body["messages"][1]["content"];
        assert_eq!(assistant[0]["type"], "text");
        assert_eq!(assistant[1]["type"], "tool_use");
        assert_eq!(assistant[1]["id"], "call_1");
        let result = &body["messages"][2]["content"][0];
        assert_eq!(result["type"], "tool_result");
        assert_eq!(result["tool_use_id"], "call_1");
        assert_eq!(
            result["is_error"], true,
            "a denial the model reads as success is worse than no denial"
        );
    }

    #[test]
    fn anthropic_advertises_every_tool_with_its_schema() {
        let body = anthropic_body("claude", &Transcript::new("x"), &tool_specs());
        let tools = body["tools"].as_array().unwrap();
        assert_eq!(tools.len(), tool_specs().len());
        assert_eq!(tools[0]["name"], "read");
        assert_eq!(
            tools[0]["input_schema"]["properties"]["path"]["type"],
            "string"
        );
    }

    #[test]
    fn an_anthropic_reply_parses_into_text_calls_and_usage() {
        let body = json!({
            "content": [
                { "type": "text", "text": "on it" },
                { "type": "tool_use", "id": "t1", "name": "write", "input": { "path": "a", "content": "b" } },
                { "type": "thinking", "thinking": "ignored" }
            ],
            "usage": { "input_tokens": 120, "output_tokens": 34 }
        });
        let turn = parse_anthropic_turn(&body).unwrap();
        assert_eq!(turn.text.as_deref(), Some("on it"));
        assert_eq!(turn.calls.len(), 1);
        assert_eq!(turn.calls[0].name, "write");
        assert_eq!(turn.calls[0].input["path"], "a");
        assert_eq!(
            turn.usage,
            TokenUsage {
                input: 120,
                output: 34
            }
        );
    }

    #[test]
    fn an_anthropic_reply_with_no_content_array_is_an_error_not_an_empty_turn() {
        assert!(parse_anthropic_turn(&json!({ "error": { "message": "overloaded" } })).is_err());
    }

    #[test]
    fn an_anthropic_reply_with_no_usage_reports_zero_rather_than_failing() {
        let turn = parse_anthropic_turn(&json!({ "content": [] })).unwrap();
        assert_eq!(turn.usage, TokenUsage::default());
        assert!(turn.claims_completion());
    }

    #[test]
    fn openai_keeps_the_system_prompt_as_a_message() {
        let body = openai_body("gpt", &transcript_with_a_tool_round_trip(), &tool_specs());
        assert_eq!(body["messages"][0]["role"], "system");
        assert_eq!(body["messages"][0]["content"], "be careful");
    }

    #[test]
    fn openai_serialises_tool_arguments_as_a_json_string() {
        let body = openai_body("gpt", &transcript_with_a_tool_round_trip(), &tool_specs());
        let arguments = &body["messages"][2]["tool_calls"][0]["function"]["arguments"];
        assert!(
            arguments.is_string(),
            "OpenAI takes arguments as a serialised string, got {arguments}"
        );
        let parsed: Value = serde_json::from_str(arguments.as_str().unwrap()).unwrap();
        assert_eq!(parsed["path"], "src/a.rs");
    }

    #[test]
    fn openai_answers_each_tool_call_with_its_own_message() {
        let mut transcript = Transcript::new("x");
        transcript.push_tool_results(vec![ToolResult::ok("a", "1"), ToolResult::ok("b", "2")]);
        let body = openai_body("gpt", &transcript, &[]);
        let messages = body["messages"].as_array().unwrap();
        assert_eq!(messages.len(), 3, "system plus one message per result");
        assert_eq!(messages[1]["tool_call_id"], "a");
        assert_eq!(messages[2]["tool_call_id"], "b");
    }

    #[test]
    fn an_openai_reply_parses_into_text_calls_and_usage() {
        let body = json!({
            "choices": [{ "message": {
                "content": "working",
                "tool_calls": [{ "id": "c1", "type": "function",
                    "function": { "name": "scan", "arguments": "{\"path\":\".\"}" } }]
            }}],
            "usage": { "prompt_tokens": 7, "completion_tokens": 3 }
        });
        let turn = parse_openai_turn(&body).unwrap();
        assert_eq!(turn.text.as_deref(), Some("working"));
        assert_eq!(turn.calls[0].name, "scan");
        assert_eq!(turn.calls[0].input["path"], ".");
        assert_eq!(
            turn.usage,
            TokenUsage {
                input: 7,
                output: 3
            }
        );
    }

    #[test]
    fn an_openai_reply_with_object_arguments_is_tolerated() {
        let body = json!({ "choices": [{ "message": {
            "tool_calls": [{ "id": "c1", "function": { "name": "read", "arguments": { "path": "a" } } }]
        }}]});
        let turn = parse_openai_turn(&body).unwrap();
        assert_eq!(turn.calls[0].input["path"], "a");
    }

    #[test]
    fn unparseable_openai_arguments_become_an_empty_object() {
        let body = json!({ "choices": [{ "message": {
            "tool_calls": [{ "id": "c1", "function": { "name": "read", "arguments": "not json" } }]
        }}]});
        let turn = parse_openai_turn(&body).unwrap();
        assert_eq!(turn.calls[0].input, json!({}));
    }

    #[test]
    fn an_openai_reply_with_no_choices_is_an_error_not_an_empty_turn() {
        assert!(parse_openai_turn(&json!({ "error": "quota" })).is_err());
    }

    #[test]
    fn a_null_openai_content_does_not_become_the_string_null() {
        let body = json!({ "choices": [{ "message": { "content": null } }] });
        assert_eq!(parse_openai_turn(&body).unwrap().text, None);
    }

    #[test]
    fn several_text_blocks_are_joined_rather_than_overwritten() {
        let body = json!({ "content": [
            { "type": "text", "text": "first" },
            { "type": "text", "text": "second" }
        ]});
        assert_eq!(
            parse_anthropic_turn(&body).unwrap().text.as_deref(),
            Some("first\nsecond")
        );
    }

    #[test]
    fn the_provider_config_builds_the_matching_chat_adapter() {
        let anthropic = crate::LlmProviderConfig {
            kind: crate::LlmProviderKind::Anthropic,
            base_url: None,
            model: "claude-sonnet-4-5-20250929".to_string(),
            api_key: "k".to_string(),
        };
        assert!(matches!(
            anthropic.build_chat_model(),
            AnyChatModel::Anthropic(_)
        ));

        let openai = crate::LlmProviderConfig {
            kind: crate::LlmProviderKind::OpenAiCompatible,
            base_url: Some("http://localhost:4000/v1".to_string()),
            model: "codellama".to_string(),
            api_key: String::new(),
        };
        assert!(matches!(
            openai.build_chat_model(),
            AnyChatModel::OpenAiCompatible(_)
        ));
    }
}
