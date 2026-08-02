//! Runtime provider selection: turns a `LlmProviderConfig` (platform default
//! from env, or a per-project BYOK override loaded from storage) into a
//! concrete `LlmProvider`.
//!
//! `LlmProvider::generate_fix` returns `impl Future + Send` (not `Box<dyn
//! Future>`), so it isn't object-safe — `Box<dyn LlmProvider>` doesn't
//! exist. `AnyLlmProvider` is the usual workaround: an enum over the
//! concrete adapters, dispatching to whichever one is active.

use vord_remediation::{FixPrompt, FixProposal, LlmError, LlmProvider};

use crate::{AnthropicAdapter, OpenAiCompatibleAdapter};

/// Which wire protocol to speak. Centralized so call sites don't match on
/// free-standing strings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LlmProviderKind {
    /// `/v1/chat/completions` — OpenAI, Groq, DeepSeek, Ollama, vLLM,
    /// LocalAI, or a LiteLLM proxy in front of almost anything else.
    OpenAiCompatible,
    /// Native Anthropic Messages API (`/v1/messages`).
    Anthropic,
}

impl LlmProviderKind {
    /// Parses the persisted/wire representation (`"openai_compatible"` |
    /// `"anthropic"`). Kept as plain strings at rest so neither the DB
    /// schema nor the HTTP DTOs need to depend on this enum's layout.
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "openai_compatible" => Some(Self::OpenAiCompatible),
            "anthropic" => Some(Self::Anthropic),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::OpenAiCompatible => "openai_compatible",
            Self::Anthropic => "anthropic",
        }
    }
}

/// Everything needed to build a provider: which wire protocol, where to
/// send requests, which model, and the credential. `base_url` is `None` to
/// mean "use the provider's own default" (the local LiteLLM proxy for
/// `OpenAiCompatible`, `https://api.anthropic.com` for `Anthropic`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LlmProviderConfig {
    pub kind: LlmProviderKind,
    pub base_url: Option<String>,
    pub model: String,
    pub api_key: String,
}

impl LlmProviderConfig {
    /// The platform-wide default, resolved from environment variables —
    /// the behavior before per-project BYOK existed, and the fallback for
    /// any project that hasn't configured its own provider.
    pub fn from_env() -> Self {
        let kind = std::env::var("VORD_LLM_PROVIDER")
            .ok()
            .and_then(|raw| LlmProviderKind::parse(&raw))
            .unwrap_or(LlmProviderKind::OpenAiCompatible);
        match kind {
            LlmProviderKind::OpenAiCompatible => {
                let adapter = OpenAiCompatibleAdapter::from_env();
                Self {
                    kind,
                    base_url: Some(adapter.api_base().to_string()),
                    model: adapter.model().to_string(),
                    api_key: adapter.api_key().to_string(),
                }
            }
            LlmProviderKind::Anthropic => {
                let adapter = AnthropicAdapter::from_env();
                Self {
                    kind,
                    base_url: Some(adapter.api_base().to_string()),
                    model: adapter.model().to_string(),
                    api_key: adapter.api_key().to_string(),
                }
            }
        }
    }

    /// Builds the concrete adapter this config describes.
    pub fn build(&self) -> AnyLlmProvider {
        match self.kind {
            LlmProviderKind::OpenAiCompatible => {
                let base = self
                    .base_url
                    .clone()
                    .unwrap_or_else(|| OpenAiCompatibleAdapter::from_env().api_base().to_string());
                AnyLlmProvider::OpenAiCompatible(OpenAiCompatibleAdapter::new(
                    base,
                    self.model.clone(),
                    self.api_key.clone(),
                ))
            }
            LlmProviderKind::Anthropic => {
                let base = self
                    .base_url
                    .clone()
                    .unwrap_or_else(|| AnthropicAdapter::from_env().api_base().to_string());
                AnyLlmProvider::Anthropic(AnthropicAdapter::new(
                    base,
                    self.model.clone(),
                    self.api_key.clone(),
                ))
            }
        }
    }
}

/// A `Box<dyn LlmProvider>` stand-in (see module docs for why a trait
/// object doesn't work here): whichever concrete adapter `LlmProviderConfig`
/// selected, callers hold one of these and don't need to be generic over it.
pub enum AnyLlmProvider {
    OpenAiCompatible(OpenAiCompatibleAdapter),
    Anthropic(AnthropicAdapter),
}

impl LlmProvider for AnyLlmProvider {
    async fn generate_fix(&self, prompt: &FixPrompt) -> Result<FixProposal, LlmError> {
        match self {
            Self::OpenAiCompatible(adapter) => adapter.generate_fix(prompt).await,
            Self::Anthropic(adapter) => adapter.generate_fix(prompt).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_kind_round_trips_through_its_wire_string() {
        for kind in [
            LlmProviderKind::OpenAiCompatible,
            LlmProviderKind::Anthropic,
        ] {
            assert_eq!(LlmProviderKind::parse(kind.as_str()), Some(kind));
        }
    }

    #[test]
    fn provider_kind_rejects_unknown_strings() {
        assert_eq!(LlmProviderKind::parse("bedrock"), None);
    }

    #[test]
    fn config_builds_matching_adapter_kind() {
        let openai_config = LlmProviderConfig {
            kind: LlmProviderKind::OpenAiCompatible,
            base_url: Some("http://localhost:4000/v1".to_string()),
            model: "codellama".to_string(),
            api_key: "key".to_string(),
        };
        assert!(matches!(
            openai_config.build(),
            AnyLlmProvider::OpenAiCompatible(_)
        ));

        let anthropic_config = LlmProviderConfig {
            kind: LlmProviderKind::Anthropic,
            base_url: None,
            model: "claude-sonnet-4-5-20250929".to_string(),
            api_key: "key".to_string(),
        };
        assert!(matches!(
            anthropic_config.build(),
            AnyLlmProvider::Anthropic(_)
        ));
    }
}
