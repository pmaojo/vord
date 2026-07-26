//! Per-project BYOK for the AI Remediation Agent: lets a project override
//! the platform-wide default LLM provider (env-configured, see
//! `generate_agent_fix` in `main.rs`) with its own provider/model/API key.
//!
//! Same shape as `ops.rs`'s other project-scoped admin writes (permission
//! grants, retention overrides): `AdminAccess`-gated, audit-logged, backed
//! by `state.ops` (the `OpsStore` port). Kept in its own file since it's
//! the one admin surface that handles a secret — the API key is never
//! echoed back in a response body, only a masked last-4 hint.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use yunq_infra_llm::LlmProviderKind;

use crate::auth::permissions::{is_allowed, Caller};
use crate::auth::Permission;
use crate::AppState;

fn actor_from_headers(state: &AppState, headers: &HeaderMap) -> Option<String> {
    state.auth.authenticate(headers).ok().map(|user| user.username().to_string())
}

fn forbidden(permission: Permission) -> (StatusCode, String) {
    (StatusCode::FORBIDDEN, format!("missing permission: {permission:?}"))
}

/// Masks a secret down to its last 4 characters (`****ab12`), so a config
/// read can confirm a key is set — and which one, roughly — without ever
/// re-exposing it in full.
fn mask_api_key(api_key: &str) -> String {
    if api_key.len() <= 4 {
        return "*".repeat(api_key.len());
    }
    let (masked, visible) = api_key.split_at(api_key.len() - 4);
    format!("{}{}", "*".repeat(masked.len().min(8)), visible)
}

#[derive(Deserialize, ToSchema)]
pub(crate) struct LlmProviderConfigRequestDto {
    /// One of: openai_compatible, anthropic.
    provider: String,
    /// Override the provider's default endpoint (e.g. a self-hosted LiteLLM
    /// proxy, or an Anthropic-compatible gateway). `null` uses the
    /// provider's own default.
    base_url: Option<String>,
    /// Model name/id to request, e.g. `gpt-4o`, `claude-sonnet-4-5-20250929`.
    model: String,
    /// The project's own API key for this provider. Encrypted at rest;
    /// never returned by `GET`.
    api_key: String,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct LlmProviderConfigDto {
    project_key: String,
    /// One of: openai_compatible, anthropic.
    provider: String,
    base_url: Option<String>,
    model: String,
    /// Last 4 characters of the configured API key, e.g. `********ab12` —
    /// enough to confirm which key is set without exposing it.
    api_key_last4: String,
}

/// Sets (or replaces) a project's BYOK LLM provider config; audit-logged as
/// `ai_provider.updated`. Requires `AdminAccess` since this handles a
/// tenant secret, not just a project setting.
#[utoipa::path(
    put,
    path = "/api/projects/{key}/ai-provider",
    params(("key" = String, Path, description = "Project key")),
    request_body = LlmProviderConfigRequestDto,
    responses(
        (status = 200, description = "The config that was stored (API key masked)", body = LlmProviderConfigDto),
        (status = 400, description = "Unknown provider, or an empty model/api_key"),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller lacks AdminAccess"),
        (status = 502, description = "Storage backend unavailable, or YUNQ_SECRETS_KEY misconfigured"),
    )
)]
pub(crate) async fn set_ai_provider(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
    Caller(caller): Caller,
    Json(request): Json<LlmProviderConfigRequestDto>,
) -> Result<Json<LlmProviderConfigDto>, (StatusCode, String)> {
    if !is_allowed(&caller, Permission::AdminAccess) {
        return Err(forbidden(Permission::AdminAccess));
    }
    if LlmProviderKind::parse(&request.provider).is_none() {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("unknown provider {:?}; expected one of: openai_compatible, anthropic", request.provider),
        ));
    }
    if request.model.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "model must not be empty".to_string()));
    }
    if request.api_key.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "api_key must not be empty".to_string()));
    }
    let actor = actor_from_headers(&state, &headers);

    state
        .ops
        .set_llm_config(
            key.clone(),
            request.provider.clone(),
            request.base_url.clone(),
            request.model.clone(),
            request.api_key.clone(),
        )
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;

    state
        .ops
        .record_audit(
            actor,
            "ai_provider.updated".to_string(),
            "project_llm_provider_config".to_string(),
            key.clone(),
            None,
            Some(serde_json::json!({
                "provider": request.provider,
                "base_url": request.base_url,
                "model": request.model,
            })),
        )
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;

    Ok(Json(LlmProviderConfigDto {
        project_key: key,
        provider: request.provider,
        base_url: request.base_url,
        model: request.model,
        api_key_last4: mask_api_key(&request.api_key),
    }))
}

/// Reads a project's BYOK LLM provider config, if any. The API key is
/// masked — this endpoint confirms *that* a key is set, not what it is.
#[utoipa::path(
    get,
    path = "/api/projects/{key}/ai-provider",
    params(("key" = String, Path, description = "Project key")),
    responses(
        (status = 200, description = "The project's BYOK config", body = LlmProviderConfigDto),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller lacks AdminAccess"),
        (status = 404, description = "Project has no BYOK override (uses the platform default provider)"),
        (status = 502, description = "Storage backend unavailable, or YUNQ_SECRETS_KEY misconfigured"),
    )
)]
pub(crate) async fn get_ai_provider(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    Caller(caller): Caller,
) -> Result<Json<LlmProviderConfigDto>, (StatusCode, String)> {
    if !is_allowed(&caller, Permission::AdminAccess) {
        return Err(forbidden(Permission::AdminAccess));
    }

    let config = state
        .ops
        .llm_config(key.clone())
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, format!("project {key:?} has no BYOK override")))?;

    Ok(Json(LlmProviderConfigDto {
        project_key: key,
        provider: config.provider,
        base_url: config.base_url,
        model: config.model,
        api_key_last4: mask_api_key(&config.api_key),
    }))
}

#[derive(Serialize, ToSchema)]
pub(crate) struct AiProviderClearedDto {
    project_key: String,
    /// Whether a BYOK override actually existed to remove.
    removed: bool,
}

/// Clears a project's BYOK override, reverting it to the platform-wide
/// default provider; audit-logged as `ai_provider.cleared`.
#[utoipa::path(
    delete,
    path = "/api/projects/{key}/ai-provider",
    params(("key" = String, Path, description = "Project key")),
    responses(
        (status = 200, description = "Whether an override was removed", body = AiProviderClearedDto),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller lacks AdminAccess"),
        (status = 502, description = "Storage backend unavailable"),
    )
)]
pub(crate) async fn clear_ai_provider(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
    Caller(caller): Caller,
) -> Result<Json<AiProviderClearedDto>, (StatusCode, String)> {
    if !is_allowed(&caller, Permission::AdminAccess) {
        return Err(forbidden(Permission::AdminAccess));
    }
    let actor = actor_from_headers(&state, &headers);

    let removed = state
        .ops
        .clear_llm_config(key.clone())
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;

    state
        .ops
        .record_audit(
            actor,
            "ai_provider.cleared".to_string(),
            "project_llm_provider_config".to_string(),
            key.clone(),
            None,
            None,
        )
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;

    Ok(Json(AiProviderClearedDto { project_key: key, removed }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_api_key_keeps_last_four_chars() {
        assert_eq!(mask_api_key("sk-ant-abcd1234"), "********1234");
    }

    #[test]
    fn mask_api_key_handles_short_keys() {
        assert_eq!(mask_api_key("abc"), "***");
        assert_eq!(mask_api_key(""), "");
    }

    #[test]
    fn mask_api_key_caps_mask_length_for_very_long_keys() {
        let long_key = "a".repeat(100) + "z9y8";
        let masked = mask_api_key(&long_key);
        assert_eq!(masked, "********z9y8");
    }
}
