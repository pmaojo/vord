use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::Redirect;
use axum::Json;
use rand::{rngs::OsRng, RngCore};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;
use utoipa::ToSchema;

const STATE_TTL: Duration = Duration::from_secs(10 * 60);
const SESSION_TTL: Duration = Duration::from_secs(24 * 60 * 60);

#[allow(dead_code)]
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub(crate) struct TenantContext {
    pub tenant_id: String,
}

impl TenantContext {
    #[allow(dead_code)]
    pub fn from_headers(headers: &HeaderMap) -> Self {
        let tenant_id = headers
            .get("x-yunq-tenant-id")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("default-tenant")
            .to_string();
        Self { tenant_id }
    }
}

#[derive(Clone)]
pub(crate) struct OAuthService {
    inner: Arc<OAuthInner>,
}

struct OAuthInner {
    client: Client,
    providers: HashMap<OAuthProvider, ProviderConfig>,
    pending_states: Mutex<HashMap<String, PendingState>>,
    sessions: RwLock<HashMap<String, SessionRecord>>,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum OAuthProvider {
    GitHub,
    GitLab,
}

impl OAuthProvider {
    fn parse(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "github" => Some(Self::GitHub),
            "gitlab" => Some(Self::GitLab),
            _ => None,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::GitHub => "github",
            Self::GitLab => "gitlab",
        }
    }
}

#[derive(Clone)]
struct ProviderConfig {
    client_id: String,
    client_secret: String,
    authorize_url: String,
    token_url: String,
    user_url: String,
    email_url: Option<String>,
    redirect_uri: String,
    scope: String,
}

struct PendingState {
    provider: OAuthProvider,
    expires_at: Instant,
    return_to: Option<String>,
}

struct SessionRecord {
    user: OAuthUserDto,
    expires_at: Instant,
    expires_at_unix: u64,
}

#[derive(Clone, Debug, Serialize, ToSchema)]
pub(crate) struct OAuthUserDto {
    provider: String,
    provider_user_id: String,
    username: String,
    name: Option<String>,
    email: Option<String>,
    avatar_url: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct OAuthLoginDto {
    access_token: String,
    token_type: &'static str,
    expires_in: u64,
    user: OAuthUserDto,
    /// Where the SPA should send the user after sign-in. Server-side
    /// validated; consumers should still treat it as a hint, not a
    /// trusted redirect target.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub(crate) return_to: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct CurrentUserDto {
    user: OAuthUserDto,
    session_expires_at: u64,
}

impl CurrentUserDto {
    /// The login/username to record as the actor on audit log entries.
    pub(crate) fn username(&self) -> &str {
        &self.user.username
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct AuthErrorDto {
    pub(crate) error: String,
}

pub(crate) type AuthError = (StatusCode, Json<AuthErrorDto>);

#[derive(Deserialize)]
pub(crate) struct OAuthCallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

/// Query parameters accepted by `GET /api/auth/oauth/{provider}/login`.
/// `return_to` is where the SPA should send the user after a successful
/// login; it is sanitized server-side before being persisted in the
/// pending OAuth state.
#[derive(Deserialize, Default)]
pub(crate) struct OAuthLoginQuery {
    return_to: Option<String>,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
}

#[derive(Deserialize)]
struct ProviderUserResponse {
    id: Value,
    login: Option<String>,
    username: Option<String>,
    name: Option<String>,
    email: Option<String>,
    avatar_url: Option<String>,
}

#[derive(Deserialize)]
struct GitHubEmail {
    email: String,
    primary: bool,
    verified: bool,
}

/// The GitHub OAuth provider config, if `YUNQ_GITHUB_*` credentials are set.
fn github_provider(public_url: &str) -> anyhow::Result<Option<(OAuthProvider, ProviderConfig)>> {
    let Some((client_id, client_secret)) = credentials("YUNQ_GITHUB") else { return Ok(None) };
    let web_base = env_base_url("YUNQ_GITHUB_URL", "https://github.com")?;
    let api_base = env_base_url("YUNQ_GITHUB_API_URL", "https://api.github.com")?;
    Ok(Some((
        OAuthProvider::GitHub,
        ProviderConfig {
            client_id,
            client_secret,
            authorize_url: format!("{web_base}/login/oauth/authorize"),
            token_url: format!("{web_base}/login/oauth/access_token"),
            user_url: format!("{api_base}/user"),
            email_url: Some(format!("{api_base}/user/emails")),
            redirect_uri: std::env::var("YUNQ_GITHUB_REDIRECT_URI")
                .unwrap_or_else(|_| format!("{public_url}/api/auth/oauth/github/callback")),
            scope: "read:user user:email".to_string(),
        },
    )))
}

/// The GitLab OAuth provider config, if `YUNQ_GITLAB_*` credentials are set.
fn gitlab_provider(public_url: &str) -> anyhow::Result<Option<(OAuthProvider, ProviderConfig)>> {
    let Some((client_id, client_secret)) = credentials("YUNQ_GITLAB") else { return Ok(None) };
    let web_base = env_base_url("YUNQ_GITLAB_URL", "https://gitlab.com")?;
    Ok(Some((
        OAuthProvider::GitLab,
        ProviderConfig {
            client_id,
            client_secret,
            authorize_url: format!("{web_base}/oauth/authorize"),
            token_url: format!("{web_base}/oauth/token"),
            user_url: format!("{web_base}/api/v4/user"),
            email_url: None,
            redirect_uri: std::env::var("YUNQ_GITLAB_REDIRECT_URI")
                .unwrap_or_else(|_| format!("{public_url}/api/auth/oauth/gitlab/callback")),
            scope: "read_user".to_string(),
        },
    )))
}

impl OAuthService {
    pub(crate) fn from_env() -> anyhow::Result<Self> {
        let public_url = std::env::var("YUNQ_PUBLIC_URL")
            .unwrap_or_else(|_| "http://localhost:8080".to_string());
        let public_url = public_url.trim_end_matches('/');
        let mut providers = HashMap::new();
        for (key, config) in [github_provider(public_url)?, gitlab_provider(public_url)?].into_iter().flatten() {
            providers.insert(key, config);
        }

        let client = Client::builder()
            .user_agent(concat!("yunq-server/", env!("CARGO_PKG_VERSION")))
            .timeout(Duration::from_secs(15))
            .build()?;
        Ok(Self::new(client, providers))
    }

    fn new(client: Client, providers: HashMap<OAuthProvider, ProviderConfig>) -> Self {
        Self {
            inner: Arc::new(OAuthInner {
                client,
                providers,
                pending_states: Mutex::new(HashMap::new()),
                sessions: RwLock::new(HashMap::new()),
            }),
        }
    }

    fn begin(&self, provider: OAuthProvider, return_to: Option<&str>) -> Result<String, AuthError> {
        let config = self.inner.providers.get(&provider).ok_or_else(|| {
            auth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                format!("{} OAuth is not configured", provider.as_str()),
            )
        })?;
        let state = random_token(32);
        {
            let mut states = self
                .inner
                .pending_states
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            states.retain(|_, pending| pending.expires_at > Instant::now());
            states.insert(
                state.clone(),
                PendingState {
                    provider,
                    expires_at: Instant::now() + STATE_TTL,
                    return_to: return_to.map(String::from),
                },
            );
        }
        authorization_url(config, &state).map_err(|error| {
            auth_error(StatusCode::INTERNAL_SERVER_ERROR, format!("invalid OAuth configuration: {error}"))
        })
    }

    async fn complete(
        &self,
        provider: OAuthProvider,
        code: &str,
        state: &str,
    ) -> Result<OAuthLoginDto, AuthError> {
        let pending = self.take_state(provider, state)?;
        let config = self.inner.providers.get(&provider).ok_or_else(|| {
            auth_error(StatusCode::SERVICE_UNAVAILABLE, "OAuth provider is not configured")
        })?;
        let provider_token = self.exchange_code(provider, config, code).await?;
        let user = self.fetch_user(provider, config, &provider_token).await?;
        let access_token = random_token(32);
        let expires_at_unix = unix_seconds() + SESSION_TTL.as_secs();
        self.inner
            .sessions
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(
                access_token.clone(),
                SessionRecord {
                    user: user.clone(),
                    expires_at: Instant::now() + SESSION_TTL,
                    expires_at_unix,
                },
            );
        Ok(OAuthLoginDto {
            access_token,
            token_type: "Bearer",
            expires_in: SESSION_TTL.as_secs(),
            user,
            return_to: pending.return_to,
        })
    }

    /// Take and validate a pending state, returning the full record so the
    /// caller can read fields like `return_to`. The state is consumed
    /// (single-use) regardless of whether the caller is `consume_state` or
    /// `complete`.
    fn take_state(&self, provider: OAuthProvider, state: &str) -> Result<PendingState, AuthError> {
        let pending = self
            .inner
            .pending_states
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(state)
            .ok_or_else(|| auth_error(StatusCode::UNAUTHORIZED, "invalid or already used OAuth state"))?;
        if pending.provider != provider || pending.expires_at <= Instant::now() {
            return Err(auth_error(StatusCode::UNAUTHORIZED, "expired or mismatched OAuth state"));
        }
        Ok(pending)
    }

    fn consume_state(&self, provider: OAuthProvider, state: &str) -> Result<(), AuthError> {
        self.take_state(provider, state).map(|_| ())
    }

    async fn exchange_code(
        &self,
        provider: OAuthProvider,
        config: &ProviderConfig,
        code: &str,
    ) -> Result<String, AuthError> {
        let mut request = self.inner.client.post(&config.token_url).form(&[
            ("client_id", config.client_id.as_str()),
            ("client_secret", config.client_secret.as_str()),
            ("code", code),
            ("redirect_uri", config.redirect_uri.as_str()),
            ("grant_type", "authorization_code"),
        ]);
        if provider == OAuthProvider::GitHub {
            request = request.header(header::ACCEPT, "application/json");
        }
        let response = request.send().await.map_err(|error| {
            auth_error(StatusCode::BAD_GATEWAY, format!("OAuth token exchange failed: {error}"))
        })?;
        if !response.status().is_success() {
            return Err(auth_error(
                StatusCode::BAD_GATEWAY,
                format!("OAuth provider rejected the code with status {}", response.status()),
            ));
        }
        response
            .json::<TokenResponse>()
            .await
            .map(|token| token.access_token)
            .map_err(|error| auth_error(StatusCode::BAD_GATEWAY, format!("invalid OAuth token response: {error}")))
    }

    async fn fetch_user(
        &self,
        provider: OAuthProvider,
        config: &ProviderConfig,
        provider_token: &str,
    ) -> Result<OAuthUserDto, AuthError> {
        let response = self
            .inner
            .client
            .get(&config.user_url)
            .bearer_auth(provider_token)
            .header(header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|error| auth_error(StatusCode::BAD_GATEWAY, format!("OAuth profile request failed: {error}")))?;
        if !response.status().is_success() {
            return Err(auth_error(
                StatusCode::BAD_GATEWAY,
                format!("OAuth profile request failed with status {}", response.status()),
            ));
        }
        let profile = response.json::<ProviderUserResponse>().await.map_err(|error| {
            auth_error(StatusCode::BAD_GATEWAY, format!("invalid OAuth profile response: {error}"))
        })?;
        let username = profile.login.or(profile.username).filter(|value| !value.is_empty()).ok_or_else(|| {
            auth_error(StatusCode::BAD_GATEWAY, "OAuth profile did not include a username")
        })?;
        let provider_user_id = match profile.id {
            Value::String(id) if !id.is_empty() => id,
            Value::Number(id) => id.to_string(),
            _ => return Err(auth_error(StatusCode::BAD_GATEWAY, "OAuth profile did not include a valid id")),
        };
        let email = if profile.email.is_none() && provider == OAuthProvider::GitHub {
            self.fetch_github_email(config, provider_token).await
        } else {
            profile.email
        };
        Ok(OAuthUserDto {
            provider: provider.as_str().to_string(),
            provider_user_id,
            username,
            name: profile.name,
            email,
            avatar_url: profile.avatar_url,
        })
    }

    async fn fetch_github_email(&self, config: &ProviderConfig, provider_token: &str) -> Option<String> {
        let url = config.email_url.as_ref()?;
        let response = self
            .inner
            .client
            .get(url)
            .bearer_auth(provider_token)
            .header(header::ACCEPT, "application/vnd.github+json")
            .send()
            .await
            .ok()?;
        if !response.status().is_success() {
            return None;
        }
        response
            .json::<Vec<GitHubEmail>>()
            .await
            .ok()?
            .into_iter()
            .find(|email| email.primary && email.verified)
            .map(|email| email.email)
    }

    pub(crate) fn authenticate(&self, headers: &HeaderMap) -> Result<CurrentUserDto, AuthError> {
        let token = headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .filter(|token| !token.is_empty())
            .ok_or_else(|| auth_error(StatusCode::UNAUTHORIZED, "missing bearer token"))?;
        let sessions = self.inner.sessions.read().unwrap_or_else(|poisoned| poisoned.into_inner());
        let session = sessions
            .get(token)
            .filter(|session| session.expires_at > Instant::now())
            .ok_or_else(|| auth_error(StatusCode::UNAUTHORIZED, "invalid or expired bearer token"))?;
        Ok(CurrentUserDto {
            user: session.user.clone(),
            session_expires_at: session.expires_at_unix,
        })
    }
}

fn credentials(prefix: &str) -> Option<(String, String)> {
    let client_id = std::env::var(format!("{prefix}_CLIENT_ID")).ok()?;
    let client_secret = std::env::var(format!("{prefix}_CLIENT_SECRET")).ok()?;
    if client_id.trim().is_empty() || client_secret.trim().is_empty() {
        None
    } else {
        Some((client_id, client_secret))
    }
}

fn env_base_url(name: &str, default: &str) -> anyhow::Result<String> {
    let raw = std::env::var(name).unwrap_or_else(|_| default.to_string());
    let parsed = Url::parse(&raw)?;
    if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
        anyhow::bail!("{name} must be an absolute HTTP(S) URL");
    }
    Ok(raw.trim_end_matches('/').to_string())
}

fn authorization_url(config: &ProviderConfig, state: &str) -> Result<String, url::ParseError> {
    let mut url = Url::parse(&config.authorize_url)?;
    url.query_pairs_mut()
        .append_pair("client_id", &config.client_id)
        .append_pair("redirect_uri", &config.redirect_uri)
        .append_pair("response_type", "code")
        .append_pair("scope", &config.scope)
        .append_pair("state", state);
    Ok(url.into())
}

pub(crate) fn random_token(bytes: usize) -> String {
    let mut random = vec![0_u8; bytes];
    OsRng.fill_bytes(&mut random);
    let mut token = String::with_capacity(bytes * 2);
    for byte in random {
        use std::fmt::Write;
        let _ = write!(token, "{byte:02x}");
    }
    token
}

fn unix_seconds() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

fn auth_error(status: StatusCode, message: impl Into<String>) -> AuthError {
    (status, Json(AuthErrorDto { error: message.into() }))
}

/// Defense-in-depth open-redirect protection. The frontend also validates;
/// the backend never trusts a client-supplied `return_to`.
///
/// Rejects:
///  - empty / whitespace-only strings
///  - anything that doesn't start with a single `/` (catches bare `https://...`,
///    `javascript:`, etc.)
///  - protocol-relative URLs (`//evil.example.com`)
///  - paths that contain a scheme separator (`/redirect?u=https://...`)
fn sanitize_return_to(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    if !trimmed.starts_with('/') {
        return None;
    }
    if trimmed.starts_with("//") {
        return None;
    }
    if trimmed.contains("://") {
        return None;
    }
    Some(trimmed.to_string())
}

/// Build the URL the browser should land on after a successful OAuth exchange.
/// The token and return_to are URL-encoded so the fragment is safe even if
/// the frontend URLSearchParams parser is strict.
fn build_fragment_callback_url(token: &str, return_to: &str) -> String {
    let token_enc = url::form_urlencoded::byte_serialize(token.as_bytes()).collect::<String>();
    let return_to_enc = url::form_urlencoded::byte_serialize(return_to.as_bytes()).collect::<String>();
    format!("/auth/callback#token={}&returnTo={}", token_enc, return_to_enc)
}

/// Content negotiation: API clients send `Accept: application/json` and
/// want the bearer session in the JSON body. Browser navigations don't
/// always send an Accept header (or send `text/html`); for them we return
/// a 303 redirect with the token in the URL fragment so the SPA can pick
/// it up and store it in localStorage without ever exposing it to the
/// server-side session layer.
fn prefers_json_response(headers: &HeaderMap) -> bool {
    let accept = headers.get(header::ACCEPT).and_then(|v| v.to_str().ok()).unwrap_or("");
    accept.contains("application/json")
}

/// Start an OAuth 2.0 authorization-code flow with GitHub or GitLab.
#[utoipa::path(
    get,
    path = "/api/auth/oauth/{provider}/login",
    params(
        ("provider" = String, Path, description = "github or gitlab"),
        OAuthLoginQuery,
    ),
    responses(
        (status = 307, description = "Redirect to the provider authorization page"),
        (status = 404, description = "Unknown provider", body = AuthErrorDto),
        (status = 503, description = "Provider is not configured", body = AuthErrorDto)
    )
)]
pub(crate) async fn oauth_login(
    State(state): State<Arc<crate::AppState>>,
    Path(provider): Path<String>,
    Query(query): Query<OAuthLoginQuery>,
) -> Result<Redirect, AuthError> {
    let provider = OAuthProvider::parse(&provider)
        .ok_or_else(|| auth_error(StatusCode::NOT_FOUND, "unknown OAuth provider"))?;
    // Sanitize the requested return-to even before we hand it to the
    // service: anything that isn't a same-origin absolute path gets
    // dropped and the user lands on `/projects` after sign-in.
    let return_to = query.return_to.as_deref().and_then(sanitize_return_to);
    state
        .auth
        .begin(provider, return_to.as_deref())
        .map(|url| Redirect::temporary(&url))
}

/// Finish OAuth login and exchange the provider code for a yunq bearer session.
///
/// Content negotiation:
///  - `Accept: application/json` -> JSON body with the bearer session (API clients).
///  - anything else (browser top-level navigation) -> 303 redirect to
///    `/auth/callback#token=...&returnTo=...` so the SPA can pick up the
///    token without it ever leaving the browser.
#[utoipa::path(
    get,
    path = "/api/auth/oauth/{provider}/callback",
    params(("provider" = String, Path, description = "github or gitlab")),
    responses(
        (status = 200, description = "OAuth login completed (JSON for API clients)", body = OAuthLoginDto),
        (status = 303, description = "Browser redirect to /auth/callback with token in hash fragment"),
        (status = 400, description = "Provider denied the request or parameters are missing", body = AuthErrorDto),
        (status = 401, description = "Invalid OAuth state", body = AuthErrorDto),
        (status = 502, description = "Provider exchange failed", body = AuthErrorDto)
    )
)]
pub(crate) async fn oauth_callback(
    State(state): State<Arc<crate::AppState>>,
    Path(provider): Path<String>,
    headers: HeaderMap,
    Query(query): Query<OAuthCallbackQuery>,
) -> Result<axum::response::Response, AuthError> {
    let provider = OAuthProvider::parse(&provider)
        .ok_or_else(|| auth_error(StatusCode::NOT_FOUND, "unknown OAuth provider"))?;
    if let Some(error) = query.error {
        state.metrics.oauth_failed();
        return Err(auth_error(
            StatusCode::BAD_REQUEST,
            query.error_description.unwrap_or(error),
        ));
    }
    let code = query.code.ok_or_else(|| auth_error(StatusCode::BAD_REQUEST, "missing OAuth code"))?;
    let oauth_state = query.state.ok_or_else(|| auth_error(StatusCode::BAD_REQUEST, "missing OAuth state"))?;
    match state.auth.complete(provider, &code, &oauth_state).await {
        Ok(login) => {
            state.metrics.oauth_succeeded();
            if prefers_json_response(&headers) {
                Ok(Json(login).into_response())
            } else {
                // Always sanitize again at the redirect site — the state
                // round-trip may have been tampered with despite our
                // URL encoding.
                let return_to = login
                    .return_to
                    .as_deref()
                    .and_then(sanitize_return_to)
                    .unwrap_or_else(|| "/projects".to_string());
                let url = build_fragment_callback_url(&login.access_token, &return_to);
                Ok(Redirect::to(&url).into_response())
            }
        }
        Err(error) => {
            state.metrics.oauth_failed();
            Err(error)
        }
    }
}

/// Return the user attached to the current yunq bearer session.
#[utoipa::path(
    get,
    path = "/api/auth/me",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Current authenticated user", body = CurrentUserDto),
        (status = 401, description = "Missing or expired bearer token", body = AuthErrorDto)
    )
)]
pub(crate) async fn current_user(
    State(state): State<Arc<crate::AppState>>,
    headers: HeaderMap,
) -> Result<Json<CurrentUserDto>, AuthError> {
    state.auth.authenticate(&headers).map(Json)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_service() -> OAuthService {
        let mut providers = HashMap::new();
        providers.insert(
            OAuthProvider::GitHub,
            ProviderConfig {
                client_id: "client id".to_string(),
                client_secret: "secret".to_string(),
                authorize_url: "https://github.example/login/oauth/authorize".to_string(),
                token_url: "https://github.example/login/oauth/access_token".to_string(),
                user_url: "https://api.github.example/user".to_string(),
                email_url: None,
                redirect_uri: "https://yunq.example/api/auth/oauth/github/callback".to_string(),
                scope: "read:user user:email".to_string(),
            },
        );
        OAuthService::new(Client::new(), providers)
    }

    fn extract_state(url: &str) -> String {
        let parsed = Url::parse(url).unwrap();
        parsed.query_pairs().find(|(k, _)| k == "state").unwrap().1.into_owned()
    }

    #[test]
    fn authorization_url_contains_encoded_redirect_scope_and_random_state() {
        let service = test_service();
        let raw = service.begin(OAuthProvider::GitHub, None).expect("configured provider");
        let url = Url::parse(&raw).expect("valid authorization URL");
        let query: HashMap<_, _> = url.query_pairs().into_owned().collect();

        assert_eq!(query.get("client_id").map(String::as_str), Some("client id"));
        assert_eq!(query.get("scope").map(String::as_str), Some("read:user user:email"));
        assert_eq!(
            query.get("redirect_uri").map(String::as_str),
            Some("https://yunq.example/api/auth/oauth/github/callback")
        );
        assert_eq!(query.get("state").map(String::len), Some(64));
    }

    #[test]
    fn state_is_provider_bound_and_single_use() {
        let service = test_service();
        let raw = service.begin(OAuthProvider::GitHub, None).expect("configured provider");
        let state = extract_state(&raw);

        assert!(service.consume_state(OAuthProvider::GitLab, &state).is_err());
        assert!(service.consume_state(OAuthProvider::GitHub, &state).is_err());
    }

    #[test]
    fn rejects_missing_bearer_token() {
        let service = test_service();
        let error = service.authenticate(&HeaderMap::new()).unwrap_err();
        assert_eq!(error.0, StatusCode::UNAUTHORIZED);
    }

    // -----------------------------------------------------------------------
    // returnTo handling (open-redirect protection + Provider binding)
    // -----------------------------------------------------------------------

    #[test]
    fn begin_stores_return_to_in_pending_state() {
        let service = test_service();
        let raw = service
            .begin(OAuthProvider::GitHub, Some("/admin"))
            .expect("configured provider");
        let state = extract_state(&raw);

        let pending = service
            .take_state(OAuthProvider::GitHub, &state)
            .expect("state present");
        assert_eq!(pending.return_to.as_deref(), Some("/admin"));
    }

    #[test]
    fn begin_with_no_return_to_yields_none_in_state() {
        let service = test_service();
        let raw = service.begin(OAuthProvider::GitHub, None).expect("configured provider");
        let state = extract_state(&raw);

        let pending = service
            .take_state(OAuthProvider::GitHub, &state)
            .expect("state present");
        assert_eq!(pending.return_to, None);
    }

    #[test]
    fn take_state_rejects_wrong_provider_even_with_return_to() {
        let service = test_service();
        let raw = service.begin(OAuthProvider::GitHub, Some("/admin")).expect("ok");
        let state = extract_state(&raw);

        assert!(service.take_state(OAuthProvider::GitLab, &state).is_err());
    }

    // -----------------------------------------------------------------------
    // sanitize_return_to (defense in depth vs. open-redirect attacks)
    // -----------------------------------------------------------------------

    #[test]
    fn sanitize_accepts_simple_absolute_path() {
        assert_eq!(sanitize_return_to("/admin"), Some("/admin".to_string()));
    }

    #[test]
    fn sanitize_accepts_nested_path_with_query() {
        assert_eq!(
            sanitize_return_to("/projects/foo?tab=issues"),
            Some("/projects/foo?tab=issues".to_string())
        );
    }

    #[test]
    fn sanitize_rejects_external_url() {
        assert_eq!(sanitize_return_to("https://evil.example.com/steal"), None);
    }

    #[test]
    fn sanitize_rejects_protocol_relative_url() {
        assert_eq!(sanitize_return_to("//evil.example.com/steal"), None);
    }

    #[test]
    fn sanitize_rejects_path_with_embedded_scheme() {
        // No `/` prefix — should be treated as not a path.
        assert_eq!(sanitize_return_to("javascript:alert(1)"), None);
    }

    #[test]
    fn sanitize_rejects_empty_string() {
        assert_eq!(sanitize_return_to(""), None);
        assert_eq!(sanitize_return_to("   "), None);
    }

    #[test]
    fn sanitize_rejects_anchored_external_looking_path() {
        // `/` prefix but contains `://` later — still suspicious.
        assert_eq!(sanitize_return_to("/redirect?u=https://evil.com"), None);
    }

    // -----------------------------------------------------------------------
    // build_fragment_callback_url (URL fragment construction)
    // -----------------------------------------------------------------------

    #[test]
    fn build_fragment_url_includes_token_and_return_to() {
        let url = build_fragment_callback_url("abc123", "/admin");
        assert_eq!(url, "/auth/callback#token=abc123&returnTo=%2Fadmin");
    }

    #[test]
    fn build_fragment_url_url_encodes_special_chars_in_return_to() {
        let url = build_fragment_callback_url("tok", "/foo bar?x=1");
        // The `/` and `?` and `=` and ` ` must all be percent-encoded inside the fragment.
        assert_eq!(url, "/auth/callback#token=tok&returnTo=%2Ffoo%20bar%3Fx%3D1");
    }

    #[test]
    fn build_fragment_url_url_encodes_token_too_for_safety() {
        // Even though our hex tokens are URL-safe, encoding is defense in depth.
        let url = build_fragment_callback_url("abc&def=x", "/admin");
        assert_eq!(url, "/auth/callback#token=abc%26def%3Dx&returnTo=%2Fadmin");
    }

    // -----------------------------------------------------------------------
    // prefers_json_response (content negotiation)
    // -----------------------------------------------------------------------

    #[test]
    fn prefers_json_when_accept_header_is_application_json() {
        let mut headers = HeaderMap::new();
        headers.insert(header::ACCEPT, "application/json".parse().unwrap());
        assert!(prefers_json_response(&headers));
    }

    #[test]
    fn prefers_json_when_accept_includes_json_with_other_types() {
        let mut headers = HeaderMap::new();
        headers.insert(header::ACCEPT, "text/html,application/json;q=0.9,*/*;q=0.5".parse().unwrap());
        assert!(prefers_json_response(&headers));
    }

    #[test]
    fn prefers_redirect_when_accept_is_text_html_only() {
        let mut headers = HeaderMap::new();
        headers.insert(header::ACCEPT, "text/html".parse().unwrap());
        assert!(!prefers_json_response(&headers));
    }

    #[test]
    fn prefers_redirect_when_accept_header_is_missing() {
        // Browsers doing top-level navigation don't always send Accept.
        let headers = HeaderMap::new();
        assert!(!prefers_json_response(&headers));
    }
}
