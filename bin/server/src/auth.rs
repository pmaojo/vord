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
        for provider in [github_provider(public_url)?, gitlab_provider(public_url)?] {
            if let Some((key, config)) = provider {
                providers.insert(key, config);
            }
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

    fn begin(&self, provider: OAuthProvider) -> Result<String, AuthError> {
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
                PendingState { provider, expires_at: Instant::now() + STATE_TTL },
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
        self.consume_state(provider, state)?;
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
        })
    }

    fn consume_state(&self, provider: OAuthProvider, state: &str) -> Result<(), AuthError> {
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
        Ok(())
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

/// Start an OAuth 2.0 authorization-code flow with GitHub or GitLab.
#[utoipa::path(
    get,
    path = "/api/auth/oauth/{provider}/login",
    params(("provider" = String, Path, description = "github or gitlab")),
    responses(
        (status = 307, description = "Redirect to the provider authorization page"),
        (status = 404, description = "Unknown provider", body = AuthErrorDto),
        (status = 503, description = "Provider is not configured", body = AuthErrorDto)
    )
)]
pub(crate) async fn oauth_login(
    State(state): State<Arc<crate::AppState>>,
    Path(provider): Path<String>,
) -> Result<Redirect, AuthError> {
    let provider = OAuthProvider::parse(&provider)
        .ok_or_else(|| auth_error(StatusCode::NOT_FOUND, "unknown OAuth provider"))?;
    state.auth.begin(provider).map(|url| Redirect::temporary(&url))
}

/// Finish OAuth login and exchange the provider code for a yunq bearer session.
#[utoipa::path(
    get,
    path = "/api/auth/oauth/{provider}/callback",
    params(("provider" = String, Path, description = "github or gitlab")),
    responses(
        (status = 200, description = "OAuth login completed", body = OAuthLoginDto),
        (status = 400, description = "Provider denied the request or parameters are missing", body = AuthErrorDto),
        (status = 401, description = "Invalid OAuth state", body = AuthErrorDto),
        (status = 502, description = "Provider exchange failed", body = AuthErrorDto)
    )
)]
pub(crate) async fn oauth_callback(
    State(state): State<Arc<crate::AppState>>,
    Path(provider): Path<String>,
    Query(query): Query<OAuthCallbackQuery>,
) -> Result<Json<OAuthLoginDto>, AuthError> {
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
            Ok(Json(login))
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

    #[test]
    fn authorization_url_contains_encoded_redirect_scope_and_random_state() {
        let service = test_service();
        let raw = service.begin(OAuthProvider::GitHub).expect("configured provider");
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
        let raw = service.begin(OAuthProvider::GitHub).expect("configured provider");
        let url = Url::parse(&raw).unwrap();
        let state = url.query_pairs().find(|(key, _)| key == "state").unwrap().1.into_owned();

        assert!(service.consume_state(OAuthProvider::GitLab, &state).is_err());
        assert!(service.consume_state(OAuthProvider::GitHub, &state).is_err());
    }

    #[test]
    fn rejects_missing_bearer_token() {
        let service = test_service();
        let error = service.authenticate(&HeaderMap::new()).unwrap_err();
        assert_eq!(error.0, StatusCode::UNAUTHORIZED);
    }
}
