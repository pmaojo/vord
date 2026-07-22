use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Sha256;
use tokio::sync::mpsc;
use url::Url;
use utoipa::{IntoParams, ToSchema};

use crate::metrics::Metrics;

const DELIVERY_QUEUE_CAPACITY: usize = 1_024;
const DELIVERY_LOG_CAPACITY: usize = 10_000;
const DEFAULT_MAX_ATTEMPTS: u32 = 4;
const DEFAULT_RETRY_BASE_MS: u64 = 500;

#[derive(Clone)]
pub(crate) struct WebhookDispatcher {
    inner: Arc<DispatcherInner>,
}

struct DispatcherInner {
    client: reqwest::Client,
    registrations: RwLock<HashMap<String, WebhookRegistration>>,
    attempts: RwLock<VecDeque<WebhookAttemptDto>>,
    sender: mpsc::Sender<DeliveryJob>,
    max_attempts: u32,
    retry_base: Duration,
    metrics: Metrics,
}

#[derive(Clone)]
struct WebhookRegistration {
    id: String,
    url: String,
    secret: String,
    events: HashSet<String>,
    created_at: u64,
}

struct DeliveryJob {
    delivery_id: String,
    webhook: WebhookRegistration,
    event: String,
    body: Vec<u8>,
}

#[derive(Deserialize, ToSchema)]
pub(crate) struct CreateWebhookDto {
    /// Absolute HTTP(S) endpoint that will receive JSON POST requests.
    url: String,
    /// Shared signing secret. It is never returned by the API.
    secret: String,
    /// Event names such as `analysis.finished` or `gate.changed`.
    events: Vec<String>,
}

#[derive(Clone, Serialize, ToSchema)]
pub(crate) struct WebhookDto {
    id: String,
    url: String,
    events: Vec<String>,
    created_at: u64,
}

impl From<&WebhookRegistration> for WebhookDto {
    fn from(registration: &WebhookRegistration) -> Self {
        let mut events: Vec<_> = registration.events.iter().cloned().collect();
        events.sort();
        Self {
            id: registration.id.clone(),
            url: registration.url.clone(),
            events,
            created_at: registration.created_at,
        }
    }
}

#[derive(Deserialize, ToSchema)]
pub(crate) struct DispatchWebhookDto {
    /// Event name delivered in the `X-Yunq-Event` header and JSON envelope.
    event: String,
    /// Arbitrary event-specific JSON payload.
    payload: Value,
    /// Optional registration id. When omitted, all subscribers receive it.
    webhook_id: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct QueuedDeliveryDto {
    delivery_id: String,
    webhook_id: String,
    event: String,
    status: &'static str,
}

#[derive(Clone, Serialize, ToSchema)]
pub(crate) struct WebhookAttemptDto {
    delivery_id: String,
    webhook_id: String,
    event: String,
    attempt: u32,
    outcome: String,
    http_status: Option<u16>,
    error: Option<String>,
    duration_ms: u64,
    attempted_at: u64,
    next_retry_in_ms: Option<u64>,
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct DeliveryLogQuery {
    /// Filter all attempts for one delivery id.
    delivery_id: Option<String>,
    /// Maximum records to return (default 100, capped at 1000).
    #[serde(default = "default_log_limit")]
    limit: usize,
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct WebhookErrorDto {
    error: String,
}

type WebhookError = (StatusCode, Json<WebhookErrorDto>);

impl WebhookDispatcher {
    pub(crate) fn from_env(metrics: Metrics) -> anyhow::Result<Self> {
        let max_attempts = env_number("YUNQ_WEBHOOK_MAX_ATTEMPTS", DEFAULT_MAX_ATTEMPTS).clamp(1, 10);
        let retry_base_ms = env_number("YUNQ_WEBHOOK_RETRY_BASE_MS", DEFAULT_RETRY_BASE_MS).clamp(10, 60_000);
        let client = reqwest::Client::builder()
            .user_agent(concat!("yunq-webhooks/", env!("CARGO_PKG_VERSION")))
            .timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        Ok(Self::new(client, metrics, max_attempts, Duration::from_millis(retry_base_ms)))
    }

    fn new(
        client: reqwest::Client,
        metrics: Metrics,
        max_attempts: u32,
        retry_base: Duration,
    ) -> Self {
        let (sender, receiver) = mpsc::channel(DELIVERY_QUEUE_CAPACITY);
        let inner = Arc::new(DispatcherInner {
            client,
            registrations: RwLock::new(HashMap::new()),
            attempts: RwLock::new(VecDeque::new()),
            sender,
            max_attempts,
            retry_base,
            metrics,
        });
        tokio::spawn(run_dispatcher(inner.clone(), receiver));
        Self { inner }
    }

    fn register(&self, request: CreateWebhookDto) -> Result<WebhookDto, WebhookError> {
        validate_target_url(&request.url)?;
        if request.secret.len() < 16 {
            return Err(webhook_error(
                StatusCode::BAD_REQUEST,
                "webhook secret must contain at least 16 characters",
            ));
        }
        if request.events.is_empty() {
            return Err(webhook_error(StatusCode::BAD_REQUEST, "at least one event is required"));
        }
        let events: HashSet<_> = request
            .events
            .into_iter()
            .map(|event| validate_event(&event).map(|_| event))
            .collect::<Result<_, _>>()?;
        let registration = WebhookRegistration {
            id: crate::auth::random_token(16),
            url: request.url,
            secret: request.secret,
            events,
            created_at: unix_millis(),
        };
        let dto = WebhookDto::from(&registration);
        self.inner
            .registrations
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(registration.id.clone(), registration);
        Ok(dto)
    }

    fn list(&self) -> Vec<WebhookDto> {
        let registrations = self
            .inner
            .registrations
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut hooks: Vec<_> = registrations.values().map(WebhookDto::from).collect();
        hooks.sort_by(|left, right| left.created_at.cmp(&right.created_at));
        hooks
    }

    async fn dispatch(&self, request: DispatchWebhookDto) -> Result<Vec<QueuedDeliveryDto>, WebhookError> {
        validate_event(&request.event)?;
        let webhooks = {
            let registrations = self
                .inner
                .registrations
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(webhook_id) = request.webhook_id.as_ref() {
                vec![registrations.get(webhook_id).cloned().ok_or_else(|| {
                    webhook_error(StatusCode::NOT_FOUND, "webhook registration not found")
                })?]
            } else {
                registrations
                    .values()
                    .filter(|webhook| webhook.events.contains(&request.event))
                    .cloned()
                    .collect()
            }
        };

        let mut queued = Vec::with_capacity(webhooks.len());
        for webhook in webhooks {
            if !webhook.events.contains(&request.event) {
                return Err(webhook_error(
                    StatusCode::BAD_REQUEST,
                    "target webhook is not subscribed to this event",
                ));
            }
            let delivery_id = crate::auth::random_token(16);
            let body = serde_json::to_vec(&serde_json::json!({
                "id": delivery_id.clone(),
                "event": request.event.clone(),
                "created_at": unix_millis(),
                "payload": request.payload.clone(),
            }))
            .map_err(|error| webhook_error(StatusCode::BAD_REQUEST, error.to_string()))?;
            let job = DeliveryJob {
                delivery_id: delivery_id.clone(),
                webhook: webhook.clone(),
                event: request.event.clone(),
                body,
            };
            self.inner.sender.send(job).await.map_err(|_| {
                self.inner.metrics.webhook_queue_error();
                webhook_error(StatusCode::SERVICE_UNAVAILABLE, "webhook dispatcher is unavailable")
            })?;
            self.inner.metrics.webhook_queued();
            queued.push(QueuedDeliveryDto {
                delivery_id,
                webhook_id: webhook.id,
                event: request.event.clone(),
                status: "queued",
            });
        }
        Ok(queued)
    }

    fn logs(&self, query: DeliveryLogQuery) -> Vec<WebhookAttemptDto> {
        self.inner
            .attempts
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .iter()
            .filter(|attempt| {
                query.delivery_id.as_ref().is_none_or(|id| attempt.delivery_id == *id)
            })
            .take(query.limit.min(1_000))
            .cloned()
            .collect()
    }
}

async fn run_dispatcher(inner: Arc<DispatcherInner>, mut receiver: mpsc::Receiver<DeliveryJob>) {
    while let Some(job) = receiver.recv().await {
        deliver_with_retries(&inner, job).await;
    }
}

async fn deliver_with_retries(inner: &DispatcherInner, job: DeliveryJob) {
    for attempt in 1..=inner.max_attempts {
        inner.metrics.webhook_attempted();
        let started = Instant::now();
        let signature = sign_payload(&job.webhook.secret, &job.body);
        let response = inner
            .client
            .post(&job.webhook.url)
            .header("content-type", "application/json")
            .header("x-yunq-event", &job.event)
            .header("x-yunq-delivery", &job.delivery_id)
            .header("x-yunq-signature-256", signature)
            .body(job.body.clone())
            .send()
            .await;
        let elapsed = started.elapsed();
        let (success, retryable, http_status, error) = match response {
            Ok(response) if response.status().is_success() => {
                (true, false, Some(response.status().as_u16()), None)
            }
            Ok(response) => {
                let status = response.status();
                (
                    false,
                    is_retryable_status(status),
                    Some(status.as_u16()),
                    Some(format!("endpoint returned {status}")),
                )
            }
            Err(error) => (false, true, None, Some(error.to_string())),
        };
        let will_retry = !success && retryable && attempt < inner.max_attempts;
        let delay = will_retry.then(|| retry_delay(inner.retry_base, attempt));
        record_attempt(
            inner,
            WebhookAttemptDto {
                delivery_id: job.delivery_id.clone(),
                webhook_id: job.webhook.id.clone(),
                event: job.event.clone(),
                attempt,
                outcome: if success {
                    "success"
                } else if will_retry {
                    "retrying"
                } else {
                    "failed"
                }
                .to_string(),
                http_status,
                error,
                duration_ms: elapsed.as_millis().min(u128::from(u64::MAX)) as u64,
                attempted_at: unix_millis(),
                next_retry_in_ms: delay.map(|duration| duration.as_millis() as u64),
            },
        );
        if success {
            inner.metrics.webhook_succeeded();
            return;
        }
        if let Some(delay) = delay {
            inner.metrics.webhook_retried();
            tokio::time::sleep(delay).await;
        } else {
            inner.metrics.webhook_failed();
            return;
        }
    }
}

fn record_attempt(inner: &DispatcherInner, attempt: WebhookAttemptDto) {
    let mut attempts = inner.attempts.write().unwrap_or_else(|poisoned| poisoned.into_inner());
    attempts.push_front(attempt);
    attempts.truncate(DELIVERY_LOG_CAPACITY);
}

fn retry_delay(base: Duration, failed_attempt: u32) -> Duration {
    let multiplier = 1_u32.checked_shl(failed_attempt.saturating_sub(1)).unwrap_or(u32::MAX);
    base.saturating_mul(multiplier).min(Duration::from_secs(60))
}

fn is_retryable_status(status: StatusCode) -> bool {
    status == StatusCode::REQUEST_TIMEOUT
        || status == StatusCode::TOO_MANY_REQUESTS
        || status.is_server_error()
}

fn sign_payload(secret: &str, body: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC accepts all key lengths");
    mac.update(body);
    let digest = mac.finalize().into_bytes();
    let mut signature = String::from("sha256=");
    for byte in digest {
        use std::fmt::Write;
        let _ = write!(signature, "{byte:02x}");
    }
    signature
}

fn validate_target_url(raw: &str) -> Result<(), WebhookError> {
    let url = Url::parse(raw)
        .map_err(|_| webhook_error(StatusCode::BAD_REQUEST, "webhook URL must be absolute"))?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err(webhook_error(
            StatusCode::BAD_REQUEST,
            "webhook URL must use HTTP or HTTPS",
        ));
    }
    if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
        return Err(webhook_error(
            StatusCode::BAD_REQUEST,
            "webhook URL must not contain credentials or a fragment",
        ));
    }
    Ok(())
}

fn validate_event(event: &str) -> Result<(), WebhookError> {
    let valid = !event.is_empty()
        && event.len() <= 100
        && event
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte));
    if valid {
        Ok(())
    } else {
        Err(webhook_error(
            StatusCode::BAD_REQUEST,
            "event must contain only lowercase letters, digits, dot, dash or underscore",
        ))
    }
}

fn webhook_error(status: StatusCode, message: impl Into<String>) -> WebhookError {
    (status, Json(WebhookErrorDto { error: message.into() }))
}

fn env_number<T>(name: &str, default: T) -> T
where
    T: std::str::FromStr + Copy,
{
    std::env::var(name).ok().and_then(|value| value.parse().ok()).unwrap_or(default)
}

fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}

fn default_log_limit() -> usize {
    100
}

/// Register a signed webhook subscription.
#[utoipa::path(
    post,
    path = "/api/webhooks",
    security(("bearer_auth" = [])),
    request_body = CreateWebhookDto,
    responses(
        (status = 201, description = "Webhook registered", body = WebhookDto),
        (status = 400, description = "Invalid URL, secret or event", body = WebhookErrorDto),
        (status = 401, description = "Missing or expired bearer token")
    )
)]
pub(crate) async fn create_webhook(
    State(state): State<Arc<crate::AppState>>,
    headers: HeaderMap,
    Json(request): Json<CreateWebhookDto>,
) -> Result<(StatusCode, Json<WebhookDto>), WebhookError> {
    state.auth.authenticate(&headers).map_err(|(status, Json(error))| {
        webhook_error(status, error.error)
    })?;
    state.webhooks.register(request).map(|hook| (StatusCode::CREATED, Json(hook)))
}

/// List webhook subscriptions without exposing their signing secrets.
#[utoipa::path(
    get,
    path = "/api/webhooks",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Webhook registrations", body = [WebhookDto]),
        (status = 401, description = "Missing or expired bearer token")
    )
)]
pub(crate) async fn list_webhooks(
    State(state): State<Arc<crate::AppState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<WebhookDto>>, WebhookError> {
    state.auth.authenticate(&headers).map_err(|(status, Json(error))| {
        webhook_error(status, error.error)
    })?;
    Ok(Json(state.webhooks.list()))
}

/// Queue an event for all subscribed webhooks or one selected registration.
#[utoipa::path(
    post,
    path = "/api/webhooks/dispatch",
    security(("bearer_auth" = [])),
    request_body = DispatchWebhookDto,
    responses(
        (status = 202, description = "Deliveries queued", body = [QueuedDeliveryDto]),
        (status = 400, description = "Invalid event or subscription", body = WebhookErrorDto),
        (status = 401, description = "Missing or expired bearer token"),
        (status = 404, description = "Selected registration was not found", body = WebhookErrorDto),
        (status = 503, description = "Dispatcher queue unavailable", body = WebhookErrorDto)
    )
)]
pub(crate) async fn dispatch_webhook(
    State(state): State<Arc<crate::AppState>>,
    headers: HeaderMap,
    Json(request): Json<DispatchWebhookDto>,
) -> Result<(StatusCode, Json<Vec<QueuedDeliveryDto>>), WebhookError> {
    state.auth.authenticate(&headers).map_err(|(status, Json(error))| {
        webhook_error(status, error.error)
    })?;
    state
        .webhooks
        .dispatch(request)
        .await
        .map(|deliveries| (StatusCode::ACCEPTED, Json(deliveries)))
}

/// Read the bounded delivery-attempt log, including retry and terminal outcomes.
#[utoipa::path(
    get,
    path = "/api/webhooks/deliveries",
    security(("bearer_auth" = [])),
    params(DeliveryLogQuery),
    responses(
        (status = 200, description = "Newest delivery attempts first", body = [WebhookAttemptDto]),
        (status = 401, description = "Missing or expired bearer token")
    )
)]
pub(crate) async fn webhook_delivery_log(
    State(state): State<Arc<crate::AppState>>,
    headers: HeaderMap,
    Query(query): Query<DeliveryLogQuery>,
) -> Result<Json<Vec<WebhookAttemptDto>>, WebhookError> {
    state.auth.authenticate(&headers).map_err(|(status, Json(error))| {
        webhook_error(status, error.error)
    })?;
    Ok(Json(state.webhooks.logs(query)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_event_names_and_urls() {
        assert!(validate_event("analysis.finished").is_ok());
        assert!(validate_event("Gate Changed").is_err());
        assert!(validate_target_url("https://hooks.example/yunq").is_ok());
        assert!(validate_target_url("file:///etc/passwd").is_err());
        assert!(validate_target_url("https://user:pass@hooks.example/yunq").is_err());
    }

    #[test]
    fn payload_signature_is_stable_and_sensitive_to_body() {
        let first = sign_payload("0123456789abcdef", br#"{"ok":true}"#);
        let second = sign_payload("0123456789abcdef", br#"{"ok":true}"#);
        let changed = sign_payload("0123456789abcdef", br#"{"ok":false}"#);
        assert_eq!(first, second);
        assert!(first.starts_with("sha256="));
        assert_ne!(first, changed);
    }

    #[test]
    fn retry_policy_is_exponential_capped_and_status_aware() {
        let base = Duration::from_millis(500);
        assert_eq!(retry_delay(base, 1), Duration::from_millis(500));
        assert_eq!(retry_delay(base, 2), Duration::from_secs(1));
        assert_eq!(retry_delay(base, 10), Duration::from_secs(60));
        assert!(is_retryable_status(StatusCode::REQUEST_TIMEOUT));
        assert!(is_retryable_status(StatusCode::TOO_MANY_REQUESTS));
        assert!(is_retryable_status(StatusCode::BAD_GATEWAY));
        assert!(!is_retryable_status(StatusCode::BAD_REQUEST));
    }
}
