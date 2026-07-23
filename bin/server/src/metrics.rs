use std::collections::BTreeMap;
use std::fmt::Write;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::{MatchedPath, State};
use axum::http::{header, Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use utoipa::ToSchema;

const LATENCY_BUCKETS: [f64; 9] = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 5.0];

#[derive(Clone)]
pub(crate) struct Metrics {
    inner: Arc<MetricsInner>,
}

struct MetricsInner {
    started: Instant,
    active_requests: AtomicI64,
    http: Mutex<HttpMetrics>,
    oauth_successes: AtomicU64,
    oauth_failures: AtomicU64,
    webhook_queued: AtomicU64,
    webhook_attempts: AtomicU64,
    webhook_successes: AtomicU64,
    webhook_failures: AtomicU64,
    webhook_retries: AtomicU64,
    webhook_queue_errors: AtomicU64,
}

#[derive(Default)]
struct HttpMetrics {
    requests: BTreeMap<(String, String, u16), u64>,
    latency: BTreeMap<(String, String), LatencyHistogram>,
}

#[derive(Default)]
struct LatencyHistogram {
    buckets: [u64; LATENCY_BUCKETS.len()],
    count: u64,
    sum_seconds: f64,
}

struct ActiveRequestGuard<'a>(&'a AtomicI64);

impl Drop for ActiveRequestGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

#[allow(dead_code)]
impl Metrics {
    pub(crate) fn new() -> Self {
        Self {
            inner: Arc::new(MetricsInner {
                started: Instant::now(),
                active_requests: AtomicI64::new(0),
                http: Mutex::new(HttpMetrics::default()),
                oauth_successes: AtomicU64::new(0),
                oauth_failures: AtomicU64::new(0),
                webhook_queued: AtomicU64::new(0),
                webhook_attempts: AtomicU64::new(0),
                webhook_successes: AtomicU64::new(0),
                webhook_failures: AtomicU64::new(0),
                webhook_retries: AtomicU64::new(0),
                webhook_queue_errors: AtomicU64::new(0),
            }),
        }
    }

    /// Seconds since this process started — backs `GET /api/system/info`'s
    /// `uptime_seconds` alongside the `yunq_process_uptime_seconds` gauge.
    pub(crate) fn uptime_seconds(&self) -> f64 {
        self.inner.started.elapsed().as_secs_f64()
    }

    pub(crate) fn oauth_succeeded(&self) {
        self.inner.oauth_successes.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn oauth_failed(&self) {
        self.inner.oauth_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn webhook_queued(&self) {
        self.inner.webhook_queued.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn webhook_attempted(&self) {
        self.inner.webhook_attempts.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn webhook_succeeded(&self) {
        self.inner.webhook_successes.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn webhook_failed(&self) {
        self.inner.webhook_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn webhook_retried(&self) {
        self.inner.webhook_retries.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn webhook_queue_error(&self) {
        self.inner.webhook_queue_errors.fetch_add(1, Ordering::Relaxed);
    }

    fn record_http(&self, method: String, route: String, status: StatusCode, elapsed: Duration) {
        let mut http = self.inner.http.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        *http.requests.entry((method.clone(), route.clone(), status.as_u16())).or_default() += 1;
        let histogram = http.latency.entry((method, route)).or_default();
        let seconds = elapsed.as_secs_f64();
        histogram.count += 1;
        histogram.sum_seconds += seconds;
        for (index, upper_bound) in LATENCY_BUCKETS.iter().enumerate() {
            if seconds <= *upper_bound {
                histogram.buckets[index] += 1;
            }
        }
    }

    fn render_process_metrics(&self, output: &mut String) {
        metric_header(output, "yunq_process_uptime_seconds", "Seconds since the server started", "gauge");
        let _ = writeln!(output, "yunq_process_uptime_seconds {}", self.inner.started.elapsed().as_secs_f64());
        metric_header(output, "yunq_http_active_requests", "HTTP requests currently being served", "gauge");
        let _ = writeln!(output, "yunq_http_active_requests {}", self.inner.active_requests.load(Ordering::Relaxed));
    }

    fn render_http_metrics(&self, output: &mut String) {
        let http = self.inner.http.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        metric_header(output, "yunq_http_requests_total", "Completed HTTP requests", "counter");
        for ((method, route, status), count) in &http.requests {
            let _ = writeln!(
                output,
                "yunq_http_requests_total{{method=\"{}\",route=\"{}\",status=\"{}\"}} {}",
                escape_label(method),
                escape_label(route),
                status,
                count
            );
        }
        metric_header(output, "yunq_http_request_duration_seconds", "HTTP request latency in seconds", "histogram");
        for ((method, route), histogram) in &http.latency {
            for (index, upper_bound) in LATENCY_BUCKETS.iter().enumerate() {
                let _ = writeln!(
                    output,
                    "yunq_http_request_duration_seconds_bucket{{method=\"{}\",route=\"{}\",le=\"{}\"}} {}",
                    escape_label(method),
                    escape_label(route),
                    upper_bound,
                    histogram.buckets[index]
                );
            }
            let labels = format!("method=\"{}\",route=\"{}\"", escape_label(method), escape_label(route));
            let _ = writeln!(
                output,
                "yunq_http_request_duration_seconds_bucket{{{labels},le=\"+Inf\"}} {}",
                histogram.count
            );
            let _ = writeln!(output, "yunq_http_request_duration_seconds_sum{{{labels}}} {}", histogram.sum_seconds);
            let _ = writeln!(output, "yunq_http_request_duration_seconds_count{{{labels}}} {}", histogram.count);
        }
    }

    fn render_oauth_and_webhook_metrics(&self, output: &mut String) {
        atomic_counter(output, "yunq_oauth_logins_total", "Completed OAuth logins", "result", [
            ("success", &self.inner.oauth_successes),
            ("failure", &self.inner.oauth_failures),
        ]);
        simple_atomic(output, "yunq_webhook_deliveries_queued_total", "Webhook deliveries accepted by the dispatcher", &self.inner.webhook_queued);
        simple_atomic(output, "yunq_webhook_delivery_attempts_total", "Webhook HTTP delivery attempts", &self.inner.webhook_attempts);
        atomic_counter(output, "yunq_webhook_deliveries_total", "Completed webhook deliveries", "result", [
            ("success", &self.inner.webhook_successes),
            ("failure", &self.inner.webhook_failures),
        ]);
        simple_atomic(output, "yunq_webhook_retries_total", "Webhook retries scheduled", &self.inner.webhook_retries);
        simple_atomic(output, "yunq_webhook_queue_errors_total", "Webhook deliveries rejected because the queue was unavailable", &self.inner.webhook_queue_errors);
    }

    fn render(&self) -> String {
        let mut output = String::with_capacity(4096);
        self.render_process_metrics(&mut output);
        self.render_http_metrics(&mut output);
        self.render_oauth_and_webhook_metrics(&mut output);
        output
    }
}

fn metric_header(output: &mut String, name: &str, help: &str, kind: &str) {
    let _ = writeln!(output, "# HELP {name} {help}");
    let _ = writeln!(output, "# TYPE {name} {kind}");
}

fn simple_atomic(output: &mut String, name: &str, help: &str, value: &AtomicU64) {
    metric_header(output, name, help, "counter");
    let _ = writeln!(output, "{name} {}", value.load(Ordering::Relaxed));
}

fn atomic_counter<const N: usize>(
    output: &mut String,
    name: &str,
    help: &str,
    label_name: &str,
    values: [(&str, &AtomicU64); N],
) {
    metric_header(output, name, help, "counter");
    for (label, value) in values {
        let _ = writeln!(output, "{name}{{{label_name}=\"{label}\"}} {}", value.load(Ordering::Relaxed));
    }
}

fn escape_label(value: &str) -> String {
    value.replace('\\', "\\\\").replace('\n', "\\n").replace('"', "\\\"")
}

pub(crate) async fn track_request(
    State(metrics): State<Metrics>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let method = request.method().as_str().to_owned();
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map(MatchedPath::as_str)
        .unwrap_or_else(|| request.uri().path())
        .to_owned();
    metrics.inner.active_requests.fetch_add(1, Ordering::Relaxed);
    let _active_guard = ActiveRequestGuard(&metrics.inner.active_requests);
    let started = Instant::now();
    let response = next.run(request).await;
    metrics.record_http(method, route, response.status(), started.elapsed());
    response
}

#[derive(ToSchema)]
#[allow(dead_code)]
pub(crate) struct PrometheusMetrics(String);

/// Export process, HTTP, OAuth and webhook metrics in Prometheus text format.
#[utoipa::path(
    get,
    path = "/api/system/metrics",
    responses(
        (status = 200, description = "Prometheus text exposition", body = String, content_type = "text/plain")
    )
)]
pub(crate) async fn prometheus_metrics(
    State(state): State<Arc<crate::AppState>>,
) -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8")],
        state.metrics.render(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_counters_and_cumulative_histogram() {
        let metrics = Metrics::new();
        metrics.record_http(
            "GET".to_string(),
            "/api/test".to_string(),
            StatusCode::OK,
            Duration::from_millis(7),
        );
        metrics.oauth_succeeded();
        metrics.webhook_retried();

        let rendered = metrics.render();

        assert!(rendered.contains("yunq_http_requests_total{method=\"GET\",route=\"/api/test\",status=\"200\"} 1"));
        assert!(rendered.contains("le=\"0.01\"} 1"));
        assert!(rendered.contains("le=\"+Inf\"} 1"));
        assert!(rendered.contains("yunq_oauth_logins_total{result=\"success\"} 1"));
        assert!(rendered.contains("yunq_webhook_retries_total 1"));
    }

    #[test]
    fn uptime_seconds_is_non_negative_and_small_just_after_start() {
        let metrics = Metrics::new();
        let uptime = metrics.uptime_seconds();
        assert!(uptime >= 0.0);
        assert!(uptime < 5.0, "expected a freshly created Metrics to report a tiny uptime, got {uptime}");
    }
}
