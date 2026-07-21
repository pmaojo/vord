//! Composition root: HTTP API (axum). Accepts scan requests, enqueues them
//! for workers over SQS, and serves persisted issues from Postgres.
//!
//! The OpenAPI contract lives here, at the adapter boundary: the serde DTOs
//! below carry utoipa schema derives, and the generated OpenAPI 3.1 document
//! is served at `GET /api-docs/openapi.json` (Swagger UI at `/swagger-ui`)
//! for frontend client codegen. Domain types stay serde-free.
//!
//! Env: `DATABASE_URL`, `YUNQ_QUEUE_URL`, `YUNQ_AWS_ENDPOINT_URL` (emulator),
//! `YUNQ_BIND` (default 0.0.0.0:8080).

use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::routing::get;
use axum::Json;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, OpenApi, ToSchema};
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;
use utoipa_swagger_ui::SwaggerUi;
use yunq_infra_postgres::PgIssueStorage;
use yunq_infra_sqs::SqsJobQueue;
use yunq_rules_engine::{IssueReader, JobQueue, ScanJob};

struct AppState {
    queue: SqsJobQueue,
    reader: PgIssueStorage,
}

#[derive(OpenApi)]
#[openapi(info(
    title = "yunq API",
    description = "Static analysis platform: enqueue scans, read issues."
))]
struct ApiDoc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let (router, api) = OpenApiRouter::with_openapi(ApiDoc::openapi())
        .routes(routes!(enqueue_scan))
        .routes(routes!(list_issues))
        .split_for_parts();

    // `yunq-server openapi` prints the contract and exits — deterministic
    // export for frontend codegen, no adapters or network involved.
    if std::env::args().nth(1).as_deref() == Some("openapi") {
        println!("{}", api.to_pretty_json()?);
        return Ok(());
    }

    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://yunq:yunq@localhost:5432/yunq".to_string());
    let queue_url = std::env::var("YUNQ_QUEUE_URL")
        .unwrap_or_else(|_| "http://localhost:4566/000000000000/yunq-scan-jobs".to_string());
    let bind = std::env::var("YUNQ_BIND").unwrap_or_else(|_| "0.0.0.0:8080".to_string());

    let reader = PgIssueStorage::connect_lazy(&database_url)?;
    let queue = SqsJobQueue::new(yunq_infra_sqs::sqs_client_from_env().await, queue_url);
    let state = Arc::new(AppState { queue, reader });

    let app = router
        .route("/health", get(|| async { "ok" }))
        .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", api))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&bind).await?;
    println!("yunq-server listening on {bind}");
    axum::serve(listener, app).await?;
    Ok(())
}

#[derive(Deserialize, ToSchema)]
struct ScanRequestDto {
    /// Project key the scan belongs to.
    project: String,
    /// Path to the checked-out sources, reachable by a worker.
    path: String,
}

#[derive(Serialize, ToSchema)]
struct ScanQueuedDto {
    status: &'static str,
}

/// Enqueue a scan job for asynchronous analysis.
#[utoipa::path(
    post,
    path = "/scans",
    request_body = ScanRequestDto,
    responses(
        (status = 202, description = "Scan job queued", body = ScanQueuedDto),
        (status = 400, description = "Invalid scan request"),
        (status = 502, description = "Queue backend unavailable"),
    )
)]
async fn enqueue_scan(
    State(state): State<Arc<AppState>>,
    Json(request): Json<ScanRequestDto>,
) -> Result<(StatusCode, Json<ScanQueuedDto>), (StatusCode, String)> {
    let job = ScanJob::new(request.project, request.path)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    state
        .queue
        .enqueue_scan(job)
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;
    Ok((StatusCode::ACCEPTED, Json(ScanQueuedDto { status: "queued" })))
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
struct IssuesQuery {
    /// Maximum number of issues to return (default 50, capped at 500).
    #[serde(default = "default_limit")]
    limit: usize,
}

fn default_limit() -> usize {
    50
}

#[derive(Serialize, ToSchema)]
struct IssueDto {
    rule: String,
    severity: String,
    file: String,
    line: u32,
    column: u32,
    message: String,
}

/// List the most recently detected issues.
#[utoipa::path(
    get,
    path = "/issues",
    params(IssuesQuery),
    responses(
        (status = 200, description = "Recent issues", body = [IssueDto]),
        (status = 502, description = "Storage backend unavailable"),
    )
)]
async fn list_issues(
    State(state): State<Arc<AppState>>,
    Query(query): Query<IssuesQuery>,
) -> Result<Json<Vec<IssueDto>>, (StatusCode, String)> {
    let issues = state
        .reader
        .recent_issues(query.limit.min(500))
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;
    Ok(Json(
        issues
            .iter()
            .map(|issue| IssueDto {
                rule: issue.rule().to_string(),
                severity: issue.severity().to_string(),
                file: issue.file().to_string(),
                line: issue.span().start_line,
                column: issue.span().start_col,
                message: issue.message().to_string(),
            })
            .collect(),
    ))
}
