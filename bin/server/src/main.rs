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

use axum::extract::{Path, Query, State};
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
use yunq_rules_engine::{
    BulkOutcome, ChangelogAction, ChangelogEntry, HotspotReader, HotspotReview, HotspotStatus,
    IssueBulkWorkflow, IssueChangelogReader, IssueFacetReader, IssueQuery, IssueReader,
    IssueStatus, IssueTransition, IssueWorkflow, JobQueue, Resolution, RuleId, ScanJob, Severity,
    StoredHotspot, StoredIssue, WorkflowError,
};

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
        .routes(routes!(transition_issue))
        .routes(routes!(assign_issue))
        .routes(routes!(bulk_transition_issues))
        .routes(routes!(issue_changelog))
        .routes(routes!(list_hotspots))
        .routes(routes!(review_hotspot))
        .routes(routes!(list_rules))
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
    /// 1-based page number (default 1).
    #[serde(default)]
    page: usize,
    /// Page size (default 50, capped at 500).
    #[serde(default)]
    page_size: usize,
    /// Filter: info|minor|major|critical|blocker.
    severity: Option<String>,
    /// Filter: open|confirmed|resolved|closed.
    status: Option<String>,
    /// Filter: exact rule id, e.g. owasp:eval-usage.
    rule: Option<String>,
    /// Filter: substring of the file path.
    file: Option<String>,
    /// Filter: exact assignee.
    assignee: Option<String>,
    /// Comma-separated facets to compute alongside the page:
    /// severity, status, rule (e.g. `facets=severity,rule`).
    facets: Option<String>,
}

impl IssuesQuery {
    fn requested_facets(&self) -> Vec<String> {
        self.facets
            .as_deref()
            .map(|raw| raw.split(',').map(str::trim).filter(|s| !s.is_empty()).map(String::from).collect())
            .unwrap_or_default()
    }

    fn into_domain(self) -> Result<IssueQuery, String> {
        let severity = self
            .severity
            .map(|raw| Severity::parse(&raw).ok_or(format!("invalid severity {raw:?}")))
            .transpose()?;
        let status = self
            .status
            .map(|raw| IssueStatus::parse(&raw).ok_or(format!("invalid status {raw:?}")))
            .transpose()?;
        let rule = self
            .rule
            .map(|raw| RuleId::new(&raw).map_err(|e| e.to_string()))
            .transpose()?;
        Ok(IssueQuery {
            severity,
            status,
            rule,
            file: self.file,
            assignee: self.assignee,
            page: self.page,
            page_size: self.page_size,
        })
    }
}

#[derive(Serialize, ToSchema)]
struct IssuePageDto {
    items: Vec<IssueDto>,
    page: usize,
    page_size: usize,
    total: usize,
    /// Present only when the request included a `facets` param.
    facets: Option<FacetsDto>,
}

#[derive(Serialize, ToSchema)]
struct FacetCountDto {
    value: String,
    count: usize,
}

#[derive(Serialize, ToSchema)]
struct FacetsDto {
    by_severity: Vec<FacetCountDto>,
    by_status: Vec<FacetCountDto>,
    by_rule: Vec<FacetCountDto>,
}

#[derive(Serialize, ToSchema)]
struct IssueDto {
    id: i64,
    rule: String,
    severity: String,
    file: String,
    line: u32,
    column: u32,
    message: String,
    status: String,
    resolution: Option<String>,
    assignee: Option<String>,
}

impl From<&StoredIssue> for IssueDto {
    fn from(stored: &StoredIssue) -> Self {
        let issue = &stored.issue;
        Self {
            id: stored.id,
            rule: issue.rule().to_string(),
            severity: issue.severity().to_string(),
            file: issue.file().to_string(),
            line: issue.span().start_line,
            column: issue.span().start_col,
            message: issue.message().to_string(),
            status: issue.status().to_string(),
            resolution: issue.resolution().map(|r| r.to_string()),
            assignee: issue.assignee().map(str::to_string),
        }
    }
}

/// Search issues with filters and pagination (newest first).
#[utoipa::path(
    get,
    path = "/issues",
    params(IssuesQuery),
    responses(
        (status = 200, description = "One page of matching issues", body = IssuePageDto),
        (status = 400, description = "Invalid filter value"),
        (status = 502, description = "Storage backend unavailable"),
    )
)]
async fn list_issues(
    State(state): State<Arc<AppState>>,
    Query(query): Query<IssuesQuery>,
) -> Result<Json<IssuePageDto>, (StatusCode, String)> {
    let requested_facets = query.requested_facets();
    let query = query.into_domain().map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let page = state
        .reader
        .search_issues(&query)
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;

    let facets = if requested_facets.is_empty() {
        None
    } else {
        let computed = state
            .reader
            .facets(&query)
            .await
            .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;
        Some(FacetsDto {
            by_severity: if requested_facets.iter().any(|f| f == "severity") {
                computed.by_severity.iter().map(|(s, c)| FacetCountDto { value: s.to_string(), count: *c }).collect()
            } else {
                Vec::new()
            },
            by_status: if requested_facets.iter().any(|f| f == "status") {
                computed.by_status.iter().map(|(s, c)| FacetCountDto { value: s.to_string(), count: *c }).collect()
            } else {
                Vec::new()
            },
            by_rule: if requested_facets.iter().any(|f| f == "rule") {
                computed.by_rule.iter().map(|(r, c)| FacetCountDto { value: r.to_string(), count: *c }).collect()
            } else {
                Vec::new()
            },
        })
    };

    Ok(Json(IssuePageDto {
        items: page.items.iter().map(IssueDto::from).collect(),
        page: page.page,
        page_size: page.page_size,
        total: page.total,
        facets,
    }))
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
struct HotspotsQuery {
    /// Maximum number of hotspots to return (default 50, capped at 500).
    #[serde(default = "default_hotspot_limit")]
    limit: usize,
}

fn default_hotspot_limit() -> usize {
    50
}

#[derive(Serialize, ToSchema)]
struct HotspotDto {
    id: i64,
    rule: String,
    file: String,
    line: u32,
    column: u32,
    message: String,
    status: String,
}

impl From<&StoredHotspot> for HotspotDto {
    fn from(stored: &StoredHotspot) -> Self {
        let hotspot = &stored.hotspot;
        Self {
            id: stored.id,
            rule: hotspot.rule().to_string(),
            file: hotspot.file().to_string(),
            line: hotspot.span().start_line,
            column: hotspot.span().start_col,
            message: hotspot.message().to_string(),
            status: hotspot.status().to_string(),
        }
    }
}

/// List the most recently detected security hotspots.
#[utoipa::path(
    get,
    path = "/hotspots",
    params(HotspotsQuery),
    responses(
        (status = 200, description = "Recent hotspots", body = [HotspotDto]),
        (status = 502, description = "Storage backend unavailable"),
    )
)]
async fn list_hotspots(
    State(state): State<Arc<AppState>>,
    Query(query): Query<HotspotsQuery>,
) -> Result<Json<Vec<HotspotDto>>, (StatusCode, String)> {
    let hotspots = state
        .reader
        .recent_hotspots(query.limit.min(500))
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;
    Ok(Json(hotspots.iter().map(HotspotDto::from).collect()))
}

#[derive(Serialize, ToSchema)]
struct RuleDto {
    id: String,
    description: String,
    tags: Vec<String>,
    cwe: Option<u32>,
    default_severity: String,
    remediation_effort_minutes: u32,
    produces_hotspots: bool,
}

/// The catalog of every rule this server's analyzers ship with.
#[utoipa::path(
    get,
    path = "/rules",
    responses((status = 200, description = "Rule catalog", body = [RuleDto]))
)]
async fn list_rules() -> Json<Vec<RuleDto>> {
    let per_file = yunq_rules_owasp::all_rules()
        .into_iter()
        .chain(yunq_rules_smells::all_rules())
        .map(|rule| {
            let metadata = rule.metadata();
            RuleDto {
                id: rule.id().to_string(),
                description: metadata.description,
                tags: metadata.tags,
                cwe: metadata.cwe,
                default_severity: rule.default_severity().to_string(),
                remediation_effort_minutes: rule.remediation_effort_minutes(),
                produces_hotspots: metadata.produces_hotspots,
            }
        });
    let cross_file = yunq_rules_owasp::all_cross_rules().into_iter().map(|rule| {
        let metadata = rule.metadata();
        RuleDto {
            id: rule.id().to_string(),
            description: metadata.description,
            tags: metadata.tags,
            cwe: metadata.cwe,
            default_severity: rule.default_severity().to_string(),
            remediation_effort_minutes: rule.remediation_effort_minutes(),
            produces_hotspots: metadata.produces_hotspots,
        }
    });
    Json(per_file.chain(cross_file).collect())
}

#[derive(Deserialize, ToSchema)]
struct HotspotReviewRequestDto {
    /// One of: to-review, acknowledged, fixed, safe.
    status: String,
}

/// Record a reviewer's verdict on a hotspot.
#[utoipa::path(
    put,
    path = "/hotspots/{id}/status",
    params(("id" = i64, Path, description = "Hotspot id")),
    request_body = HotspotReviewRequestDto,
    responses(
        (status = 200, description = "Hotspot after the review", body = HotspotDto),
        (status = 400, description = "Unknown status"),
        (status = 404, description = "Hotspot not found"),
        (status = 502, description = "Storage backend unavailable"),
    )
)]
async fn review_hotspot(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
    Json(request): Json<HotspotReviewRequestDto>,
) -> Result<Json<HotspotDto>, (StatusCode, String)> {
    let status = HotspotStatus::parse(&request.status).ok_or((
        StatusCode::BAD_REQUEST,
        format!("invalid status {:?} (to-review|acknowledged|fixed|safe)", request.status),
    ))?;
    let stored = state
        .reader
        .review_hotspot(id, status)
        .await
        .map_err(workflow_error_response)?;
    Ok(Json(HotspotDto::from(&stored)))
}

#[derive(Deserialize, ToSchema)]
struct TransitionRequestDto {
    /// One of: confirm, resolve, reopen, close.
    transition: String,
    /// Required when transition is `resolve`: fixed, wont-fix, false-positive.
    resolution: Option<String>,
}

fn parse_transition(dto: &TransitionRequestDto) -> Result<IssueTransition, String> {
    match dto.transition.as_str() {
        "confirm" => Ok(IssueTransition::Confirm),
        "reopen" => Ok(IssueTransition::Reopen),
        "close" => Ok(IssueTransition::Close),
        "resolve" => {
            let raw = dto.resolution.as_deref().ok_or("resolve requires a resolution")?;
            let resolution = Resolution::parse(raw)
                .ok_or("invalid resolution (fixed|wont-fix|false-positive)")?;
            Ok(IssueTransition::Resolve(resolution))
        }
        other => Err(format!("invalid transition {other:?} (confirm|resolve|reopen|close)")),
    }
}

fn workflow_error_response(error: WorkflowError) -> (StatusCode, String) {
    match &error {
        WorkflowError::NotFound(_) => (StatusCode::NOT_FOUND, error.to_string()),
        WorkflowError::InvalidTransition(_) => (StatusCode::CONFLICT, error.to_string()),
        WorkflowError::Storage(_) | WorkflowError::Corrupt(..) => {
            (StatusCode::BAD_GATEWAY, error.to_string())
        }
    }
}

/// Apply a workflow transition to an issue.
#[utoipa::path(
    post,
    path = "/issues/{id}/transitions",
    params(("id" = i64, Path, description = "Issue id")),
    request_body = TransitionRequestDto,
    responses(
        (status = 200, description = "Issue after the transition", body = IssueDto),
        (status = 400, description = "Unknown transition or resolution"),
        (status = 404, description = "Issue not found"),
        (status = 409, description = "Transition not allowed from the current status"),
        (status = 502, description = "Storage backend unavailable"),
    )
)]
async fn transition_issue(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
    Json(request): Json<TransitionRequestDto>,
) -> Result<Json<IssueDto>, (StatusCode, String)> {
    let transition =
        parse_transition(&request).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    let stored = state
        .reader
        .apply_transition(id, transition)
        .await
        .map_err(workflow_error_response)?;
    Ok(Json(IssueDto::from(&stored)))
}

#[derive(Deserialize, ToSchema)]
struct AssigneeRequestDto {
    /// User to assign; null/omitted to unassign.
    assignee: Option<String>,
}

/// Assign or unassign an issue.
#[utoipa::path(
    put,
    path = "/issues/{id}/assignee",
    params(("id" = i64, Path, description = "Issue id")),
    request_body = AssigneeRequestDto,
    responses(
        (status = 200, description = "Issue after the assignment", body = IssueDto),
        (status = 404, description = "Issue not found"),
        (status = 502, description = "Storage backend unavailable"),
    )
)]
async fn assign_issue(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
    Json(request): Json<AssigneeRequestDto>,
) -> Result<Json<IssueDto>, (StatusCode, String)> {
    let stored = state
        .reader
        .set_assignee(id, request.assignee)
        .await
        .map_err(workflow_error_response)?;
    Ok(Json(IssueDto::from(&stored)))
}

#[derive(Deserialize, ToSchema)]
struct BulkTransitionRequestDto {
    issue_ids: Vec<i64>,
    /// One of: confirm, resolve, reopen, close.
    transition: String,
    /// Required when transition is `resolve`: fixed, wont-fix, false-positive.
    resolution: Option<String>,
}

#[derive(Serialize, ToSchema)]
struct BulkOutcomeDto {
    issue_id: i64,
    status: &'static str,
    issue: Option<IssueDto>,
    error: Option<String>,
}

impl From<&BulkOutcome> for BulkOutcomeDto {
    fn from(outcome: &BulkOutcome) -> Self {
        match outcome {
            BulkOutcome::Applied(stored) => Self {
                issue_id: stored.id,
                status: "applied",
                issue: Some(IssueDto::from(stored)),
                error: None,
            },
            BulkOutcome::Failed { issue_id, reason } => {
                Self { issue_id: *issue_id, status: "failed", issue: None, error: Some(reason.clone()) }
            }
        }
    }
}

/// Apply the same transition to many issues at once. Each issue succeeds or
/// fails independently — one illegal transition does not abort the batch.
#[utoipa::path(
    post,
    path = "/issues/bulk-transition",
    request_body = BulkTransitionRequestDto,
    responses(
        (status = 200, description = "Per-issue outcomes", body = [BulkOutcomeDto]),
        (status = 400, description = "Unknown transition or resolution"),
        (status = 502, description = "Storage backend unavailable"),
    )
)]
async fn bulk_transition_issues(
    State(state): State<Arc<AppState>>,
    Json(request): Json<BulkTransitionRequestDto>,
) -> Result<Json<Vec<BulkOutcomeDto>>, (StatusCode, String)> {
    let transition = parse_transition(&TransitionRequestDto {
        transition: request.transition,
        resolution: request.resolution,
    })
    .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    let outcomes = state
        .reader
        .bulk_transition(&request.issue_ids, transition)
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;
    Ok(Json(outcomes.iter().map(BulkOutcomeDto::from).collect()))
}

#[derive(Serialize, ToSchema)]
struct ChangelogEntryDto {
    action: &'static str,
    from_status: Option<String>,
    transition: Option<String>,
    resolution: Option<String>,
    assignee: Option<String>,
    at: String,
}

impl From<&ChangelogEntry> for ChangelogEntryDto {
    fn from(entry: &ChangelogEntry) -> Self {
        match &entry.action {
            ChangelogAction::Transitioned { from, transition } => {
                let (name, resolution) = match transition {
                    IssueTransition::Confirm => ("confirm", None),
                    IssueTransition::Reopen => ("reopen", None),
                    IssueTransition::Close => ("close", None),
                    IssueTransition::Resolve(r) => ("resolve", Some(r.to_string())),
                };
                Self {
                    action: "transitioned",
                    from_status: Some(from.to_string()),
                    transition: Some(name.to_string()),
                    resolution,
                    assignee: None,
                    at: entry.at.clone(),
                }
            }
            ChangelogAction::Assigned { assignee } => Self {
                action: "assigned",
                from_status: None,
                transition: None,
                resolution: None,
                assignee: assignee.clone(),
                at: entry.at.clone(),
            },
        }
    }
}

/// The recorded workflow history of an issue (audit trail).
#[utoipa::path(
    get,
    path = "/issues/{id}/changelog",
    params(("id" = i64, Path, description = "Issue id")),
    responses(
        (status = 200, description = "Changelog entries, oldest first", body = [ChangelogEntryDto]),
        (status = 502, description = "Storage backend unavailable"),
    )
)]
async fn issue_changelog(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
) -> Result<Json<Vec<ChangelogEntryDto>>, (StatusCode, String)> {
    let entries = state
        .reader
        .changelog(id)
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;
    Ok(Json(entries.iter().map(ChangelogEntryDto::from).collect()))
}
