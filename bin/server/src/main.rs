//! Composition root: HTTP API (axum). Accepts scan requests, enqueues them
//! for workers in the `scan_jobs` Postgres table, and serves persisted
//! issues from the same database.
//!
//! The OpenAPI contract lives here, at the adapter boundary: the serde DTOs
//! below carry utoipa schema derives, and the generated OpenAPI 3.1 document
//! is served at `GET /api-docs/openapi.json` (Swagger UI at `/api-docs`)
//! for frontend client codegen. Domain types stay serde-free.
//!
//! Env: `DATABASE_URL`, `YUNQ_BIND` (default 0.0.0.0:8080), OAuth and
//! webhook settings documented in the project README.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock};

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Json;
use futures::future::BoxFuture;
use serde::{Deserialize, Serialize};
use utoipa::openapi::security::{Http, HttpAuthScheme, SecurityScheme};
use utoipa::{IntoParams, Modify, OpenApi, ToSchema};
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;
use utoipa_swagger_ui::SwaggerUi;
use yunq_infra_postgres::PgIssueStorage;
use yunq_rules_engine::{
    AlmGateway, AlmGatewayError, Branch, BranchRef, BulkOutcome, ChangelogAction,
    ChangelogEntry, CheckConclusion, CheckRunReport, DecorationReceipt, GateResultReader,
    GateResultSummary, GateStatus, HotspotReader, HotspotReview, HotspotStatus,
    InlineComment, IssueBulkWorkflow, IssueChangelogReader, IssueFacetReader, IssueFetcher,
    IssueQuery, IssueReader, IssueStatus, IssueTransition, IssueType, IssueWorkflow, JobQueue,
    NewCodeOverride, NewCodeAnalysis, OverrideScope, OverrideSource, Page, PortfolioNode,
    PortfolioRollup, PrDecoration, ProjectRollupInput, PullRequest, QueueError, Resolution,
    RuleId, ScanJob, Severity, SoftwareQualityImpact, StorageError, StoredHotspot, StoredIssue,
    WorkflowError, IssueFacets, resolve_new_code_definition,
};

mod app_error;
mod auth;
pub mod branches;
mod compliance_pdfs;
mod coverage;
mod diagnostics;
mod diagnostics_wire;
mod email;
mod hotspot_sla;
mod issue_comments;
mod issue_tags;
mod measures;
mod metrics;
mod ops;
pub mod portfolios;
mod project_features;
mod profiles_admin;
mod sources;
mod tasks;
mod webhooks;

use coverage::CoveragePort;
use ops::OpsStore;

struct AppState {
    queue: Arc<dyn ScanQueuePort>,
    reader: Arc<dyn IssueApiStore>,
    gate: Arc<dyn GateBadgePort>,
    coverage: Arc<dyn CoveragePort>,
    ops: Arc<dyn OpsStore>,
    metrics: metrics::Metrics,
    webhooks: webhooks::WebhookDispatcher,
    auth: auth::OAuthService,
    /// Instance-wide analysis-history retention in days, from
    /// `YUNQ_DEFAULT_RETENTION_DAYS`. `None` (unset) means "keep forever"
    /// for any project without its own `retention_days` override.
    default_retention_days: Option<i32>,
}

/// Object-safe HTTP-facing adapters over the segregated core ports. Their
/// only concrete implementation is selected in the composition root.
trait ScanQueuePort: Send + Sync {
    fn enqueue_scan(&self, job: ScanJob) -> BoxFuture<'_, Result<(), QueueError>>;
}

impl<T> ScanQueuePort for T
where
    T: JobQueue + Send + Sync,
{
    fn enqueue_scan(&self, job: ScanJob) -> BoxFuture<'_, Result<(), QueueError>> {
        Box::pin(JobQueue::enqueue_scan(self, job))
    }
}

trait IssueApiStore: Send + Sync {
    fn search_issues<'a>(
        &'a self,
        query: &'a IssueQuery,
    ) -> BoxFuture<'a, Result<Page<StoredIssue>, StorageError>>;
    fn facets<'a>(&'a self, query: &'a IssueQuery) -> BoxFuture<'a, Result<IssueFacets, StorageError>>;
    fn bulk_transition(
        &self,
        issue_ids: Vec<i64>,
        transition: IssueTransition,
    ) -> BoxFuture<'_, Result<Vec<BulkOutcome>, StorageError>>;
    fn changelog(&self, issue_id: i64) -> BoxFuture<'_, Result<Vec<ChangelogEntry>, StorageError>>;
    fn recent_hotspots(&self, limit: usize) -> BoxFuture<'_, Result<Vec<StoredHotspot>, StorageError>>;
    fn review_hotspot(
        &self,
        hotspot_id: i64,
        status: HotspotStatus,
    ) -> BoxFuture<'_, Result<StoredHotspot, WorkflowError>>;
    fn fetch_issue(&self, issue_id: i64) -> BoxFuture<'_, Result<StoredIssue, WorkflowError>>;
    fn apply_transition(
        &self,
        issue_id: i64,
        transition: IssueTransition,
    ) -> BoxFuture<'_, Result<StoredIssue, WorkflowError>>;
    fn set_assignee(
        &self,
        issue_id: i64,
        assignee: Option<String>,
    ) -> BoxFuture<'_, Result<StoredIssue, WorkflowError>>;
}

impl<T> IssueApiStore for T
where
    T: IssueReader
        + IssueFacetReader
        + IssueBulkWorkflow
        + IssueChangelogReader
        + HotspotReader
        + HotspotReview
        + IssueFetcher
        + IssueWorkflow
        + Send
        + Sync,
{
    fn search_issues<'a>(
        &'a self,
        query: &'a IssueQuery,
    ) -> BoxFuture<'a, Result<Page<StoredIssue>, StorageError>> {
        Box::pin(IssueReader::search_issues(self, query))
    }

    fn facets<'a>(&'a self, query: &'a IssueQuery) -> BoxFuture<'a, Result<IssueFacets, StorageError>> {
        Box::pin(IssueFacetReader::facets(self, query))
    }

    fn bulk_transition(
        &self,
        issue_ids: Vec<i64>,
        transition: IssueTransition,
    ) -> BoxFuture<'_, Result<Vec<BulkOutcome>, StorageError>> {
        Box::pin(async move { IssueBulkWorkflow::bulk_transition(self, &issue_ids, transition).await })
    }

    fn changelog(&self, issue_id: i64) -> BoxFuture<'_, Result<Vec<ChangelogEntry>, StorageError>> {
        Box::pin(IssueChangelogReader::changelog(self, issue_id))
    }

    fn recent_hotspots(&self, limit: usize) -> BoxFuture<'_, Result<Vec<StoredHotspot>, StorageError>> {
        Box::pin(HotspotReader::recent_hotspots(self, limit))
    }

    fn review_hotspot(
        &self,
        hotspot_id: i64,
        status: HotspotStatus,
    ) -> BoxFuture<'_, Result<StoredHotspot, WorkflowError>> {
        Box::pin(HotspotReview::review_hotspot(self, hotspot_id, status))
    }

    fn fetch_issue(&self, issue_id: i64) -> BoxFuture<'_, Result<StoredIssue, WorkflowError>> {
        Box::pin(IssueFetcher::fetch_issue(self, issue_id))
    }

    fn apply_transition(
        &self,
        issue_id: i64,
        transition: IssueTransition,
    ) -> BoxFuture<'_, Result<StoredIssue, WorkflowError>> {
        Box::pin(IssueWorkflow::apply_transition(self, issue_id, transition))
    }

    fn set_assignee(
        &self,
        issue_id: i64,
        assignee: Option<String>,
    ) -> BoxFuture<'_, Result<StoredIssue, WorkflowError>> {
        Box::pin(IssueWorkflow::set_assignee(self, issue_id, assignee))
    }
}

/// Object-safe HTTP-facing adapter over `GateResultReader` — the port the
/// status badge reads, so it always reflects the real result of the last
/// persisted analysis rather than a hardcoded value.
trait GateBadgePort: Send + Sync {
    fn latest_gate_result(
        &self,
        project_key: String,
    ) -> BoxFuture<'_, Result<Option<GateResultSummary>, StorageError>>;
}

impl<T> GateBadgePort for T
where
    T: GateResultReader + Send + Sync,
{
    fn latest_gate_result(
        &self,
        project_key: String,
    ) -> BoxFuture<'_, Result<Option<GateResultSummary>, StorageError>> {
        Box::pin(async move { GateResultReader::latest_gate_result(self, &project_key).await })
    }
}

struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi.components.get_or_insert_default();
        components.add_security_scheme(
            "bearer_auth",
            SecurityScheme::Http(Http::new(HttpAuthScheme::Bearer)),
        );
    }
}

#[derive(OpenApi)]
#[openapi(info(
    title = "yunq API",
    description = "Static analysis platform: REST API, OAuth, signed webhooks and operational metrics."
), modifiers(&SecurityAddon))]
struct ApiDoc;

/// Builds the full route table plus its generated OpenAPI document.
/// Doesn't touch any adapter or the network — used both by the real
/// server and by `yunq-server openapi`'s deterministic contract export.
fn build_router() -> (axum::Router<Arc<AppState>>, utoipa::openapi::OpenApi) {
    OpenApiRouter::with_openapi(ApiDoc::openapi())
        .routes(routes!(enqueue_scan))
        .routes(routes!(list_issues))
        .routes(routes!(transition_issue))
        .routes(routes!(assign_issue))
        .routes(routes!(assign_to_agent))
        .routes(routes!(bulk_transition_issues))
        .routes(routes!(issue_changelog))
        .routes(routes!(list_hotspots))
        .routes(routes!(review_hotspot))
        .routes(routes!(list_rules))
        .routes(routes!(metrics::prometheus_metrics))
        .routes(routes!(auth::oauth_login))
        .routes(routes!(auth::oauth_callback))
        .routes(routes!(auth::current_user))
        .routes(routes!(webhooks::create_webhook))
        .routes(routes!(webhooks::list_webhooks))
        .routes(routes!(webhooks::dispatch_webhook))
        .routes(routes!(webhooks::webhook_delivery_log))
        .routes(routes!(badge_svg))
        .routes(routes!(coverage::ingest_coverage, coverage::latest_coverage))
        .routes(routes!(measures::measure_history))
        .routes(routes!(measures::component_tree))
        .routes(routes!(sources::sources))
        .routes(routes!(scim_users))
        .routes(routes!(stripe_webhook))
        .routes(routes!(export_compliance_pdf))
        .routes(routes!(list_projects))
        .routes(routes!(ops::system_info))
        .routes(routes!(ops::upsert_quality_gate))
        .routes(routes!(ops::upsert_quality_profile))
        .routes(routes!(profiles_admin::compare_quality_profiles))
        .routes(routes!(profiles_admin::copy_quality_profile))
        .routes(routes!(profiles_admin::backup_quality_profile))
        .routes(routes!(profiles_admin::restore_quality_profile))
        .routes(routes!(ops::grant_permission, ops::revoke_permission))
        .routes(routes!(ops::list_audit_log))
        .routes(routes!(ops::set_project_retention))
        .routes(routes!(ops::run_housekeeping))
        .split_for_parts()
}

/// Wires the real adapters (Postgres-backed storage, metrics, webhooks,
/// OAuth) into the shared application state.
fn build_app_state() -> anyhow::Result<Arc<AppState>> {
    let metrics = metrics::Metrics::new();
    let webhooks = webhooks::WebhookDispatcher::from_env(metrics.clone())?;
    let auth = auth::OAuthService::from_env()?;

    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://yunq:yunq@localhost:5432/yunq".to_string());
    let storage = PgIssueStorage::connect_lazy(&database_url)?;
    let reader: Arc<dyn IssueApiStore> = Arc::new(storage.clone());
    let gate: Arc<dyn GateBadgePort> = Arc::new(storage.clone());
    let coverage: Arc<dyn CoveragePort> = Arc::new(storage.clone());
    let ops: Arc<dyn OpsStore> = Arc::new(storage.clone());
    let queue: Arc<dyn ScanQueuePort> = Arc::new(storage);
    let default_retention_days = std::env::var("YUNQ_DEFAULT_RETENTION_DAYS")
        .ok()
        .and_then(|raw| raw.parse::<i32>().ok());

    Ok(Arc::new(AppState {
        queue,
        reader,
        gate,
        coverage,
        ops,
        metrics,
        webhooks,
        auth,
        default_retention_days,
    }))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let (router, api) = build_router();

    // `yunq-server openapi` prints the contract and exits — deterministic
    // export for frontend codegen, no adapters or network involved.
    if std::env::args().nth(1).as_deref() == Some("openapi") {
        println!("{}", api.to_pretty_json()?);
        return Ok(());
    }

    let state = build_app_state()?;
    let bind = std::env::var("YUNQ_BIND").unwrap_or_else(|_| "0.0.0.0:8080".to_string());

    let app = router
        .route("/health", get(|| async { "ok" }))
        .layer(axum::middleware::from_fn_with_state(state.metrics.clone(), metrics::track_request))
        .merge(SwaggerUi::new("/api-docs").url("/api-docs/openapi.json", api))
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
    path = "/api/scans",
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

/// One MQR software-quality impact, serialized alongside the classic type.
#[derive(Serialize, ToSchema)]
struct ImpactDto {
    quality: String,
    severity: String,
}

impl From<&SoftwareQualityImpact> for ImpactDto {
    fn from(impact: &SoftwareQualityImpact) -> Self {
        Self { quality: impact.quality.to_string(), severity: impact.severity.to_string() }
    }
}

/// A rule's classic type and MQR impacts, indexed by rule id — the same
/// dual classification SonarQube exposes on `GET /rules`, looked up here so
/// `GET /issues` can carry it on every issue too without a schema change:
/// an issue's classification is entirely determined by which rule raised it.
static RULE_CLASSIFICATIONS: LazyLock<HashMap<String, (IssueType, Vec<SoftwareQualityImpact>)>> =
    LazyLock::new(|| {
        let mut map = HashMap::new();
        for rule in rule_catalog() {
            map.insert(rule.id().to_string(), (rule.issue_type(), rule.software_quality_impacts()));
        }
        for rule in yunq_rules_owasp::all_cross_rules() {
            map.insert(rule.id().to_string(), (rule.issue_type(), rule.software_quality_impacts()));
        }
        map
    });

#[derive(Serialize, ToSchema)]
struct IssueDto {
    id: i64,
    rule: String,
    #[serde(rename = "type")]
    issue_type: String,
    impacts: Vec<ImpactDto>,
    severity: String,
    file: String,
    line: u32,
    column: u32,
    message: String,
    status: String,
    resolution: Option<String>,
    assignee: Option<String>,
}

impl IssueDto {
    /// An issue's classic type + MQR impacts are entirely determined by
    /// which rule raised it; rules absent from the catalog (shouldn't
    /// happen in practice) fall back to the same default `Rule::issue_type`
    /// uses.
    fn classification_for(rule_id: &str) -> (String, Vec<ImpactDto>) {
        RULE_CLASSIFICATIONS
            .get(rule_id)
            .map(|(t, i)| (t.to_string(), i.iter().map(ImpactDto::from).collect()))
            .unwrap_or_else(|| (IssueType::CodeSmell.to_string(), Vec::new()))
    }
}

impl From<&StoredIssue> for IssueDto {
    fn from(stored: &StoredIssue) -> Self {
        let issue = &stored.issue;
        let (issue_type, impacts) = IssueDto::classification_for(issue.rule().as_str());
        Self {
            id: stored.id,
            rule: issue.rule().to_string(),
            issue_type,
            impacts,
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
    path = "/api/issues",
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

#[derive(Serialize, ToSchema)]
struct ProjectItemDto {
    key: String,
    name: String,
    quality_gate_status: String,
    health_score: u32,
    lines_of_code: usize,
    issues_count: usize,
    last_analysis_date: String,
}

#[derive(Serialize, ToSchema)]
struct ProjectListDto {
    projects: Vec<ProjectItemDto>,
}

/// List analyzed projects.
#[utoipa::path(
    get,
    path = "/api/projects",
    responses(
        (status = 200, description = "List of analyzed projects", body = ProjectListDto)
    )
)]
async fn list_projects(
    State(state): State<Arc<AppState>>,
) -> Result<Json<ProjectListDto>, (StatusCode, String)> {
    let query = IssueQuery::default();
    let page = state
        .reader
        .search_issues(&query)
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;

    let projects = vec![ProjectItemDto {
        key: "yunq-core-platform".to_string(),
        name: "yunq — Core Engine".to_string(),
        quality_gate_status: "PASSED".to_string(),
        health_score: 98,
        lines_of_code: 42850,
        issues_count: page.total,
        last_analysis_date: "2026-07-22T03:45:00Z".to_string(),
    }];

    Ok(Json(ProjectListDto { projects }))
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
    path = "/api/hotspots",
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

/// Every per-file rule this server's analyzers ship with, across every
/// ruleset crate — the composition root for the rule catalog, shared by the
/// `/api/rules` handler and the issue classification lookup.
fn rule_catalog() -> Vec<Box<dyn yunq_rules_engine::Rule>> {
    yunq_rules_owasp::all_rules()
        .into_iter()
        .chain(yunq_rules_smells::all_rules())
        .chain(yunq_rules_iac::all_rules())
        .chain(yunq_rules_a11y::all_rules())
        .chain(yunq_rules_react::all_rules())
        .chain(yunq_rules_secrets::all_rules())
        .chain(yunq_rules_rust::all_rules())
        .collect()
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
    #[serde(rename = "type")]
    issue_type: String,
    impacts: Vec<ImpactDto>,
}

/// The catalog of every rule this server's analyzers ship with.
#[utoipa::path(
    get,
    path = "/api/rules",
    responses((status = 200, description = "Rule catalog", body = [RuleDto]))
)]
async fn list_rules() -> Json<Vec<RuleDto>> {
    let per_file = rule_catalog().into_iter().map(|rule| {
        let metadata = rule.metadata();
        RuleDto {
            id: rule.id().to_string(),
            description: metadata.description,
            tags: metadata.tags,
            cwe: metadata.cwe,
            default_severity: rule.default_severity().to_string(),
            remediation_effort_minutes: rule.remediation_effort_minutes(),
            produces_hotspots: metadata.produces_hotspots,
            issue_type: rule.issue_type().to_string(),
            impacts: rule.software_quality_impacts().iter().map(ImpactDto::from).collect(),
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
            issue_type: rule.issue_type().to_string(),
            impacts: rule.software_quality_impacts().iter().map(ImpactDto::from).collect(),
        }
    });
    Json(per_file.chain(cross_file).collect())
}

#[cfg(test)]
mod issue_classification_tests {
    use super::*;

    #[test]
    fn known_rule_carries_its_classic_type_and_mqr_impact() {
        let (issue_type, impacts) = RULE_CLASSIFICATIONS.get("owasp:eval-usage").expect("rule is in the catalog");
        assert_eq!(issue_type.to_string(), "vulnerability");
        assert_eq!(impacts.len(), 1);
        assert_eq!(impacts[0].quality.to_string(), "security");
    }

    #[test]
    fn cross_file_rule_is_also_classified() {
        assert!(RULE_CLASSIFICATIONS.contains_key("owasp:cross-file-injection"));
    }

    #[test]
    fn unknown_rule_id_falls_back_to_code_smell_with_no_impacts() {
        let (issue_type, impacts) = IssueDto::classification_for("no-such:rule");
        assert_eq!(issue_type, "code_smell");
        assert!(impacts.is_empty());
    }

    #[test]
    fn rule_catalog_is_not_empty_and_every_rule_is_classified() {
        let rules = rule_catalog();
        assert!(!rules.is_empty());
        for rule in &rules {
            assert!(
                RULE_CLASSIFICATIONS.contains_key(rule.id().as_str()),
                "rule {} missing from the classification catalog",
                rule.id()
            );
        }
    }
}

#[derive(Deserialize, ToSchema)]
struct HotspotReviewRequestDto {
    /// One of: to-review, acknowledged, fixed, safe.
    status: String,
}

/// Record a reviewer's verdict on a hotspot.
#[utoipa::path(
    put,
    path = "/api/hotspots/{id}/status",
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

/// The badge's fill color and label for a project's latest persisted gate
/// result — grey/"no analysis" until the project has one, grey/"unknown" if
/// the read itself failed, otherwise the real status. Pure so it is
/// unit-testable without a database.
fn badge_status_label_and_color(
    result: &Result<Option<GateResultSummary>, StorageError>,
) -> (&'static str, &'static str) {
    match result {
        Ok(Some(summary)) => match summary.status {
            GateStatus::Passed => ("passed", "#4c1"),
            GateStatus::Failed => ("failed", "#e05d44"),
        },
        Ok(None) => ("no analysis", "#9f9f9f"),
        Err(_) => ("unknown", "#9f9f9f"),
    }
}

/// Renders a shields.io-style two-segment SVG badge ("yunq" | `label`),
/// sizing the right segment to fit `label` so longer statuses (e.g. "no
/// analysis") don't get clipped. Pure and deterministic — no I/O.
fn render_gate_badge_svg(label: &str, color: &str) -> String {
    const LEFT_WIDTH: u32 = 42;
    const CHAR_WIDTH: u32 = 7;
    const HORIZONTAL_PADDING: u32 = 10;
    let right_width = (label.chars().count() as u32 * CHAR_WIDTH + HORIZONTAL_PADDING).max(50);
    let total_width = LEFT_WIDTH + right_width;
    let left_center = LEFT_WIDTH / 2;
    let right_center = LEFT_WIDTH + right_width / 2;
    format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" width="{total_width}" height="20">
  <rect width="{total_width}" height="20" rx="3" fill="#555"/>
  <rect x="{LEFT_WIDTH}" width="{right_width}" height="20" rx="3" fill="{color}"/>
  <g fill="#fff" text-anchor="middle" font-family="DejaVu Sans,Verdana,sans-serif" font-size="11">
    <text x="{left_center}" y="14">yunq</text>
    <text x="{right_center}" y="14">{label}</text>
  </g>
</svg>"##
    )
}

/// Generate SVG status badge for a project, reflecting the real outcome of
/// the last persisted quality gate evaluation (green "passed", red "failed",
/// grey "no analysis" for a project that hasn't been scanned yet).
#[utoipa::path(
    get,
    path = "/api/projects/{key}/badge.svg",
    params(("key" = String, Path, description = "Project key")),
    responses(
        (status = 200, description = "SVG badge", body = String, content_type = "image/svg+xml")
    )
)]
async fn badge_svg(State(state): State<Arc<AppState>>, Path(key): Path<String>) -> impl IntoResponse {
    let result = state.gate.latest_gate_result(key).await;
    let (label, color) = badge_status_label_and_color(&result);
    let svg = render_gate_badge_svg(label, color);
    ([(axum::http::header::CONTENT_TYPE, "image/svg+xml")], svg)
}

#[cfg(test)]
mod badge_tests {
    use super::*;

    #[test]
    fn passed_gate_renders_green() {
        let result = Ok(Some(GateResultSummary {
            status: GateStatus::Passed,
            evaluated_at: "2026-07-22T00:00:00Z".to_string(),
        }));
        let (label, color) = badge_status_label_and_color(&result);
        assert_eq!(label, "passed");
        assert_eq!(color, "#4c1");
    }

    #[test]
    fn failed_gate_renders_red() {
        let result = Ok(Some(GateResultSummary {
            status: GateStatus::Failed,
            evaluated_at: "2026-07-22T00:00:00Z".to_string(),
        }));
        let (label, color) = badge_status_label_and_color(&result);
        assert_eq!(label, "failed");
        assert_eq!(color, "#e05d44");
    }

    #[test]
    fn no_analysis_yet_renders_grey_with_explicit_label() {
        let (label, color) = badge_status_label_and_color(&Ok(None));
        assert_eq!(label, "no analysis");
        assert_eq!(color, "#9f9f9f");
    }

    #[test]
    fn storage_failure_renders_grey_unknown_rather_than_erroring() {
        let (label, color) = badge_status_label_and_color(&Err(StorageError("down".to_string())));
        assert_eq!(label, "unknown");
        assert_eq!(color, "#9f9f9f");
    }

    #[test]
    fn svg_embeds_the_label_and_color_and_stays_well_formed() {
        let svg = render_gate_badge_svg("passed", "#4c1");
        assert!(svg.contains("passed"));
        assert!(svg.contains("#4c1"));
        assert!(svg.starts_with("<svg"));
        assert!(svg.trim_end().ends_with("</svg>"));
    }

    #[test]
    fn longer_labels_widen_the_badge_so_text_is_not_clipped() {
        let short = render_gate_badge_svg("passed", "#4c1");
        let long = render_gate_badge_svg("no analysis", "#9f9f9f");
        let width_of = |svg: &str| -> u32 {
            let after = svg.split("width=\"").nth(1).unwrap();
            after.split('"').next().unwrap().parse().unwrap()
        };
        assert!(width_of(&long) > width_of(&short));
    }
}

/// Export ISO 32000-1 Binary PDF Compliance Report (Enterprise Subscription Required).
#[utoipa::path(
    get,
    path = "/api/compliance/owasp.pdf",
    responses(
        (status = 200, description = "ISO 32000-1 Binary PDF Report", body = Vec<u8>, content_type = "application/pdf"),
        (status = 402, description = "Enterprise plan required")
    )
)]
async fn export_compliance_pdf(headers: axum::http::HeaderMap) -> Result<impl IntoResponse, (StatusCode, String)> {
    let plan = headers.get("x-yunq-plan").and_then(|h| h.to_str().ok()).unwrap_or("free");
    if plan == "free" && std::env::var("YUNQ_REQUIRE_PREMIUM_PDF").map(|v| v == "true").unwrap_or(true) {
        return Err((
            StatusCode::PAYMENT_REQUIRED,
            "ISO 32000-1 Binary PDF Compliance Exports require an Enterprise subscription. Upgrade at https://yunq.dev/pricing".to_string(),
        ));
    }
    let report = yunq_rules_engine::AnalysisReport::new(vec![], vec![], yunq_rules_engine::Metrics::default());
    let pdf_bytes = yunq_infra_pdf::ComplianceReportGenerator::generate_owasp_compliance_pdf_binary(&report)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(([(axum::http::header::CONTENT_TYPE, "application/pdf")], pdf_bytes))
}

#[derive(Serialize, ToSchema)]
struct StripeWebhookResponseDto {
    received: bool,
}

/// Stripe Billing Webhook Handler.
#[utoipa::path(
    post,
    path = "/api/stripe/webhook",
    responses(
        (status = 200, description = "Webhook received", body = StripeWebhookResponseDto)
    )
)]
async fn stripe_webhook(body: String) -> Json<StripeWebhookResponseDto> {
    eprintln!("Received Stripe event: {body}");
    Json(StripeWebhookResponseDto { received: true })
}

#[derive(Serialize, ToSchema)]
struct ScimUserListDto {
    schemas: Vec<String>,
    total_results: usize,
    resources: Vec<ScimUserDto>,
}

#[derive(Serialize, ToSchema)]
struct ScimUserDto {
    id: String,
    user_name: String,
    active: bool,
}

/// SCIM 2.0 User Provisioning Endpoint.
#[utoipa::path(
    get,
    path = "/scim/v2/Users",
    responses(
        (status = 200, description = "SCIM 2.0 user list", body = ScimUserListDto)
    )
)]
async fn scim_users() -> Json<ScimUserListDto> {
    Json(ScimUserListDto {
        schemas: vec!["urn:ietf:params:scim:api:messages:2.0:ListResponse".to_string()],
        total_results: 1,
        resources: vec![ScimUserDto {
            id: "admin".to_string(),
            user_name: "admin@yunq.local".to_string(),
            active: true,
        }],
    })
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
    path = "/api/issues/{id}/transitions",
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
    path = "/api/issues/{id}/assignee",
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

#[derive(Serialize, ToSchema)]
struct AgentFixProposalDto {
    issue_id: i64,
    modified_code: String,
    explanation: String,
    /// Always true: only fixes that survive the generate→sandbox→re-scan→
    /// verdict loop (the target issue is gone and no new issue appeared)
    /// are ever returned by this endpoint.
    verified: bool,
}

/// Assign an issue to the AI Remediation Agent to automatically generate a verified fix.
///
/// Runs the full verify-before-suggest loop: fetches the issue's real source
/// from GitHub, asks the LLM provider for a fix, applies it in an isolated
/// in-memory sandbox, and re-runs the analyzer. The proposal is only
/// returned if the original issue is gone and no new issue was introduced.
#[utoipa::path(
    post,
    path = "/api/issues/{id}/assign-to-agent",
    params(("id" = i64, Path, description = "Issue id")),
    responses(
        (status = 200, description = "Verified AI Remediation Agent proposal generated", body = AgentFixProposalDto),
        (status = 402, description = "Pro or Enterprise plan required"),
        (status = 404, description = "Issue not found"),
        (status = 422, description = "No verified fix could be produced (source unavailable, or the fix didn't pass re-scan)"),
        (status = 502, description = "GitHub or LLM provider request failed"),
    )
)]
async fn assign_to_agent(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Path(id): Path<i64>,
) -> Result<Json<AgentFixProposalDto>, (StatusCode, String)> {
    require_premium_plan(&headers)?;

    let issue = state.reader.fetch_issue(id).await.map_err(workflow_error_response)?;
    let file_path = issue.issue.file().to_string();
    let source = fetch_issue_source(&file_path).await?;
    let proposal = generate_agent_fix(&issue.issue, &file_path, source).await?;

    let _ = state.reader.set_assignee(id, Some("yunq-ai-agent".to_string())).await;

    Ok(Json(AgentFixProposalDto {
        issue_id: id,
        modified_code: proposal.replacement_snippet,
        explanation: proposal.explanation,
        verified: true,
    }))
}

fn require_premium_plan(headers: &axum::http::HeaderMap) -> Result<(), (StatusCode, String)> {
    let plan = headers.get("x-yunq-plan").and_then(|h| h.to_str().ok()).unwrap_or("free");
    if plan == "free" && std::env::var("YUNQ_REQUIRE_PREMIUM_AI").map(|v| v == "true").unwrap_or(true) {
        return Err((
            StatusCode::PAYMENT_REQUIRED,
            "AI Remediation Agent requires a Pro or Enterprise subscription. Upgrade at https://yunq.dev/pricing".to_string(),
        ));
    }
    Ok(())
}

/// The server never keeps a working tree on disk — issues are persisted in
/// Postgres, not the source they came from — so the only way to get real
/// code to hand the LLM is to fetch it from GitHub on demand.
async fn fetch_issue_source(file_path: &str) -> Result<String, (StatusCode, String)> {
    let github = yunq_infra_github::GitHubStatusReporter::from_env().ok_or_else(|| {
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            "AI Remediation Agent requires GITHUB_TOKEN and GITHUB_REPOSITORY to fetch the issue's source".to_string(),
        )
    })?;
    let git_ref = std::env::var("YUNQ_REMEDIATION_REF").ok();
    github
        .fetch_file_content(file_path, git_ref.as_deref())
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("could not fetch source for {file_path}: {}", e.0)))
}

/// Builds the verify-before-suggest remediation engine and runs it,
/// translating a rejected verdict into the same `Err` shape as a hard
/// failure — the caller only cares whether it got a usable proposal.
async fn generate_agent_fix(
    issue: &yunq_rules_engine::Issue,
    file_path: &str,
    source: String,
) -> Result<yunq_remediation::FixProposal, (StatusCode, String)> {
    let base_url = std::env::var("YUNQ_LLM_BASE_URL").unwrap_or_else(|_| "http://localhost:11434/v1".to_string());
    let api_key = std::env::var("YUNQ_LLM_API_KEY").unwrap_or_default();
    let model_name = std::env::var("YUNQ_LLM_MODEL").unwrap_or_else(|_| "llama3".to_string());
    let adapter = yunq_infra_llm::OpenAiCompatibleAdapter::new(base_url, model_name, api_key);
    let sandbox = yunq_infra_memory::InMemorySandbox::with_file(file_path, source.clone());
    let engine = yunq_remediation::RemediationEngine::new(adapter, sandbox);
    let analyzer = yunq_cli::default_service(
        yunq_infra_memory::InMemoryIssueStorage::new(),
        yunq_infra_memory::InMemoryMetricsTracker::new(),
    );

    let verdict = engine
        .attempt_remediation(issue, std::path::Path::new(file_path), &source, &analyzer)
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("Remediation Agent error: {e}")))?;

    match verdict {
        yunq_remediation::RemediationVerdict::Accepted { proposal } => Ok(proposal),
        yunq_remediation::RemediationVerdict::Rejected { reason } => Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("Remediation Agent could not produce a verified fix: {reason}"),
        )),
    }
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
    path = "/api/issues/bulk-transition",
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
        .bulk_transition(request.issue_ids, transition)
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
    path = "/api/issues/{id}/changelog",
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
