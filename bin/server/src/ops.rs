//! Ops (Fase 4): `GET /api/system/info` plus the write paths for quality
//! gates, quality profiles and project permissions, each audit-logged right
//! after it lands, and `GET /api/audit-log` to read the trail back.
//!
//! Deliberately minimal: gates/profiles are a flat name + condition/
//! activation list (no per-project assignment endpoint — that's Fase 3
//! territory) and permissions are a single fixed role per (project, user)
//! — no groups, no templates, no SSO. Just enough surface to have
//! something real to audit.
//!
//! Profile inheritance, compare/copy/backup-restore (issue #22) live in
//! `profiles_admin` — this module only exposes the persistence ops they
//! need (`compare_profiles`/`copy_profile`/`read_profile`/`restore_profile`
//! below) through the same `OpsStore` port as everything else.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use futures::future::BoxFuture;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::{IntoParams, ToSchema};
use yunq_infra_postgres::{
    AuditLogEntry, AuditLogQuery, CompareProfileError, CopyProfileError, LlmConfigError,
    PgIssueStorage, ProjectLlmConfig, PurgeReport, RestoreProfileError, SystemSnapshot,
};
use yunq_rules_engine::{
    ComparisonOperator, MetricKey, Page, ProfileBackup, ProfileDiff, QualityProfile, RuleId,
    Severity, StorageError,
};

use crate::auth::permissions::{is_allowed, Caller};
use crate::auth::Permission;
use crate::AppState;

/// Shared 403 body shape for every admin endpoint below.
fn forbidden(permission: Permission) -> (StatusCode, String) {
    (StatusCode::FORBIDDEN, format!("missing permission: {permission:?}"))
}

/// One gate condition as `(metric, operator, threshold)`.
type GateCondition = (String, ComparisonOperator, f64);
/// One profile activation as `(rule id, severity)`, both already stringified
/// — the shape returned by (and stored as) the `before`/`after` audit pair.
type ProfileActivation = (String, String);
/// The `(before, after)` pair a gate/profile write returns, for the audit log.
type BeforeAfter<T> = (Vec<T>, Vec<T>);

/// Object-safe HTTP-facing adapter over the Ops persistence methods on
/// `PgIssueStorage` — same "one trait per composition-root need" pattern as
/// `IssueApiStore`/`ScanQueuePort` in `main.rs`.
pub(crate) trait OpsStore: Send + Sync {
    fn upsert_gate(
        &self,
        name: String,
        conditions: Vec<GateCondition>,
    ) -> BoxFuture<'_, Result<BeforeAfter<GateCondition>, StorageError>>;

    fn upsert_profile(
        &self,
        name: String,
        activations: Vec<(RuleId, Severity)>,
    ) -> BoxFuture<'_, Result<BeforeAfter<ProfileActivation>, StorageError>>;

    fn set_permission(
        &self,
        project_key: String,
        user_login: String,
        role: Option<String>,
    ) -> BoxFuture<'_, Result<Option<String>, StorageError>>;

    fn record_audit(
        &self,
        actor_user_id: Option<String>,
        action: String,
        entity_type: String,
        entity_id: String,
        before: Option<Value>,
        after: Option<Value>,
    ) -> BoxFuture<'_, Result<(), StorageError>>;

    fn list_audit_log(
        &self,
        query: AuditLogQuery,
    ) -> BoxFuture<'_, Result<Page<AuditLogEntry>, StorageError>>;

    fn system_snapshot(&self) -> BoxFuture<'_, SystemSnapshot>;

    /// Sets (or clears, with `None`) a project's analysis-history retention
    /// override in days. Returns the prior value for the audit log.
    fn set_retention(
        &self,
        project_key: String,
        retention_days: Option<i32>,
    ) -> BoxFuture<'_, Result<Option<i32>, StorageError>>;

    /// Deletes analyses past each project's effective retention (its own
    /// override, else `default_days`).
    fn purge_expired(&self, default_days: Option<i32>) -> BoxFuture<'_, Result<PurgeReport, StorageError>>;

    /// Reads a stored profile (activations plus its resolved parent chain),
    /// for `profiles_admin`'s backup endpoint. `Ok(None)` if no profile has
    /// that name.
    fn read_profile(&self, name: String) -> BoxFuture<'_, Result<Option<QualityProfile>, StorageError>>;

    /// Compares two stored profiles' effective activations — issue #22's
    /// "Compare profiles" operation.
    fn compare_profiles(
        &self,
        name_a: String,
        name_b: String,
    ) -> BoxFuture<'_, Result<ProfileDiff, CompareProfileError>>;

    /// Duplicates a stored profile's effective activations under a new
    /// name — issue #22's "Copy profile" operation. Returns the copy's
    /// activations for the audit log.
    fn copy_profile(
        &self,
        source_name: String,
        new_name: String,
    ) -> BoxFuture<'_, Result<Vec<ProfileActivation>, CopyProfileError>>;

    /// Restores a profile from a backup — issue #22's "Restore profile"
    /// operation. See `PgIssueStorage::restore_quality_profile` for the
    /// name-collision policy `force` controls.
    fn restore_profile(
        &self,
        backup: ProfileBackup,
        force: bool,
    ) -> BoxFuture<'_, Result<Vec<ProfileActivation>, RestoreProfileError>>;

    /// Upserts a project's BYOK LLM provider override (see
    /// `ai_provider_admin`). Encrypts the API key before it reaches Postgres.
    fn set_llm_config(
        &self,
        project_key: String,
        provider: String,
        base_url: Option<String>,
        model: String,
        api_key: String,
    ) -> BoxFuture<'_, Result<(), LlmConfigError>>;

    /// Reads a project's BYOK config, decrypted. `Ok(None)` means the
    /// project uses the platform-wide default provider.
    fn llm_config(
        &self,
        project_key: String,
    ) -> BoxFuture<'_, Result<Option<ProjectLlmConfig>, LlmConfigError>>;

    /// Clears a project's BYOK override. Returns whether a row existed.
    fn clear_llm_config(&self, project_key: String) -> BoxFuture<'_, Result<bool, LlmConfigError>>;

    /// Resolves the project key that owns an issue, so the Remediation
    /// Agent can route to that project's BYOK config.
    fn project_key_for_issue(&self, issue_id: i64) -> BoxFuture<'_, Result<Option<String>, StorageError>>;
}

impl OpsStore for PgIssueStorage {
    fn upsert_gate(
        &self,
        name: String,
        conditions: Vec<GateCondition>,
    ) -> BoxFuture<'_, Result<BeforeAfter<GateCondition>, StorageError>> {
        Box::pin(async move { PgIssueStorage::upsert_quality_gate(self, &name, &conditions).await })
    }

    fn upsert_profile(
        &self,
        name: String,
        activations: Vec<(RuleId, Severity)>,
    ) -> BoxFuture<'_, Result<BeforeAfter<ProfileActivation>, StorageError>> {
        Box::pin(async move {
            PgIssueStorage::upsert_quality_profile(self, &name, &activations).await
        })
    }

    fn set_permission(
        &self,
        project_key: String,
        user_login: String,
        role: Option<String>,
    ) -> BoxFuture<'_, Result<Option<String>, StorageError>> {
        Box::pin(async move {
            PgIssueStorage::set_project_permission(self, &project_key, &user_login, role.as_deref())
                .await
        })
    }

    fn record_audit(
        &self,
        actor_user_id: Option<String>,
        action: String,
        entity_type: String,
        entity_id: String,
        before: Option<Value>,
        after: Option<Value>,
    ) -> BoxFuture<'_, Result<(), StorageError>> {
        Box::pin(async move {
            PgIssueStorage::record_audit(
                self,
                actor_user_id.as_deref(),
                &action,
                &entity_type,
                &entity_id,
                before,
                after,
            )
            .await
        })
    }

    fn list_audit_log(
        &self,
        query: AuditLogQuery,
    ) -> BoxFuture<'_, Result<Page<AuditLogEntry>, StorageError>> {
        Box::pin(async move { PgIssueStorage::list_audit_log(self, &query).await })
    }

    fn system_snapshot(&self) -> BoxFuture<'_, SystemSnapshot> {
        Box::pin(PgIssueStorage::system_snapshot(self))
    }

    fn set_retention(
        &self,
        project_key: String,
        retention_days: Option<i32>,
    ) -> BoxFuture<'_, Result<Option<i32>, StorageError>> {
        Box::pin(async move {
            PgIssueStorage::set_project_retention_days(self, &project_key, retention_days).await
        })
    }

    fn purge_expired(&self, default_days: Option<i32>) -> BoxFuture<'_, Result<PurgeReport, StorageError>> {
        Box::pin(async move { PgIssueStorage::purge_expired(self, default_days).await })
    }

    fn read_profile(&self, name: String) -> BoxFuture<'_, Result<Option<QualityProfile>, StorageError>> {
        Box::pin(async move { PgIssueStorage::read_quality_profile(self, &name).await })
    }

    fn compare_profiles(
        &self,
        name_a: String,
        name_b: String,
    ) -> BoxFuture<'_, Result<ProfileDiff, CompareProfileError>> {
        Box::pin(async move { PgIssueStorage::compare_quality_profiles(self, &name_a, &name_b).await })
    }

    fn copy_profile(
        &self,
        source_name: String,
        new_name: String,
    ) -> BoxFuture<'_, Result<Vec<ProfileActivation>, CopyProfileError>> {
        Box::pin(async move { PgIssueStorage::copy_quality_profile(self, &source_name, &new_name).await })
    }

    fn restore_profile(
        &self,
        backup: ProfileBackup,
        force: bool,
    ) -> BoxFuture<'_, Result<Vec<ProfileActivation>, RestoreProfileError>> {
        Box::pin(async move { PgIssueStorage::restore_quality_profile(self, &backup, force).await })
    }

    fn set_llm_config(
        &self,
        project_key: String,
        provider: String,
        base_url: Option<String>,
        model: String,
        api_key: String,
    ) -> BoxFuture<'_, Result<(), LlmConfigError>> {
        Box::pin(async move {
            PgIssueStorage::set_project_llm_config(
                self,
                &project_key,
                &provider,
                base_url.as_deref(),
                &model,
                &api_key,
            )
            .await
        })
    }

    fn llm_config(
        &self,
        project_key: String,
    ) -> BoxFuture<'_, Result<Option<ProjectLlmConfig>, LlmConfigError>> {
        Box::pin(async move { PgIssueStorage::get_project_llm_config(self, &project_key).await })
    }

    fn clear_llm_config(&self, project_key: String) -> BoxFuture<'_, Result<bool, LlmConfigError>> {
        Box::pin(async move { PgIssueStorage::delete_project_llm_config(self, &project_key).await })
    }

    fn project_key_for_issue(&self, issue_id: i64) -> BoxFuture<'_, Result<Option<String>, StorageError>> {
        Box::pin(async move { PgIssueStorage::project_key_for_issue(self, issue_id).await })
    }
}

/// The audit log actor: the bearer session's username. Every write handler
/// in this file now requires a `Caller` (see the `is_allowed` checks below),
/// so this only returns `None` in the narrow window where `auth.authenticate`
/// and `Caller`'s own PAT fallback disagree (e.g. a role check passed via
/// PAT scopes but the OAuth session lookup used here doesn't recognize the
/// token) rather than because the request was anonymous.
fn actor_from_headers(state: &AppState, headers: &HeaderMap) -> Option<String> {
    state.auth.authenticate(headers).ok().map(|user| user.username().to_string())
}

#[derive(Serialize, ToSchema)]
pub(crate) struct DatabaseInfoDto {
    connected: bool,
    postgres_version: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct SystemInfoDto {
    /// Cargo package version (`CARGO_PKG_VERSION`).
    version: &'static str,
    /// `YUNQ_GIT_SHA` if the deploy set it, else "unknown".
    git_sha: String,
    uptime_seconds: f64,
    database: DatabaseInfoDto,
    issues_total: i64,
    hotspots_total: i64,
    /// Scan jobs still waiting for a worker to claim them.
    pending_scan_jobs: i64,
}

/// Operational snapshot: build version, uptime, DB reachability and a few
/// cheap counters — everything already available from server state or one
/// indexed count query each, nothing that scans a table.
#[utoipa::path(
    get,
    path = "/api/system/info",
    responses(
        (status = 200, description = "System info snapshot", body = SystemInfoDto),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller lacks AdminAccess"),
    )
)]
pub(crate) async fn system_info(
    State(state): State<Arc<AppState>>,
    Caller(caller): Caller,
) -> Result<Json<SystemInfoDto>, (StatusCode, String)> {
    if !is_allowed(&caller, Permission::AdminAccess) {
        return Err(forbidden(Permission::AdminAccess));
    }
    let snapshot = state.ops.system_snapshot().await;
    Ok(Json(SystemInfoDto {
        version: env!("CARGO_PKG_VERSION"),
        git_sha: std::env::var("YUNQ_GIT_SHA").unwrap_or_else(|_| "unknown".to_string()),
        uptime_seconds: state.metrics.uptime_seconds(),
        database: DatabaseInfoDto {
            connected: snapshot.database_connected,
            postgres_version: snapshot.postgres_version,
        },
        issues_total: snapshot.issues_total,
        hotspots_total: snapshot.hotspots_total,
        pending_scan_jobs: snapshot.pending_scan_jobs,
    }))
}

#[derive(Deserialize, Serialize, ToSchema, Clone)]
pub(crate) struct GateConditionDto {
    /// Lowercase snake_case metric key, e.g. blocker_issues.
    metric: String,
    /// One of: gt, lt.
    operator: String,
    threshold: f64,
}

#[derive(Deserialize, ToSchema)]
pub(crate) struct GateUpsertRequestDto {
    conditions: Vec<GateConditionDto>,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct GateDto {
    name: String,
    conditions: Vec<GateConditionDto>,
}

fn parse_operator(raw: &str) -> Result<ComparisonOperator, String> {
    match raw {
        "gt" => Ok(ComparisonOperator::GreaterThan),
        "lt" => Ok(ComparisonOperator::LessThan),
        other => Err(format!("invalid operator {other:?} (gt|lt)")),
    }
}

fn operator_label(operator: ComparisonOperator) -> &'static str {
    match operator {
        ComparisonOperator::GreaterThan => "gt",
        ComparisonOperator::LessThan => "lt",
    }
}

/// Validates every condition (metric key format, operator) before anything
/// is persisted — pure, so it's unit-testable without a database.
fn validate_and_convert_conditions(
    conditions: &[GateConditionDto],
) -> Result<Vec<GateCondition>, String> {
    conditions
        .iter()
        .map(|c| {
            MetricKey::new(&c.metric).map_err(|e| e.to_string())?;
            let operator = parse_operator(&c.operator)?;
            Ok((c.metric.clone(), operator, c.threshold))
        })
        .collect()
}

fn conditions_to_dto(conditions: &[GateCondition]) -> Vec<GateConditionDto> {
    conditions
        .iter()
        .map(|(metric, operator, threshold)| GateConditionDto {
            metric: metric.clone(),
            operator: operator_label(*operator).to_string(),
            threshold: *threshold,
        })
        .collect()
}

/// Create or update a named quality gate's condition set; audit-logged as
/// `gate.updated`.
#[utoipa::path(
    put,
    path = "/api/quality-gates/{name}",
    params(("name" = String, Path, description = "Gate name")),
    request_body = GateUpsertRequestDto,
    responses(
        (status = 200, description = "Gate after the update", body = GateDto),
        (status = 400, description = "Invalid metric key or operator"),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller lacks ManageQualityGates"),
        (status = 502, description = "Storage backend unavailable"),
    )
)]
pub(crate) async fn upsert_quality_gate(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
    headers: HeaderMap,
    Caller(caller): Caller,
    Json(request): Json<GateUpsertRequestDto>,
) -> Result<Json<GateDto>, (StatusCode, String)> {
    if !is_allowed(&caller, Permission::ManageQualityGates) {
        return Err(forbidden(Permission::ManageQualityGates));
    }
    let conditions =
        validate_and_convert_conditions(&request.conditions).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let actor = actor_from_headers(&state, &headers);

    let (before, after) = state
        .ops
        .upsert_gate(name.clone(), conditions)
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;

    state
        .ops
        .record_audit(
            actor,
            "gate.updated".to_string(),
            "quality_gate".to_string(),
            name.clone(),
            Some(serde_json::to_value(conditions_to_dto(&before)).unwrap_or(Value::Null)),
            Some(serde_json::to_value(conditions_to_dto(&after)).unwrap_or(Value::Null)),
        )
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;

    Ok(Json(GateDto { name, conditions: conditions_to_dto(&after) }))
}

#[derive(Deserialize, Serialize, ToSchema, Clone)]
pub(crate) struct ProfileActivationDto {
    /// e.g. owasp:eval-usage.
    rule: String,
    /// One of: info, minor, major, critical, blocker.
    severity: String,
}

#[derive(Deserialize, ToSchema)]
pub(crate) struct ProfileUpsertRequestDto {
    activations: Vec<ProfileActivationDto>,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct ProfileDto {
    name: String,
    activations: Vec<ProfileActivationDto>,
}

/// Validates every activation (rule id format, severity) before anything is
/// persisted — pure, so it's unit-testable without a database.
fn validate_and_convert_activations(
    activations: &[ProfileActivationDto],
) -> Result<Vec<(RuleId, Severity)>, String> {
    activations
        .iter()
        .map(|a| {
            let rule = RuleId::new(&a.rule).map_err(|e| e.to_string())?;
            let severity = Severity::parse(&a.severity)
                .ok_or_else(|| format!("invalid severity {:?} (info|minor|major|critical|blocker)", a.severity))?;
            Ok((rule, severity))
        })
        .collect()
}

fn activations_to_dto(activations: &[ProfileActivation]) -> Vec<ProfileActivationDto> {
    activations
        .iter()
        .map(|(rule, severity)| ProfileActivationDto { rule: rule.clone(), severity: severity.clone() })
        .collect()
}

/// Create or update a named quality profile's rule activations;
/// audit-logged as `profile.updated`.
#[utoipa::path(
    put,
    path = "/api/quality-profiles/{name}",
    params(("name" = String, Path, description = "Profile name")),
    request_body = ProfileUpsertRequestDto,
    responses(
        (status = 200, description = "Profile after the update", body = ProfileDto),
        (status = 400, description = "Invalid rule id or severity"),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller lacks ManageProfiles"),
        (status = 502, description = "Storage backend unavailable"),
    )
)]
pub(crate) async fn upsert_quality_profile(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
    headers: HeaderMap,
    Caller(caller): Caller,
    Json(request): Json<ProfileUpsertRequestDto>,
) -> Result<Json<ProfileDto>, (StatusCode, String)> {
    if !is_allowed(&caller, Permission::ManageProfiles) {
        return Err(forbidden(Permission::ManageProfiles));
    }
    let activations = validate_and_convert_activations(&request.activations)
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let actor = actor_from_headers(&state, &headers);

    let (before, after) = state
        .ops
        .upsert_profile(name.clone(), activations)
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;

    state
        .ops
        .record_audit(
            actor,
            "profile.updated".to_string(),
            "quality_profile".to_string(),
            name.clone(),
            Some(serde_json::to_value(activations_to_dto(&before)).unwrap_or(Value::Null)),
            Some(serde_json::to_value(activations_to_dto(&after)).unwrap_or(Value::Null)),
        )
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;

    Ok(Json(ProfileDto { name, activations: activations_to_dto(&after) }))
}

const VALID_ROLES: [&str; 3] = ["admin", "editor", "viewer"];

fn validate_role(role: &str) -> Result<(), String> {
    if VALID_ROLES.contains(&role) {
        Ok(())
    } else {
        Err(format!("invalid role {role:?} (expected one of: {})", VALID_ROLES.join(", ")))
    }
}

#[derive(Deserialize, ToSchema)]
pub(crate) struct PermissionGrantRequestDto {
    /// One of: admin, editor, viewer.
    role: String,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct PermissionDto {
    project_key: String,
    user_login: String,
    role: Option<String>,
}

/// Grant (or change) a user's fixed role on a project; audit-logged as
/// `permission.granted`. No groups, no templates, no SSO — a single role
/// per (project, user).
#[utoipa::path(
    put,
    path = "/api/projects/{key}/permissions/{user}",
    params(
        ("key" = String, Path, description = "Project key"),
        ("user" = String, Path, description = "User login"),
    ),
    request_body = PermissionGrantRequestDto,
    responses(
        (status = 200, description = "Permission after the grant", body = PermissionDto),
        (status = 400, description = "Invalid role"),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller lacks AdminAccess"),
        (status = 502, description = "Storage backend unavailable"),
    )
)]
pub(crate) async fn grant_permission(
    State(state): State<Arc<AppState>>,
    Path((key, user)): Path<(String, String)>,
    headers: HeaderMap,
    Caller(caller): Caller,
    Json(request): Json<PermissionGrantRequestDto>,
) -> Result<Json<PermissionDto>, (StatusCode, String)> {
    if !is_allowed(&caller, Permission::AdminAccess) {
        return Err(forbidden(Permission::AdminAccess));
    }
    validate_role(&request.role).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let actor = actor_from_headers(&state, &headers);

    let before = state
        .ops
        .set_permission(key.clone(), user.clone(), Some(request.role.clone()))
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;

    let entity_id = format!("{key}:{user}");
    state
        .ops
        .record_audit(
            actor,
            "permission.granted".to_string(),
            "project_permission".to_string(),
            entity_id,
            before.map(|role| serde_json::json!({ "role": role })),
            Some(serde_json::json!({ "role": request.role })),
        )
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;

    Ok(Json(PermissionDto { project_key: key, user_login: user, role: Some(request.role) }))
}

/// Revoke a user's role on a project; audit-logged as `permission.revoked`.
#[utoipa::path(
    delete,
    path = "/api/projects/{key}/permissions/{user}",
    params(
        ("key" = String, Path, description = "Project key"),
        ("user" = String, Path, description = "User login"),
    ),
    responses(
        (status = 200, description = "Permission after the revoke", body = PermissionDto),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller lacks AdminAccess"),
        (status = 502, description = "Storage backend unavailable"),
    )
)]
pub(crate) async fn revoke_permission(
    State(state): State<Arc<AppState>>,
    Path((key, user)): Path<(String, String)>,
    headers: HeaderMap,
    Caller(caller): Caller,
) -> Result<Json<PermissionDto>, (StatusCode, String)> {
    if !is_allowed(&caller, Permission::AdminAccess) {
        return Err(forbidden(Permission::AdminAccess));
    }
    let actor = actor_from_headers(&state, &headers);

    let before = state
        .ops
        .set_permission(key.clone(), user.clone(), None)
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;

    let entity_id = format!("{key}:{user}");
    state
        .ops
        .record_audit(
            actor,
            "permission.revoked".to_string(),
            "project_permission".to_string(),
            entity_id,
            before.map(|role| serde_json::json!({ "role": role })),
            None,
        )
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;

    Ok(Json(PermissionDto { project_key: key, user_login: user, role: None }))
}

#[derive(Deserialize, ToSchema)]
pub(crate) struct RetentionUpdateRequestDto {
    /// Days to keep this project's analysis history for, or `null` to fall
    /// back to the instance-wide default (`YUNQ_DEFAULT_RETENTION_DAYS`, if
    /// set — otherwise history is kept forever).
    retention_days: Option<i32>,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct RetentionDto {
    project_key: String,
    retention_days: Option<i32>,
}

/// Sets (or clears) a project's analysis-history retention override, in
/// days; audit-logged as `project.retention_updated`.
#[utoipa::path(
    put,
    path = "/api/projects/{key}/retention",
    params(("key" = String, Path, description = "Project key")),
    request_body = RetentionUpdateRequestDto,
    responses(
        (status = 200, description = "Retention override after the update", body = RetentionDto),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller lacks AdminAccess"),
        (status = 502, description = "Storage backend unavailable"),
    )
)]
pub(crate) async fn set_project_retention(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
    Caller(caller): Caller,
    Json(request): Json<RetentionUpdateRequestDto>,
) -> Result<Json<RetentionDto>, (StatusCode, String)> {
    if !is_allowed(&caller, Permission::AdminAccess) {
        return Err(forbidden(Permission::AdminAccess));
    }
    let actor = actor_from_headers(&state, &headers);

    let before = state
        .ops
        .set_retention(key.clone(), request.retention_days)
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;

    state
        .ops
        .record_audit(
            actor,
            "project.retention_updated".to_string(),
            "project".to_string(),
            key.clone(),
            Some(serde_json::json!({ "retention_days": before })),
            Some(serde_json::json!({ "retention_days": request.retention_days })),
        )
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;

    Ok(Json(RetentionDto { project_key: key, retention_days: request.retention_days }))
}

#[derive(Serialize, ToSchema)]
pub(crate) struct PurgeReportDto {
    analyses_deleted: i64,
    issues_deleted: i64,
    hotspots_deleted: i64,
}

/// Runs housekeeping immediately: deletes analyses, issues and hotspots
/// past each project's effective retention (its own override, else the
/// instance-wide `YUNQ_DEFAULT_RETENTION_DAYS` default, if set). Issues/
/// hotspots saved before a project/analysis could be resolved (or saved
/// before `0016_issue_hotspot_scoping.sql` existed) carry no `project_id`
/// and are never matched by this purge, no matter their age. The worker
/// also runs this on a timer (`YUNQ_HOUSEKEEPING_INTERVAL_HOURS`); this
/// endpoint is for an on-demand run or an external scheduler. Audit-logged
/// as `housekeeping.purged`.
#[utoipa::path(
    post,
    path = "/api/housekeeping/purge",
    responses(
        (status = 200, description = "Rows removed by this run", body = PurgeReportDto),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller lacks AdminAccess"),
        (status = 502, description = "Storage backend unavailable"),
    )
)]
pub(crate) async fn run_housekeeping(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Caller(caller): Caller,
) -> Result<Json<PurgeReportDto>, (StatusCode, String)> {
    if !is_allowed(&caller, Permission::AdminAccess) {
        return Err(forbidden(Permission::AdminAccess));
    }
    let actor = actor_from_headers(&state, &headers);

    let report = state
        .ops
        .purge_expired(state.default_retention_days)
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;

    state
        .ops
        .record_audit(
            actor,
            "housekeeping.purged".to_string(),
            "housekeeping".to_string(),
            "retention".to_string(),
            None,
            Some(serde_json::json!({
                "analyses_deleted": report.analyses_deleted,
                "issues_deleted": report.issues_deleted,
                "hotspots_deleted": report.hotspots_deleted,
            })),
        )
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;

    Ok(Json(PurgeReportDto {
        analyses_deleted: report.analyses_deleted as i64,
        issues_deleted: report.issues_deleted as i64,
        hotspots_deleted: report.hotspots_deleted as i64,
    }))
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct AuditLogQueryDto {
    /// Filter: exact entity_type (quality_gate|quality_profile|project_permission).
    entity_type: Option<String>,
    /// Inclusive lower bound, RFC3339.
    from: Option<String>,
    /// Inclusive upper bound, RFC3339.
    to: Option<String>,
    /// 1-based page number (default 1).
    #[serde(default)]
    page: usize,
    /// Page size (default 50, capped at 500).
    #[serde(default)]
    page_size: usize,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct AuditLogEntryDto {
    id: i64,
    actor_user_id: Option<String>,
    action: String,
    entity_type: String,
    entity_id: String,
    before: Option<Value>,
    after: Option<Value>,
    at: String,
}

impl From<&AuditLogEntry> for AuditLogEntryDto {
    fn from(entry: &AuditLogEntry) -> Self {
        Self {
            id: entry.id,
            actor_user_id: entry.actor_user_id.clone(),
            action: entry.action.clone(),
            entity_type: entry.entity_type.clone(),
            entity_id: entry.entity_id.clone(),
            before: entry.before.clone(),
            after: entry.after.clone(),
            at: entry.created_at.clone(),
        }
    }
}

#[derive(Serialize, ToSchema)]
pub(crate) struct AuditLogPageDto {
    items: Vec<AuditLogEntryDto>,
    page: usize,
    page_size: usize,
    total: usize,
}

/// Read the audit trail of gate/profile/permission changes, newest first.
#[utoipa::path(
    get,
    path = "/api/audit-log",
    params(AuditLogQueryDto),
    responses(
        (status = 200, description = "One page of audit log entries", body = AuditLogPageDto),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller lacks AdminAccess"),
        (status = 502, description = "Storage backend unavailable"),
    )
)]
pub(crate) async fn list_audit_log(
    State(state): State<Arc<AppState>>,
    Query(query): Query<AuditLogQueryDto>,
    Caller(caller): Caller,
) -> Result<Json<AuditLogPageDto>, (StatusCode, String)> {
    if !is_allowed(&caller, Permission::AdminAccess) {
        return Err(forbidden(Permission::AdminAccess));
    }
    let domain_query = AuditLogQuery {
        entity_type: query.entity_type,
        from: query.from,
        to: query.to,
        page: query.page,
        page_size: query.page_size,
    };
    let page = state
        .ops
        .list_audit_log(domain_query)
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;
    Ok(Json(AuditLogPageDto {
        items: page.items.iter().map(AuditLogEntryDto::from).collect(),
        page: page.page,
        page_size: page.page_size,
        total: page.total,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_gate_conditions_roundtrip_through_dto_and_domain() {
        let dto = vec![
            GateConditionDto {
                metric: "blocker_issues".to_string(),
                operator: "gt".to_string(),
                threshold: 0.0,
            },
            GateConditionDto { metric: "coverage".to_string(), operator: "lt".to_string(), threshold: 80.0 },
        ];
        let domain = validate_and_convert_conditions(&dto).expect("valid conditions");
        assert_eq!(domain.len(), 2);
        assert_eq!(domain[0].1, ComparisonOperator::GreaterThan);
        assert_eq!(domain[1].1, ComparisonOperator::LessThan);

        let back = conditions_to_dto(&domain);
        assert_eq!(back[0].metric, "blocker_issues");
        assert_eq!(back[0].operator, "gt");
        assert_eq!(back[1].threshold, 80.0);
    }

    #[test]
    fn invalid_metric_key_is_rejected() {
        let dto = vec![GateConditionDto {
            metric: "Blocker Issues".to_string(),
            operator: "gt".to_string(),
            threshold: 0.0,
        }];
        assert!(validate_and_convert_conditions(&dto).is_err());
    }

    #[test]
    fn invalid_operator_is_rejected() {
        let dto = vec![GateConditionDto {
            metric: "blocker_issues".to_string(),
            operator: "equals".to_string(),
            threshold: 0.0,
        }];
        assert!(validate_and_convert_conditions(&dto).is_err());
    }

    #[test]
    fn valid_profile_activations_are_accepted() {
        let dto =
            vec![ProfileActivationDto { rule: "owasp:eval-usage".to_string(), severity: "critical".to_string() }];
        let domain = validate_and_convert_activations(&dto).expect("valid activations");
        assert_eq!(domain.len(), 1);
        assert_eq!(domain[0].1, Severity::Critical);
    }

    #[test]
    fn invalid_severity_is_rejected() {
        let dto = vec![ProfileActivationDto { rule: "owasp:eval-usage".to_string(), severity: "urgent".to_string() }];
        assert!(validate_and_convert_activations(&dto).is_err());
    }

    #[test]
    fn invalid_rule_id_is_rejected() {
        let dto = vec![ProfileActivationDto { rule: "".to_string(), severity: "major".to_string() }];
        assert!(validate_and_convert_activations(&dto).is_err());
    }

    #[test]
    fn role_validation_accepts_only_the_fixed_set() {
        assert!(validate_role("admin").is_ok());
        assert!(validate_role("editor").is_ok());
        assert!(validate_role("viewer").is_ok());
        assert!(validate_role("superadmin").is_err());
    }

    #[test]
    fn audit_log_entry_dto_carries_before_and_after_through() {
        let entry = AuditLogEntry {
            id: 1,
            actor_user_id: Some("alice".to_string()),
            action: "gate.updated".to_string(),
            entity_type: "quality_gate".to_string(),
            entity_id: "yunq-default".to_string(),
            before: Some(serde_json::json!([])),
            after: Some(serde_json::json!([{"metric": "coverage"}])),
            created_at: "2026-07-22T00:00:00Z".to_string(),
        };
        let dto = AuditLogEntryDto::from(&entry);
        assert_eq!(dto.actor_user_id.as_deref(), Some("alice"));
        assert_eq!(dto.action, "gate.updated");
        assert_eq!(dto.entity_id, "yunq-default");
        assert!(dto.before.is_some());
        assert!(dto.after.is_some());
    }
}
