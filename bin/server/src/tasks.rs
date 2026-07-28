//! Background-task queue status API + failure diagnostics (Fase 4, issue
//! #30): `GET /api/admin/queue/status` exposes the real `scan_jobs` queue
//! depth by status, the oldest still-pending job's age, and the jobs that
//! have actually failed (dead-lettered or still eligible for retry) —
//! backed by `PgAuditStore::queue_status` (`infra/postgres/src/queue.rs`,
//! which is also where the dead-letter/attempt-tracking logic that makes
//! this data meaningful lives). Requires `AdminAccess`: the failure list
//! includes internal error text, same sensitivity level as the audit log.
//!
//! Superseded the earlier in-memory `TaskTracker` skeleton and the fully
//! hardcoded `diagnostics`/`diagnostics_wire` modules (worker heartbeats
//! and query telemetry that don't exist anywhere in this codebase) — this
//! is scoped to data the worker/queue actually produce, not fabricated.

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use futures::future::BoxFuture;
use serde::Serialize;
use utoipa::ToSchema;
use yunq_infra_postgres::{FailedJob, PgAuditStore, QueueStatus};
use yunq_rules_engine::QueueError;

use crate::auth::permissions::{is_allowed, Caller};
use crate::auth::Permission;
use crate::AppState;

/// Object-safe HTTP-facing adapter over `PgAuditStore::queue_status` —
/// same "one trait per composition-root need" pattern as `OpsStore`/
/// `ScanQueuePort` in `main.rs`.
pub(crate) trait QueueDiagnosticsPort: Send + Sync {
    fn queue_status(&self) -> BoxFuture<'_, Result<QueueStatus, QueueError>>;
}

impl QueueDiagnosticsPort for PgAuditStore {
    fn queue_status(&self) -> BoxFuture<'_, Result<QueueStatus, QueueError>> {
        Box::pin(PgAuditStore::queue_status(self))
    }
}

#[derive(Serialize, ToSchema)]
pub(crate) struct FailedJobDto {
    id: i64,
    project: String,
    path: String,
    /// `pending` (still eligible for retry) or `dead` (retry budget exhausted).
    status: String,
    attempts: i32,
    last_error: Option<String>,
    updated_at: String,
}

impl From<&FailedJob> for FailedJobDto {
    fn from(job: &FailedJob) -> Self {
        Self {
            id: job.id,
            project: job.project.clone(),
            path: job.path.clone(),
            status: job.status.clone(),
            attempts: job.attempts,
            last_error: job.last_error.clone(),
            updated_at: job.updated_at.clone(),
        }
    }
}

#[derive(Serialize, ToSchema)]
pub(crate) struct QueueStatusDto {
    pending: i64,
    processing: i64,
    dead: i64,
    oldest_pending_age_seconds: Option<i64>,
    recent_failures: Vec<FailedJobDto>,
}

impl From<QueueStatus> for QueueStatusDto {
    fn from(status: QueueStatus) -> Self {
        Self {
            pending: status.pending,
            processing: status.processing,
            dead: status.dead,
            oldest_pending_age_seconds: status.oldest_pending_age_seconds,
            recent_failures: status.recent_failures.iter().map(FailedJobDto::from).collect(),
        }
    }
}

/// Task queue depth by status plus recent failures, for the ops dashboard
/// and for diagnosing a stuck or perpetually-failing scan.
#[utoipa::path(
    get,
    path = "/api/admin/queue/status",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Queue depth by status and recent failures", body = QueueStatusDto),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller lacks AdminAccess"),
        (status = 502, description = "Storage backend unavailable"),
    )
)]
pub(crate) async fn queue_status(
    State(state): State<Arc<AppState>>,
    Caller(caller): Caller,
) -> Result<Json<QueueStatusDto>, (StatusCode, String)> {
    if !is_allowed(&caller, Permission::AdminAccess) {
        return Err((StatusCode::FORBIDDEN, format!("missing permission: {:?}", Permission::AdminAccess)));
    }
    let status = state
        .queue_diagnostics
        .queue_status()
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;
    Ok(Json(QueueStatusDto::from(status)))
}
