//! Per-project activity log (Fase 4, issue #30): `GET
//! /api/projects/{key}/activity` reads back what the worker did for a
//! project's background scan jobs (started/succeeded/failed), written by
//! `bin/worker`'s `PgAuditStore::record_activity`. Same "no permission
//! check, project key is the only scope" convention as the other
//! project-scoped read endpoints (`measures`, `sources`, `coverage`).

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use futures::future::BoxFuture;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::{IntoParams, ToSchema};
use yunq_infra_postgres::{ActivityLogEntry, ActivityLogQuery, PgAuditStore};
use yunq_rules_engine::{Page, StorageError};

use crate::AppState;

/// Object-safe HTTP-facing adapter over `PgAuditStore::list_activity` —
/// same "one trait per composition-root need" pattern as `OpsStore`/
/// `ScanQueuePort` in `main.rs`.
pub(crate) trait ActivityPort: Send + Sync {
    fn list_activity(
        &self,
        project_key: String,
        query: ActivityLogQuery,
    ) -> BoxFuture<'_, Result<Page<ActivityLogEntry>, StorageError>>;
}

impl ActivityPort for PgAuditStore {
    fn list_activity(
        &self,
        project_key: String,
        query: ActivityLogQuery,
    ) -> BoxFuture<'_, Result<Page<ActivityLogEntry>, StorageError>> {
        Box::pin(async move { PgAuditStore::list_activity(self, &project_key, &query).await })
    }
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct ActivityLogQueryDto {
    /// Filter to one event type, e.g. `scan.failed`.
    event_type: Option<String>,
    #[serde(default)]
    page: usize,
    #[serde(default)]
    page_size: usize,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct ActivityLogEntryDto {
    id: i64,
    event_type: String,
    message: String,
    metadata: Option<Value>,
    at: String,
}

impl From<&ActivityLogEntry> for ActivityLogEntryDto {
    fn from(entry: &ActivityLogEntry) -> Self {
        Self {
            id: entry.id,
            event_type: entry.event_type.clone(),
            message: entry.message.clone(),
            metadata: entry.metadata.clone(),
            at: entry.created_at.clone(),
        }
    }
}

#[derive(Serialize, ToSchema)]
pub(crate) struct ActivityLogPageDto {
    items: Vec<ActivityLogEntryDto>,
    page: usize,
    page_size: usize,
    total: usize,
}

/// Read one project's activity log (scan started/succeeded/failed, newest
/// first). An unknown project key reads as an empty page, not a 404 — same
/// convention `list_activity` documents at the storage layer.
#[utoipa::path(
    get,
    path = "/api/projects/{key}/activity",
    params(("key" = String, Path, description = "Project key"), ActivityLogQueryDto),
    responses(
        (status = 200, description = "One page of activity log entries, newest first", body = ActivityLogPageDto),
        (status = 502, description = "Storage backend unavailable"),
    )
)]
pub(crate) async fn project_activity(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    Query(query): Query<ActivityLogQueryDto>,
) -> Result<Json<ActivityLogPageDto>, (StatusCode, String)> {
    let domain_query = ActivityLogQuery {
        event_type: query.event_type,
        page: query.page,
        page_size: query.page_size,
    };
    let page = state
        .activity
        .list_activity(key, domain_query)
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;
    Ok(Json(ActivityLogPageDto {
        items: page.items.iter().map(ActivityLogEntryDto::from).collect(),
        page: page.page,
        page_size: page.page_size,
        total: page.total,
    }))
}
