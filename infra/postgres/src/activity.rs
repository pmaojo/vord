//! Outbound adapter: per-project activity log (Fase 4, issue #30) — a
//! durable record of what a project's background tasks did (scan started/
//! succeeded/failed today; more event types can reuse the same table since
//! `metadata` is JSONB). Written by `bin/worker` around each scan job; read
//! back by `GET /api/projects/{key}/activity`.
//!
//! Distinct from `audit_log` (`audit.rs`): that table is instance-wide admin
//! actions (who changed a gate/profile/permission); this one is per-project
//! system activity, scoped and queried by project key.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::postgres::{PgRow, Postgres};
use sqlx::{QueryBuilder, Row};
use yunq_rules_engine::{Page, StorageError};

use crate::PgIssueStorage;

fn storage_err(e: impl std::fmt::Display) -> StorageError {
    StorageError(e.to_string())
}

/// One persisted activity log entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActivityLogEntry {
    pub id: i64,
    pub event_type: String,
    pub message: String,
    pub metadata: Option<Value>,
    /// RFC3339 timestamp.
    pub created_at: String,
}

/// Filters plus pagination for `GET /api/projects/{key}/activity`;
/// normalization mirrors `AuditLogQuery`'s (1-based page, page size
/// default 50 capped at 500).
#[derive(Clone, Debug, Default)]
pub struct ActivityLogQuery {
    pub event_type: Option<String>,
    pub page: usize,
    pub page_size: usize,
}

impl ActivityLogQuery {
    pub fn normalized_page(&self) -> usize {
        self.page.max(1)
    }

    pub fn normalized_page_size(&self) -> usize {
        if self.page_size == 0 {
            50
        } else {
            self.page_size.clamp(1, 500)
        }
    }

    pub fn offset(&self) -> usize {
        (self.normalized_page() - 1) * self.normalized_page_size()
    }
}

fn activity_entry_from_row(row: &PgRow) -> Result<ActivityLogEntry, StorageError> {
    Ok(ActivityLogEntry {
        id: row.try_get("id").map_err(storage_err)?,
        event_type: row.try_get("event_type").map_err(storage_err)?,
        message: row.try_get("message").map_err(storage_err)?,
        metadata: row.try_get("metadata").map_err(storage_err)?,
        created_at: row.try_get("created_at").map_err(storage_err)?,
    })
}

impl PgIssueStorage {
    /// Appends one activity log entry, resolving (and creating, if unseen)
    /// the project by key — same "first sight creates the row" convention
    /// as `ensure_project`'s other callers (retention, permissions). Best-
    /// effort from the caller's point of view: failures are logged, never
    /// allowed to fail the scan job they describe (see `bin/worker`).
    pub async fn record_activity(
        &self,
        project_key: &str,
        event_type: &str,
        message: &str,
        metadata: Option<Value>,
    ) -> Result<(), StorageError> {
        let project_id = self.ensure_project(project_key).await?;
        sqlx::query(
            "INSERT INTO activity_log (project_id, event_type, message, metadata)
             VALUES ($1, $2, $3, $4)",
        )
        .bind(project_id)
        .bind(event_type)
        .bind(message)
        .bind(metadata)
        .execute(&self.pool)
        .await
        .map_err(storage_err)?;
        Ok(())
    }

    /// Reads a page of one project's activity log, newest first. `Ok` with
    /// an empty page (not an error) when the project key is unknown — same
    /// "unknown project reads as empty" convention as the measures/
    /// component-tree endpoints.
    pub async fn list_activity(
        &self,
        project_key: &str,
        query: &ActivityLogQuery,
    ) -> Result<Page<ActivityLogEntry>, StorageError> {
        let mut count = QueryBuilder::<Postgres>::new(
            "SELECT COUNT(*) FROM activity_log al
             JOIN projects p ON p.id = al.project_id
             WHERE p.key = ",
        );
        count.push_bind(project_key);
        if let Some(event_type) = &query.event_type {
            count
                .push(" AND al.event_type = ")
                .push_bind(event_type.as_str());
        }
        let total: i64 = count
            .build_query_scalar()
            .fetch_one(&self.pool)
            .await
            .map_err(storage_err)?;

        let mut select = QueryBuilder::<Postgres>::new(
            "SELECT al.id, al.event_type, al.message, al.metadata,
                    to_char(al.created_at, 'YYYY-MM-DD\"T\"HH24:MI:SS.USZ') AS created_at
             FROM activity_log al
             JOIN projects p ON p.id = al.project_id
             WHERE p.key = ",
        );
        select.push_bind(project_key);
        if let Some(event_type) = &query.event_type {
            select
                .push(" AND al.event_type = ")
                .push_bind(event_type.as_str());
        }
        select
            .push(" ORDER BY al.id DESC LIMIT ")
            .push_bind(query.normalized_page_size() as i64)
            .push(" OFFSET ")
            .push_bind(query.offset() as i64);
        let rows = select
            .build()
            .fetch_all(&self.pool)
            .await
            .map_err(storage_err)?;

        Ok(Page {
            items: rows
                .iter()
                .map(activity_entry_from_row)
                .collect::<Result<_, _>>()?,
            page: query.normalized_page(),
            page_size: query.normalized_page_size(),
            total: total as usize,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_defaults_to_one_and_fifty() {
        let query = ActivityLogQuery::default();
        assert_eq!(query.normalized_page(), 1);
        assert_eq!(query.normalized_page_size(), 50);
        assert_eq!(query.offset(), 0);
    }

    #[test]
    fn page_size_is_capped_at_five_hundred() {
        let query = ActivityLogQuery {
            page_size: 10_000,
            ..Default::default()
        };
        assert_eq!(query.normalized_page_size(), 500);
    }

    #[test]
    fn offset_advances_by_page_size() {
        let query = ActivityLogQuery {
            page: 3,
            page_size: 20,
            ..Default::default()
        };
        assert_eq!(query.offset(), 40);
    }
}

/// `#[ignore]`d by default so `cargo test` needs no database; run explicitly
/// with `cargo test -p yunq-infra-postgres -- --ignored` against
/// `DATABASE_URL`, same convention as `lib.rs`'s `live_db_tests` module.
#[cfg(test)]
mod live_db_tests {
    use super::*;

    async fn connected_storage() -> PgIssueStorage {
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://yunq:yunq@localhost:5432/yunq".to_string());
        let storage = PgIssueStorage::connect_lazy(&database_url).unwrap();
        storage.migrate().await.unwrap();
        storage
    }

    #[tokio::test]
    #[ignore = "requires a live Postgres; see module docs"]
    async fn record_and_list_activity_round_trips_newest_first() {
        let storage = connected_storage().await;
        let key = format!(
            "activity-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );

        storage
            .record_activity(&key, "scan.started", "scan started", None)
            .await
            .unwrap();
        storage
            .record_activity(
                &key,
                "scan.failed",
                "boom",
                Some(serde_json::json!({"error": "boom"})),
            )
            .await
            .unwrap();

        let page = storage
            .list_activity(&key, &ActivityLogQuery::default())
            .await
            .unwrap();
        assert_eq!(page.total, 2);
        assert_eq!(page.items[0].event_type, "scan.failed");
        assert_eq!(
            page.items[0].metadata,
            Some(serde_json::json!({"error": "boom"}))
        );
        assert_eq!(page.items[1].event_type, "scan.started");

        let filtered = storage
            .list_activity(
                &key,
                &ActivityLogQuery {
                    event_type: Some("scan.failed".to_string()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(filtered.total, 1);

        let project_id = storage.ensure_project(&key).await.unwrap();
        sqlx::query("DELETE FROM projects WHERE id = $1")
            .bind(project_id)
            .execute(storage.pool())
            .await
            .unwrap();
    }

    #[tokio::test]
    #[ignore = "requires a live Postgres; see module docs"]
    async fn list_activity_for_unknown_project_is_an_empty_page() {
        let storage = connected_storage().await;
        let page = storage
            .list_activity("no-such-project-at-all", &ActivityLogQuery::default())
            .await
            .unwrap();
        assert_eq!(page.total, 0);
        assert!(page.items.is_empty());
    }
}
