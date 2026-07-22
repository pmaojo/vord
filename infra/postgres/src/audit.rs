//! Outbound adapter: the ops audit log — who changed what and when for
//! quality gates, quality profiles and project permissions
//! (`GET /api/audit-log`). Pure persistence: callers decide the action name
//! and compute `before`/`after`; this module only writes and reads rows.

use serde_json::Value;
use sqlx::postgres::{PgRow, Postgres};
use sqlx::{QueryBuilder, Row};
use yunq_rules_engine::{Page, StorageError};

use crate::PgIssueStorage;

fn storage_err(e: impl std::fmt::Display) -> StorageError {
    StorageError(e.to_string())
}

/// One persisted audit log entry.
#[derive(Clone, Debug, PartialEq)]
pub struct AuditLogEntry {
    pub id: i64,
    pub actor_user_id: Option<String>,
    pub action: String,
    pub entity_type: String,
    pub entity_id: String,
    pub before: Option<Value>,
    pub after: Option<Value>,
    /// RFC3339 timestamp.
    pub created_at: String,
}

/// Filters plus pagination for `GET /api/audit-log`; normalization mirrors
/// `IssueQuery`'s (1-based page, page size default 50 capped at 500).
#[derive(Clone, Debug, Default)]
pub struct AuditLogQuery {
    pub entity_type: Option<String>,
    /// Inclusive lower bound, RFC3339 (cast to `timestamptz` in SQL).
    pub from: Option<String>,
    /// Inclusive upper bound, RFC3339 (cast to `timestamptz` in SQL).
    pub to: Option<String>,
    pub page: usize,
    pub page_size: usize,
}

impl AuditLogQuery {
    pub fn normalized_page(&self) -> usize {
        self.page.max(1)
    }

    pub fn normalized_page_size(&self) -> usize {
        if self.page_size == 0 { 50 } else { self.page_size.clamp(1, 500) }
    }

    pub fn offset(&self) -> usize {
        (self.normalized_page() - 1) * self.normalized_page_size()
    }
}

fn push_audit_filters<'a>(builder: &mut QueryBuilder<'a, Postgres>, query: &'a AuditLogQuery) {
    if let Some(entity_type) = &query.entity_type {
        builder.push(" AND entity_type = ").push_bind(entity_type.as_str());
    }
    if let Some(from) = &query.from {
        builder.push(" AND created_at >= ").push_bind(from.as_str()).push("::timestamptz");
    }
    if let Some(to) = &query.to {
        builder.push(" AND created_at <= ").push_bind(to.as_str()).push("::timestamptz");
    }
}

fn audit_entry_from_row(row: &PgRow) -> Result<AuditLogEntry, StorageError> {
    Ok(AuditLogEntry {
        id: row.try_get("id").map_err(storage_err)?,
        actor_user_id: row.try_get("actor_user_id").map_err(storage_err)?,
        action: row.try_get("action").map_err(storage_err)?,
        entity_type: row.try_get("entity_type").map_err(storage_err)?,
        entity_id: row.try_get("entity_id").map_err(storage_err)?,
        before: row.try_get("before").map_err(storage_err)?,
        after: row.try_get("after").map_err(storage_err)?,
        created_at: row.try_get("created_at").map_err(storage_err)?,
    })
}

impl PgIssueStorage {
    /// Appends one audit log entry. Not run inside the caller's mutation
    /// transaction (same fire-and-follow-up pattern already used for the
    /// issue changelog in `lib.rs::record_transition`) — the audit trail is
    /// a best-effort record of what happened, not a consistency boundary.
    pub async fn record_audit(
        &self,
        actor_user_id: Option<&str>,
        action: &str,
        entity_type: &str,
        entity_id: &str,
        before: Option<Value>,
        after: Option<Value>,
    ) -> Result<(), StorageError> {
        sqlx::query(
            "INSERT INTO audit_log (actor_user_id, action, entity_type, entity_id, before, after)
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(actor_user_id)
        .bind(action)
        .bind(entity_type)
        .bind(entity_id)
        .bind(before)
        .bind(after)
        .execute(&self.pool)
        .await
        .map_err(storage_err)?;
        Ok(())
    }

    /// Reads a page of the audit log, newest first.
    pub async fn list_audit_log(
        &self,
        query: &AuditLogQuery,
    ) -> Result<Page<AuditLogEntry>, StorageError> {
        let mut count = QueryBuilder::<Postgres>::new("SELECT COUNT(*) FROM audit_log WHERE 1=1");
        push_audit_filters(&mut count, query);
        let total: i64 =
            count.build_query_scalar().fetch_one(&self.pool).await.map_err(storage_err)?;

        let mut select = QueryBuilder::<Postgres>::new(
            "SELECT id, actor_user_id, action, entity_type, entity_id, before, after,
                    to_char(created_at, 'YYYY-MM-DD\"T\"HH24:MI:SS.USZ') AS created_at
             FROM audit_log WHERE 1=1",
        );
        push_audit_filters(&mut select, query);
        select
            .push(" ORDER BY id DESC LIMIT ")
            .push_bind(query.normalized_page_size() as i64)
            .push(" OFFSET ")
            .push_bind(query.offset() as i64);
        let rows = select.build().fetch_all(&self.pool).await.map_err(storage_err)?;

        Ok(Page {
            items: rows.iter().map(audit_entry_from_row).collect::<Result<_, _>>()?,
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
        let query = AuditLogQuery::default();
        assert_eq!(query.normalized_page(), 1);
        assert_eq!(query.normalized_page_size(), 50);
        assert_eq!(query.offset(), 0);
    }

    #[test]
    fn page_size_is_capped_at_five_hundred() {
        let query = AuditLogQuery { page_size: 10_000, ..Default::default() };
        assert_eq!(query.normalized_page_size(), 500);
    }

    #[test]
    fn offset_advances_by_page_size() {
        let query = AuditLogQuery { page: 3, page_size: 20, ..Default::default() };
        assert_eq!(query.offset(), 40);
    }
}
