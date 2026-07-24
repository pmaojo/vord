//! Outbound adapter: housekeeping — configurable retention for analysis
//! history. A project's `retention_days` overrides the instance-wide
//! default passed into `purge_expired`; `NULL` on both means "keep
//! forever" (retention is opt-in, not a silent default, since deletion
//! isn't reversible).
//!
//! Scoped to `analyses` (and, via `ON DELETE CASCADE`, its
//! `analysis_gate_results`/`analysis_coverage` rows) because that's the
//! table that actually grows unbounded with history. `issues`/`hotspots`
//! aren't scoped to a project or analysis in this schema — they're a flat,
//! current-findings table, not history — so pruning them isn't this
//! feature's job. `scan_jobs` never accumulates finished rows either: a
//! successfully handled job is deleted immediately and a failed one is
//! released back to `pending` for retry (see `queue.rs`), so there's
//! nothing there to age out.

use sqlx::Row;
use yunq_rules_engine::StorageError;

use crate::PgIssueStorage;

fn storage_err(e: impl std::fmt::Display) -> StorageError {
    StorageError(e.to_string())
}

/// How many analyses a housekeeping run actually removed, for the audit
/// log/API response.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PurgeReport {
    pub analyses_deleted: u64,
}

impl PgIssueStorage {
    /// Sets (or clears, with `None`) a project's retention override in
    /// days. Returns the prior value for the audit log. Creates the
    /// project by key on first sight, same as gate assignment/permissions.
    pub async fn set_project_retention_days(
        &self,
        project_key: &str,
        retention_days: Option<i32>,
    ) -> Result<Option<i32>, StorageError> {
        let project_id = self.ensure_project(project_key).await?;
        let mut tx = self.pool.begin().await.map_err(storage_err)?;

        let before: Option<i32> = sqlx::query("SELECT retention_days FROM projects WHERE id = $1")
            .bind(project_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(storage_err)?
            .try_get("retention_days")
            .map_err(storage_err)?;

        sqlx::query("UPDATE projects SET retention_days = $1 WHERE id = $2")
            .bind(retention_days)
            .bind(project_id)
            .execute(&mut *tx)
            .await
            .map_err(storage_err)?;

        tx.commit().await.map_err(storage_err)?;
        Ok(before)
    }

    /// Deletes analyses older than each project's effective retention —
    /// its own `retention_days` override if set, else `default_days`. A
    /// project with neither set is left untouched.
    pub async fn purge_expired(&self, default_days: Option<i32>) -> Result<PurgeReport, StorageError> {
        let analyses_deleted = sqlx::query(
            "WITH cutoffs AS (
                 SELECT id, COALESCE(retention_days, $1) AS days FROM projects
             )
             DELETE FROM analyses a
             USING cutoffs c
             WHERE a.project_id = c.id
               AND c.days IS NOT NULL
               AND a.created_at < now() - (c.days || ' days')::interval",
        )
        .bind(default_days)
        .execute(&self.pool)
        .await
        .map_err(storage_err)?
        .rows_affected();

        Ok(PurgeReport { analyses_deleted })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn purge_report_defaults_to_zero() {
        assert_eq!(PurgeReport::default(), PurgeReport { analyses_deleted: 0 });
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
    async fn purge_expired_removes_only_analyses_past_their_effective_retention() {
        let storage = connected_storage().await;
        let key = format!(
            "retention-test-{}",
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        );
        let project_id = storage.ensure_project(&key).await.unwrap();

        storage.record_analysis(project_id, "main", 100, 0).await.unwrap();
        let old_id = storage.record_analysis(project_id, "main", 100, 0).await.unwrap();
        sqlx::query("UPDATE analyses SET created_at = now() - interval '30 days' WHERE id = $1")
            .bind(old_id)
            .execute(storage.pool())
            .await
            .unwrap();

        let before = storage.set_project_retention_days(&key, Some(1)).await.unwrap();
        assert_eq!(before, None);

        let report = storage.purge_expired(None).await.unwrap();
        assert_eq!(report.analyses_deleted, 1);

        let remaining: i64 = sqlx::query("SELECT COUNT(*) AS n FROM analyses WHERE project_id = $1")
            .bind(project_id)
            .fetch_one(storage.pool())
            .await
            .unwrap()
            .try_get("n")
            .unwrap();
        assert_eq!(remaining, 1);

        sqlx::query("DELETE FROM projects WHERE id = $1")
            .bind(project_id)
            .execute(storage.pool())
            .await
            .unwrap();
    }

    #[tokio::test]
    #[ignore = "requires a live Postgres; see module docs"]
    async fn purge_expired_leaves_projects_with_no_effective_retention_untouched() {
        let storage = connected_storage().await;
        let key = format!(
            "retention-test-noop-{}",
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        );
        let project_id = storage.ensure_project(&key).await.unwrap();

        let old_id = storage.record_analysis(project_id, "main", 100, 0).await.unwrap();
        sqlx::query("UPDATE analyses SET created_at = now() - interval '3650 days' WHERE id = $1")
            .bind(old_id)
            .execute(storage.pool())
            .await
            .unwrap();

        // No project override, no instance default: this project's analysis
        // must survive the purge no matter what other test data is present.
        storage.purge_expired(None).await.unwrap();
        let remaining: i64 = sqlx::query("SELECT COUNT(*) AS n FROM analyses WHERE project_id = $1")
            .bind(project_id)
            .fetch_one(storage.pool())
            .await
            .unwrap()
            .try_get("n")
            .unwrap();
        assert_eq!(remaining, 1);

        sqlx::query("DELETE FROM projects WHERE id = $1")
            .bind(project_id)
            .execute(storage.pool())
            .await
            .unwrap();
    }
}
