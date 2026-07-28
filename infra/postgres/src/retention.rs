//! Outbound adapter: housekeeping — configurable retention for analysis
//! history, plus (since migration `0016_issue_hotspot_scoping.sql`) the
//! issues/hotspots found by each analysis. A project's `retention_days`
//! overrides the instance-wide default passed into `purge_expired`; `NULL`
//! on both means "keep forever" (retention is opt-in, not a silent
//! default, since deletion isn't reversible).
//!
//! `analyses` (and, via `ON DELETE CASCADE`, its
//! `analysis_gate_results`/`analysis_coverage` rows) purges on the same
//! effective-retention rule as `issues`/`hotspots`, now that the latter two
//! carry a `project_id`/`analysis_id` (nullable — pre-migration rows have
//! neither and are never matched by the purge query below, so they're kept
//! forever rather than guessed at). `scan_jobs` never accumulates finished
//! rows: a successfully handled job is deleted immediately and a failed one
//! is released back to `pending` for retry (see `queue.rs`), so there's
//! nothing there to age out.

use sqlx::Row;
use yunq_rules_engine::StorageError;

use crate::{PgAuditStore, PgConfigStore};

fn storage_err(e: impl std::fmt::Display) -> StorageError {
    StorageError(e.to_string())
}

/// How many rows of each kind a housekeeping run actually removed, for the
/// audit log/API response.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PurgeReport {
    pub analyses_deleted: u64,
    pub issues_deleted: u64,
    pub hotspots_deleted: u64,
}

impl PgConfigStore {
    /// Sets (or clears, with `None`) a project's retention override in
    /// days. Returns the prior value for the audit log. Creates the
    /// project by key on first sight, same as gate assignment/permissions.
    pub async fn set_project_retention_days(
        &self,
        project_key: &str,
        retention_days: Option<i32>,
    ) -> Result<Option<i32>, StorageError> {
        let project_id = crate::shared::ensure_project(&self.pool, project_key).await?;
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
}

impl PgAuditStore {
    /// Deletes analyses, issues and hotspots older than each project's
    /// effective retention — its own `retention_days` override if set, else
    /// `default_days`. A project with neither set is left untouched.
    /// `issues`/`hotspots` rows with no `project_id` (saved before
    /// `0016_issue_hotspot_scoping.sql`, or from a run that never resolved
    /// a project) can never match the `project_id = c.id` join and so are
    /// never touched by this query, no matter their age.
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

        let issues_deleted = sqlx::query(
            "WITH cutoffs AS (
                 SELECT id, COALESCE(retention_days, $1) AS days FROM projects
             )
             DELETE FROM issues i
             USING cutoffs c
             WHERE i.project_id = c.id
               AND c.days IS NOT NULL
               AND i.created_at < now() - (c.days || ' days')::interval",
        )
        .bind(default_days)
        .execute(&self.pool)
        .await
        .map_err(storage_err)?
        .rows_affected();

        let hotspots_deleted = sqlx::query(
            "WITH cutoffs AS (
                 SELECT id, COALESCE(retention_days, $1) AS days FROM projects
             )
             DELETE FROM hotspots h
             USING cutoffs c
             WHERE h.project_id = c.id
               AND c.days IS NOT NULL
               AND h.created_at < now() - (c.days || ' days')::interval",
        )
        .bind(default_days)
        .execute(&self.pool)
        .await
        .map_err(storage_err)?
        .rows_affected();

        Ok(PurgeReport { analyses_deleted, issues_deleted, hotspots_deleted })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn purge_report_defaults_to_zero() {
        assert_eq!(
            PurgeReport::default(),
            PurgeReport { analyses_deleted: 0, issues_deleted: 0, hotspots_deleted: 0 }
        );
    }
}

/// `#[ignore]`d by default so `cargo test` needs no database; run explicitly
/// with `cargo test -p yunq-infra-postgres -- --ignored` against
/// `DATABASE_URL`, same convention as `lib.rs`'s `live_db_tests` module.
#[cfg(test)]
mod live_db_tests {
    use super::*;
    use crate::{PgAnalysisStore, PgIssueStorage};
    use yunq_ast::Span;
    use yunq_rules_engine::{Hotspot, HotspotStorage, Issue, IssueScope, IssueStorage, RuleId, Severity};

    /// A connected adapter plus exclusive use of the issue/hotspot/analysis
    /// tables: `purge_expired` sweeps *every* project past its effective
    /// retention, so a sibling test's rows are fair game for the sweep
    /// this test is asserting on. The guard must outlive the test body,
    /// so callers bind it.
    async fn exclusive_retention() -> (PgAnalysisStore, tokio::sync::MutexGuard<'static, ()>) {
        let guard = crate::shared::WHOLE_TABLE_LOCK.lock().await;
        (connected_storage().await, guard)
    }

    /// The retention sweep spans three contexts: an analysis to age out,
    /// the issues/hotspots hanging off it, and the audit-side purge that
    /// removes them. Tests build all three from the one pool.
    async fn connected_storage() -> PgAnalysisStore {
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://yunq:yunq@localhost:5432/yunq".to_string());
        let storage = PgAnalysisStore::connect_lazy(&database_url).unwrap();
        storage.migrate().await.unwrap();
        storage
    }

    #[tokio::test]
    #[ignore = "requires a live Postgres; see module docs"]
    async fn purge_expired_removes_only_analyses_past_their_effective_retention() {
        let (storage, _retention) = exclusive_retention().await;
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

        let before = PgConfigStore::new(storage.pool().clone()).set_project_retention_days(&key, Some(1)).await.unwrap();
        assert_eq!(before, None);

        let report = PgAuditStore::new(storage.pool().clone()).purge_expired(None).await.unwrap();
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
        let (storage, _retention) = exclusive_retention().await;
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
        PgAuditStore::new(storage.pool().clone()).purge_expired(None).await.unwrap();
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

    fn test_issue(marker: &str) -> Issue {
        Issue::new(
            RuleId::new("owasp:sql-injection").unwrap(),
            Severity::Major,
            format!("issue {marker}"),
            format!("src/{marker}.rs"),
            Span::new(1, 0, 1, 10),
        )
    }

    fn test_hotspot(marker: &str) -> Hotspot {
        Hotspot::new(
            RuleId::new("owasp:hotspot").unwrap(),
            format!("hotspot {marker}"),
            format!("src/{marker}.rs"),
            Span::new(2, 0, 2, 5),
        )
    }

    #[tokio::test]
    #[ignore = "requires a live Postgres; see module docs"]
    async fn purge_expired_removes_only_issues_and_hotspots_past_their_effective_retention() {
        let (storage, _retention) = exclusive_retention().await;
        let key = format!(
            "retention-test-findings-{}",
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        );
        let project_id = storage.ensure_project(&key).await.unwrap();
        let scope = IssueScope { project_id: Some(project_id), analysis_id: None };

        // One recent issue/hotspot (kept) and one old issue/hotspot (purged).
        PgIssueStorage::new(storage.pool().clone()).save_issues(&[test_issue("recent")], scope).await.unwrap();
        PgIssueStorage::new(storage.pool().clone()).save_issues(&[test_issue("old")], scope).await.unwrap();
        PgIssueStorage::new(storage.pool().clone()).save_hotspots(&[test_hotspot("recent")], scope).await.unwrap();
        PgIssueStorage::new(storage.pool().clone()).save_hotspots(&[test_hotspot("old")], scope).await.unwrap();

        sqlx::query(
            "UPDATE issues SET created_at = now() - interval '30 days'
             WHERE project_id = $1 AND file = 'src/old.rs'",
        )
        .bind(project_id)
        .execute(storage.pool())
        .await
        .unwrap();
        sqlx::query(
            "UPDATE hotspots SET created_at = now() - interval '30 days'
             WHERE project_id = $1 AND file = 'src/old.rs'",
        )
        .bind(project_id)
        .execute(storage.pool())
        .await
        .unwrap();

        let before = PgConfigStore::new(storage.pool().clone()).set_project_retention_days(&key, Some(1)).await.unwrap();
        assert_eq!(before, None);

        let report = PgAuditStore::new(storage.pool().clone()).purge_expired(None).await.unwrap();
        assert_eq!(report.issues_deleted, 1);
        assert_eq!(report.hotspots_deleted, 1);

        let remaining_issues: i64 =
            sqlx::query("SELECT COUNT(*) AS n FROM issues WHERE project_id = $1")
                .bind(project_id)
                .fetch_one(storage.pool())
                .await
                .unwrap()
                .try_get("n")
                .unwrap();
        assert_eq!(remaining_issues, 1);

        let remaining_hotspots: i64 =
            sqlx::query("SELECT COUNT(*) AS n FROM hotspots WHERE project_id = $1")
                .bind(project_id)
                .fetch_one(storage.pool())
                .await
                .unwrap()
                .try_get("n")
                .unwrap();
        assert_eq!(remaining_hotspots, 1);

        sqlx::query("DELETE FROM projects WHERE id = $1")
            .bind(project_id)
            .execute(storage.pool())
            .await
            .unwrap();
    }

    #[tokio::test]
    #[ignore = "requires a live Postgres; see module docs"]
    async fn purge_expired_leaves_unscoped_issues_and_hotspots_untouched() {
        let (storage, _retention) = exclusive_retention().await;
        let key = format!(
            "retention-test-unscoped-{}",
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        );
        let marker = format!("unscoped-{}", key);

        // Pre-migration-shaped rows: saved with no project/analysis at all
        // (the default `IssueScope`), same as every row saved before
        // 0016_issue_hotspot_scoping.sql existed.
        PgIssueStorage::new(storage.pool().clone()).save_issues(&[test_issue(&marker)], IssueScope::default()).await.unwrap();
        PgIssueStorage::new(storage.pool().clone()).save_hotspots(&[test_hotspot(&marker)], IssueScope::default()).await.unwrap();

        let issue_file = format!("src/{marker}.rs");
        sqlx::query("UPDATE issues SET created_at = now() - interval '3650 days' WHERE file = $1")
            .bind(&issue_file)
            .execute(storage.pool())
            .await
            .unwrap();
        sqlx::query("UPDATE hotspots SET created_at = now() - interval '3650 days' WHERE file = $1")
            .bind(&issue_file)
            .execute(storage.pool())
            .await
            .unwrap();

        // An aggressive instance-wide default: if these rows had a
        // project_id, this would purge them instantly. They don't, so the
        // purge query's join against `projects` can never match them.
        PgAuditStore::new(storage.pool().clone()).purge_expired(Some(1)).await.unwrap();

        let remaining_issues: i64 =
            sqlx::query("SELECT COUNT(*) AS n FROM issues WHERE file = $1")
                .bind(&issue_file)
                .fetch_one(storage.pool())
                .await
                .unwrap()
                .try_get("n")
                .unwrap();
        assert_eq!(remaining_issues, 1);

        let remaining_hotspots: i64 =
            sqlx::query("SELECT COUNT(*) AS n FROM hotspots WHERE file = $1")
                .bind(&issue_file)
                .fetch_one(storage.pool())
                .await
                .unwrap()
                .try_get("n")
                .unwrap();
        assert_eq!(remaining_hotspots, 1);

        sqlx::query("DELETE FROM issues WHERE file = $1")
            .bind(&issue_file)
            .execute(storage.pool())
            .await
            .unwrap();
        sqlx::query("DELETE FROM hotspots WHERE file = $1")
            .bind(&issue_file)
            .execute(storage.pool())
            .await
            .unwrap();
    }
}
