//! Postgres-backed `AnalysisHistoryReader`: resolves a New Code override
//! (`ReferenceBranch`/`Days`/`SpecificAnalysis`, see
//! `yunq_rules_engine::new_code_overrides`) to a concrete analysis id and
//! rebuilds that analysis' `Baseline` from its persisted issue snapshot.
//!
//! No new table: `IssueStorage::save_issues` is a plain `INSERT`, never an
//! upsert, so every scan writes a *fresh* set of rows tagged with that scan's
//! `analysis_id` (see `lib.rs`). The full set of `issues` rows carrying one
//! `analysis_id` is therefore already that analysis' point-in-time snapshot —
//! exactly what a Baseline needs to be rebuilt from.

use sqlx::Row;
use yunq_ast::Span;
use yunq_rules_engine::{
    AnalysisHistoryReader, AnalysisReport, Baseline, Issue, Metrics, RuleId, Severity, StorageError,
};

use crate::shared::{find_project_id, storage_err};
use crate::PgAnalysisStore;

impl AnalysisHistoryReader for PgAnalysisStore {
    async fn latest_analysis_id_on_branch(
        &self,
        project_key: &str,
        branch: &str,
    ) -> Result<Option<i64>, StorageError> {
        let Some(project_id) = find_project_id(&self.pool, project_key).await? else {
            return Ok(None);
        };
        // Delegates to the existing project_id-keyed lookup coverage
        // ingestion already uses — same "most recent row for this branch"
        // query, just reached from a project key instead of an id already
        // in hand.
        self.latest_analysis_id(project_id, branch).await
    }

    async fn analysis_id_days_ago(
        &self,
        project_key: &str,
        branch: &str,
        days_ago: u32,
    ) -> Result<Option<i64>, StorageError> {
        let Some(project_id) = find_project_id(&self.pool, project_key).await? else {
            return Ok(None);
        };
        let row = sqlx::query(
            "SELECT id FROM analyses
             WHERE project_id = $1 AND branch = $2
               AND created_at <= now() - ($3 * interval '1 day')
             ORDER BY created_at DESC LIMIT 1",
        )
        .bind(project_id)
        .bind(branch)
        .bind(days_ago as i32)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_err)?;
        row.map(|row| row.try_get::<i64, _>("id")).transpose().map_err(storage_err)
    }

    async fn previous_analysis_id(
        &self,
        project_key: &str,
        branch: &str,
        before_analysis_id: i64,
    ) -> Result<Option<i64>, StorageError> {
        let Some(project_id) = find_project_id(&self.pool, project_key).await? else {
            return Ok(None);
        };
        let row = sqlx::query(
            "SELECT id FROM analyses
             WHERE project_id = $1 AND branch = $2 AND id < $3
             ORDER BY id DESC LIMIT 1",
        )
        .bind(project_id)
        .bind(branch)
        .bind(before_analysis_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_err)?;
        row.map(|row| row.try_get::<i64, _>("id")).transpose().map_err(storage_err)
    }

    async fn baseline_for_analysis(&self, analysis_id: i64) -> Result<Baseline, StorageError> {
        let rows = sqlx::query(
            "SELECT rule, severity, file, start_line, start_col, end_line, end_col, message
             FROM issues WHERE analysis_id = $1",
        )
        .bind(analysis_id)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_err)?;

        let mut issues = Vec::with_capacity(rows.len());
        for row in &rows {
            let rule = RuleId::new(row.try_get::<String, _>("rule").map_err(storage_err)?.as_str())
                .map_err(storage_err)?;
            let severity_raw: String = row.try_get("severity").map_err(storage_err)?;
            let severity = Severity::parse(&severity_raw)
                .ok_or_else(|| StorageError(format!("invalid severity {severity_raw:?}")))?;
            let span = Span::new(
                row.try_get::<i32, _>("start_line").map_err(storage_err)? as u32,
                row.try_get::<i32, _>("start_col").map_err(storage_err)? as u32,
                row.try_get::<i32, _>("end_line").map_err(storage_err)? as u32,
                row.try_get::<i32, _>("end_col").map_err(storage_err)? as u32,
            );
            let message: String = row.try_get("message").map_err(storage_err)?;
            let file: String = row.try_get("file").map_err(storage_err)?;
            issues.push(Issue::new(rule, severity, message, file, span));
        }

        let report = AnalysisReport::new(issues, Vec::new(), Metrics::new());
        Ok(Baseline::from_report(&report))
    }
}

#[cfg(test)]
mod live_db_tests {
    use yunq_rules_engine::{IssueScope, IssueStorage};

    use super::*;
    use crate::{PgIssueStorage, shared::WHOLE_TABLE_LOCK};

    async fn connected_storage() -> PgAnalysisStore {
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://yunq:yunq@localhost:5432/yunq".to_string());
        let storage = PgAnalysisStore::connect_lazy(&database_url).unwrap();
        storage.migrate().await.unwrap();
        storage
    }

    fn unique_key(prefix: &str) -> String {
        format!(
            "{prefix}-{}",
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        )
    }

    #[tokio::test]
    #[ignore = "requires a live Postgres; see module docs"]
    async fn reference_branch_resolves_to_latest_analysis_baseline() {
        let _guard = WHOLE_TABLE_LOCK.lock().await;
        let analyses = connected_storage().await;
        let issues = PgIssueStorage::new(analyses.pool().clone());
        let key = unique_key("nco-refbranch");
        let project_id = analyses.ensure_project(&key).await.unwrap();

        let analysis_id = analyses.record_analysis(project_id, "develop", 100, 1).await.unwrap();
        let issue = Issue::new(
            RuleId::new("owasp:sqli").unwrap(),
            Severity::Critical,
            "sql injection",
            "src/db.rs",
            Span::new(10, 1, 10, 20),
        );
        issues
            .save_issues(&[issue.clone()], IssueScope { project_id: Some(project_id), analysis_id: Some(analysis_id) })
            .await
            .unwrap();

        let resolved_id = analyses.latest_analysis_id_on_branch(&key, "develop").await.unwrap();
        assert_eq!(resolved_id, Some(analysis_id));

        let baseline = analyses.baseline_for_analysis(analysis_id).await.unwrap();
        assert!(baseline.contains(&issue));

        sqlx::query("DELETE FROM projects WHERE id = $1").bind(project_id).execute(analyses.pool()).await.unwrap();
    }

    #[tokio::test]
    #[ignore = "requires a live Postgres; see module docs"]
    async fn days_ago_resolves_to_the_closest_prior_analysis() {
        let _guard = WHOLE_TABLE_LOCK.lock().await;
        let analyses = connected_storage().await;
        let key = unique_key("nco-daysago");
        let project_id = analyses.ensure_project(&key).await.unwrap();

        let old_id = analyses.record_analysis(project_id, "main", 100, 0).await.unwrap();
        sqlx::query("UPDATE analyses SET created_at = now() - interval '10 days' WHERE id = $1")
            .bind(old_id)
            .execute(analyses.pool())
            .await
            .unwrap();
        // A more recent analysis exists too, but a 7-day lookback must land
        // on the 10-day-old row, not this one.
        analyses.record_analysis(project_id, "main", 100, 0).await.unwrap();

        let resolved_id = analyses.analysis_id_days_ago(&key, "main", 7).await.unwrap();
        assert_eq!(resolved_id, Some(old_id));

        sqlx::query("DELETE FROM projects WHERE id = $1").bind(project_id).execute(analyses.pool()).await.unwrap();
    }

    #[tokio::test]
    #[ignore = "requires a live Postgres; see module docs"]
    async fn unanalyzed_project_resolves_to_no_analysis() {
        let analyses = connected_storage().await;
        let resolved = analyses
            .latest_analysis_id_on_branch(&unique_key("nco-nonexistent"), "main")
            .await
            .unwrap();
        assert_eq!(resolved, None);
    }

    #[tokio::test]
    #[ignore = "requires a live Postgres; see module docs"]
    async fn previous_analysis_id_excludes_the_current_pending_row() {
        let _guard = WHOLE_TABLE_LOCK.lock().await;
        let analyses = connected_storage().await;
        let key = unique_key("nco-previous");
        let project_id = analyses.ensure_project(&key).await.unwrap();

        let first_id = analyses.record_analysis(project_id, "main", 100, 0).await.unwrap();
        // The pending row for the scan currently being classified — must
        // not be returned as its own "previous" analysis.
        let current_id = analyses.record_analysis_pending(project_id, "main").await.unwrap();

        let resolved = analyses.previous_analysis_id(&key, "main", current_id).await.unwrap();
        assert_eq!(resolved, Some(first_id));

        sqlx::query("DELETE FROM projects WHERE id = $1").bind(project_id).execute(analyses.pool()).await.unwrap();
    }

    #[tokio::test]
    #[ignore = "requires a live Postgres; see module docs"]
    async fn previous_analysis_id_is_none_on_a_project_s_first_scan() {
        let _guard = WHOLE_TABLE_LOCK.lock().await;
        let analyses = connected_storage().await;
        let key = unique_key("nco-previous-first");
        let project_id = analyses.ensure_project(&key).await.unwrap();

        let current_id = analyses.record_analysis_pending(project_id, "main").await.unwrap();
        let resolved = analyses.previous_analysis_id(&key, "main", current_id).await.unwrap();
        assert_eq!(resolved, None);

        sqlx::query("DELETE FROM projects WHERE id = $1").bind(project_id).execute(analyses.pool()).await.unwrap();
    }
}
