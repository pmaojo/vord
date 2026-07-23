//! Outbound adapter: coverage report persistence — the server-side
//! counterpart to the CLI's local `--coverage`/`--cobertura`/etc. flags.
//! Lives alongside `PgIssueStorage`/`gate.rs` (same pool, same database).

use sqlx::Row;
use yunq_rules_engine::{CoverageResultReader, CoverageResultSummary, CoverageStorage, CoverageSummary, StorageError};

use crate::PgIssueStorage;

fn storage_err(e: impl std::fmt::Display) -> StorageError {
    StorageError(e.to_string())
}

impl CoverageStorage for PgIssueStorage {
    async fn save_coverage(
        &self,
        analysis_id: i64,
        summary: CoverageSummary,
    ) -> Result<(), StorageError> {
        sqlx::query(
            "INSERT INTO analysis_coverage
                (analysis_id, covered_lines, coverable_lines, covered_branches, coverable_branches)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (analysis_id) DO UPDATE SET
                covered_lines = EXCLUDED.covered_lines,
                coverable_lines = EXCLUDED.coverable_lines,
                covered_branches = EXCLUDED.covered_branches,
                coverable_branches = EXCLUDED.coverable_branches,
                recorded_at = now()",
        )
        .bind(analysis_id)
        .bind(summary.covered_lines() as i64)
        .bind(summary.coverable_lines() as i64)
        .bind(summary.covered_branches() as i64)
        .bind(summary.coverable_branches() as i64)
        .execute(&self.pool)
        .await
        .map_err(storage_err)?;
        Ok(())
    }
}

impl PgIssueStorage {
    /// The most recent analysis id for a project's branch — the row a
    /// freshly-ingested coverage report attaches to, since coverage is
    /// scoped to an already-completed scan rather than starting a new one.
    pub async fn latest_analysis_id(
        &self,
        project_id: i64,
        branch: &str,
    ) -> Result<Option<i64>, StorageError> {
        let row = sqlx::query("SELECT id FROM analyses WHERE project_id = $1 AND branch = $2 ORDER BY id DESC LIMIT 1")
            .bind(project_id)
            .bind(branch)
            .fetch_optional(&self.pool)
            .await
            .map_err(storage_err)?;
        row.map(|row| row.try_get::<i64, _>("id")).transpose().map_err(storage_err)
    }
}

impl CoverageResultReader for PgIssueStorage {
    async fn latest_coverage(
        &self,
        project_key: &str,
    ) -> Result<Option<CoverageResultSummary>, StorageError> {
        let row = sqlx::query(
            "SELECT c.covered_lines, c.coverable_lines, c.covered_branches, c.coverable_branches
             FROM analysis_coverage c
             JOIN analyses a ON a.id = c.analysis_id
             JOIN projects p ON p.id = a.project_id
             WHERE p.key = $1
             ORDER BY a.id DESC
             LIMIT 1",
        )
        .bind(project_key)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_err)?;

        let Some(row) = row else { return Ok(None) };
        let covered_lines: i64 = row.try_get("covered_lines").map_err(storage_err)?;
        let coverable_lines: i64 = row.try_get("coverable_lines").map_err(storage_err)?;
        let covered_branches: i64 = row.try_get("covered_branches").map_err(storage_err)?;
        let coverable_branches: i64 = row.try_get("coverable_branches").map_err(storage_err)?;

        let mut summary = CoverageSummary::default();
        summary.add(covered_lines as usize, coverable_lines as usize).map_err(storage_err)?;
        summary
            .add_branches(covered_branches as usize, coverable_branches as usize)
            .map_err(storage_err)?;
        Ok(Some(CoverageResultSummary { summary }))
    }
}
