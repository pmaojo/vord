//! Outbound adapter: coverage report persistence — the server-side
//! counterpart to the CLI's local `--coverage`/`--cobertura`/etc. flags.
//! Lives alongside `PgIssueStorage`/`gate.rs` (same pool, same database).

use std::collections::BTreeMap;

use sqlx::{Postgres, QueryBuilder, Row};
use yunq_rules_engine::{
    CoverageResultReader, CoverageResultSummary, CoverageStorage, CoverageSummary, FileCoverage,
    FileCoverageLineReader, FileCoverageLineStorage, FileCoverageLines, StorageError,
};

use crate::PgAnalysisStore;

fn storage_err(e: impl std::fmt::Display) -> StorageError {
    StorageError(e.to_string())
}

impl CoverageStorage for PgAnalysisStore {
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

impl PgAnalysisStore {
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

/// Postgres binds at most 65535 parameters per statement; coverage-line rows
/// bind 4 columns each, matching the batching convention `IssueStorage::save_issues`
/// already uses.
const COVERAGE_LINE_BATCH_ROWS: usize = 1000;

impl FileCoverageLineStorage for PgAnalysisStore {
    async fn save_file_coverage_lines(
        &self,
        analysis_id: i64,
        files: &[FileCoverage],
    ) -> Result<(), StorageError> {
        let mut rows: Vec<(&str, u32, i32)> = Vec::new();
        for file in files {
            for (line, hits) in file.lines() {
                rows.push((file.path(), *line, *hits as i32));
            }
        }
        if rows.is_empty() {
            return Ok(());
        }

        let mut tx = self.pool.begin().await.map_err(storage_err)?;
        // Re-ingesting a report for the same analysis replaces its line
        // detail rather than accumulating duplicates, same convention as
        // `save_coverage`'s summary upsert.
        sqlx::query("DELETE FROM analysis_file_coverage_lines WHERE analysis_id = $1")
            .bind(analysis_id)
            .execute(&mut *tx)
            .await
            .map_err(storage_err)?;

        for chunk in rows.chunks(COVERAGE_LINE_BATCH_ROWS) {
            let mut builder = QueryBuilder::<Postgres>::new(
                "INSERT INTO analysis_file_coverage_lines (analysis_id, file, line_number, hits) ",
            );
            builder.push_values(chunk, |mut row, (file, line, hits)| {
                row.push_bind(analysis_id).push_bind(*file).push_bind(*line as i32).push_bind(*hits);
            });
            builder.build().execute(&mut *tx).await.map_err(storage_err)?;
        }
        tx.commit().await.map_err(storage_err)
    }
}

impl FileCoverageLineReader for PgAnalysisStore {
    async fn file_coverage_lines(
        &self,
        project_key: &str,
        branch: &str,
        file: &str,
    ) -> Result<Option<FileCoverageLines>, StorageError> {
        // Scoped to the project's most recent analysis that has coverage
        // ingested at all (not necessarily the very latest analysis — a scan
        // may have run since the last coverage upload), mirroring
        // `latest_coverage`'s own "most recent coverage-bearing analysis"
        // semantics.
        let rows = sqlx::query(
            "SELECT l.line_number, l.hits
             FROM analysis_file_coverage_lines l
             JOIN analyses a ON a.id = l.analysis_id
             JOIN projects p ON p.id = a.project_id
             WHERE p.key = $1 AND a.branch = $2 AND l.file = $3
               AND l.analysis_id = (
                   SELECT c.analysis_id FROM analysis_coverage c
                   JOIN analyses a2 ON a2.id = c.analysis_id
                   WHERE a2.project_id = a.project_id AND a2.branch = $2
                   ORDER BY c.analysis_id DESC LIMIT 1
               )
             ORDER BY l.line_number ASC",
        )
        .bind(project_key)
        .bind(branch)
        .bind(file)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_err)?;

        if rows.is_empty() {
            return Ok(None);
        }

        let mut lines = BTreeMap::new();
        for row in &rows {
            let line: i32 = row.try_get("line_number").map_err(storage_err)?;
            let hits: i32 = row.try_get("hits").map_err(storage_err)?;
            lines.insert(line as u32, hits as usize);
        }
        Ok(Some(FileCoverageLines { lines }))
    }
}

impl CoverageResultReader for PgAnalysisStore {
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
