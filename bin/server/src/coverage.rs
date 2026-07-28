//! Coverage ingestion (Fase 2 gap noted in `ROADMAP.md`): `POST
//! /api/projects/{key}/coverage` ingests a raw LCOV/Cobertura/JaCoCo/
//! llvm-cov/Istanbul report against a project's latest analysis, and `GET
//! /api/projects/{key}/coverage` reads the persisted summary back. Until
//! now coverage was only ever computed locally by the CLI's `--coverage`/
//! `--cobertura`/etc. flags; this is the server-side counterpart so a CI
//! job can upload a report without shelling out to the CLI.
//!
//! Coverage attaches to the most recent analysis already recorded for the
//! project/branch (`analyses`, populated by the worker after a scan) rather
//! than starting a new one — same relationship `analysis_gate_results` has
//! to `analyses`. A project with no prior scan gets 404, not a silently
//! orphaned coverage row.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use futures::future::BoxFuture;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use yunq_infra_fs::CoverageFormat;
use yunq_infra_postgres::PgAnalysisStore;
use yunq_rules_engine::{
    ComponentTree, ComponentTreeReader, CoverageResultReader, CoverageResultSummary,
    CoverageStorage, CoverageSummary, FileBlame, FileBlameLineReader, FileBlameLineStorage,
    FileBlameLines, FileCoverage, FileCoverageLineReader, FileCoverageLineStorage,
    FileCoverageLines, MeasureHistoryPoint, MeasureHistoryReader, StorageError,
};

use crate::AppState;

/// Object-safe HTTP-facing adapter over the coverage, measure-history and
/// component-tree read/write methods on `PgAnalysisStore` — same "one trait
/// per composition-root need" pattern as `OpsStore`/`GateBadgePort` in
/// `main.rs`. Grown beyond pure coverage concerns (issue #26's measure
/// history / component tree / sources endpoints) rather than adding a new
/// `AppState` field, since `AppState`'s construction lives in `main.rs`
/// and other in-flight work touches that file concurrently — reusing this
/// already-wired field keeps `main.rs` changes to `mod` + route
/// registrations only.
pub(crate) trait CoveragePort: Send + Sync {
    fn ensure_project(&self, key: String) -> BoxFuture<'_, Result<i64, StorageError>>;

    fn latest_analysis_id(
        &self,
        project_id: i64,
        branch: String,
    ) -> BoxFuture<'_, Result<Option<i64>, StorageError>>;

    fn save_coverage(
        &self,
        analysis_id: i64,
        summary: CoverageSummary,
    ) -> BoxFuture<'_, Result<(), StorageError>>;

    fn latest_coverage(
        &self,
        project_key: String,
    ) -> BoxFuture<'_, Result<Option<CoverageResultSummary>, StorageError>>;

    fn save_file_coverage_lines(
        &self,
        analysis_id: i64,
        files: Vec<FileCoverage>,
    ) -> BoxFuture<'_, Result<(), StorageError>>;

    fn file_coverage_lines(
        &self,
        project_key: String,
        branch: String,
        file: String,
    ) -> BoxFuture<'_, Result<Option<FileCoverageLines>, StorageError>>;

    #[allow(clippy::too_many_arguments)]
    fn measure_history(
        &self,
        project_key: String,
        branch: String,
        component: Option<String>,
        metric_keys: Vec<String>,
        from: Option<String>,
        to: Option<String>,
    ) -> BoxFuture<'_, Result<Vec<MeasureHistoryPoint>, StorageError>>;

    fn component_tree(
        &self,
        project_key: String,
        branch: String,
    ) -> BoxFuture<'_, Result<Option<ComponentTree>, StorageError>>;

    fn save_file_blame_lines(
        &self,
        analysis_id: i64,
        files: Vec<FileBlame>,
    ) -> BoxFuture<'_, Result<(), StorageError>>;

    fn file_blame_lines(
        &self,
        project_key: String,
        branch: String,
        file: String,
    ) -> BoxFuture<'_, Result<Option<FileBlameLines>, StorageError>>;
}

impl CoveragePort for PgAnalysisStore {
    fn ensure_project(&self, key: String) -> BoxFuture<'_, Result<i64, StorageError>> {
        Box::pin(async move { PgAnalysisStore::ensure_project(self, &key).await })
    }

    fn latest_analysis_id(
        &self,
        project_id: i64,
        branch: String,
    ) -> BoxFuture<'_, Result<Option<i64>, StorageError>> {
        Box::pin(async move { PgAnalysisStore::latest_analysis_id(self, project_id, &branch).await })
    }

    fn save_coverage(
        &self,
        analysis_id: i64,
        summary: CoverageSummary,
    ) -> BoxFuture<'_, Result<(), StorageError>> {
        Box::pin(async move { CoverageStorage::save_coverage(self, analysis_id, summary).await })
    }

    fn latest_coverage(
        &self,
        project_key: String,
    ) -> BoxFuture<'_, Result<Option<CoverageResultSummary>, StorageError>> {
        Box::pin(async move { CoverageResultReader::latest_coverage(self, &project_key).await })
    }

    fn save_file_coverage_lines(
        &self,
        analysis_id: i64,
        files: Vec<FileCoverage>,
    ) -> BoxFuture<'_, Result<(), StorageError>> {
        Box::pin(async move {
            FileCoverageLineStorage::save_file_coverage_lines(self, analysis_id, &files).await
        })
    }

    fn file_coverage_lines(
        &self,
        project_key: String,
        branch: String,
        file: String,
    ) -> BoxFuture<'_, Result<Option<FileCoverageLines>, StorageError>> {
        Box::pin(async move {
            FileCoverageLineReader::file_coverage_lines(self, &project_key, &branch, &file).await
        })
    }

    fn measure_history(
        &self,
        project_key: String,
        branch: String,
        component: Option<String>,
        metric_keys: Vec<String>,
        from: Option<String>,
        to: Option<String>,
    ) -> BoxFuture<'_, Result<Vec<MeasureHistoryPoint>, StorageError>> {
        Box::pin(async move {
            MeasureHistoryReader::measure_history(
                self,
                &project_key,
                &branch,
                component.as_deref(),
                &metric_keys,
                from.as_deref(),
                to.as_deref(),
            )
            .await
        })
    }

    fn component_tree(
        &self,
        project_key: String,
        branch: String,
    ) -> BoxFuture<'_, Result<Option<ComponentTree>, StorageError>> {
        Box::pin(async move { ComponentTreeReader::component_tree(self, &project_key, &branch).await })
    }

    fn save_file_blame_lines(
        &self,
        analysis_id: i64,
        files: Vec<FileBlame>,
    ) -> BoxFuture<'_, Result<(), StorageError>> {
        Box::pin(async move { FileBlameLineStorage::save_file_blame_lines(self, analysis_id, &files).await })
    }

    fn file_blame_lines(
        &self,
        project_key: String,
        branch: String,
        file: String,
    ) -> BoxFuture<'_, Result<Option<FileBlameLines>, StorageError>> {
        Box::pin(async move {
            FileBlameLineReader::file_blame_lines(self, &project_key, &branch, &file).await
        })
    }
}

fn parse_format(raw: &str) -> Result<CoverageFormat, String> {
    match raw.to_ascii_lowercase().as_str() {
        "lcov" => Ok(CoverageFormat::Lcov),
        "cobertura" => Ok(CoverageFormat::Cobertura),
        "jacoco" => Ok(CoverageFormat::Jacoco),
        "llvm-cov" | "llvmcov" => Ok(CoverageFormat::LlvmCov),
        "istanbul" => Ok(CoverageFormat::Istanbul),
        other => {
            Err(format!("unknown format {other:?} (lcov|cobertura|jacoco|llvm-cov|istanbul)"))
        }
    }
}

fn default_branch() -> String {
    "main".to_string()
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct CoverageIngestQuery {
    /// Report format: lcov, cobertura, jacoco, llvm-cov, istanbul. Auto-detected from content when omitted.
    format: Option<String>,
    /// Branch of the analysis the coverage report attaches to (default "main").
    #[serde(default = "default_branch")]
    branch: String,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct CoverageSummaryDto {
    covered_lines: usize,
    coverable_lines: usize,
    covered_branches: usize,
    coverable_branches: usize,
    coverage_percent: Option<f64>,
    branch_coverage_percent: Option<f64>,
}

impl From<CoverageSummary> for CoverageSummaryDto {
    fn from(summary: CoverageSummary) -> Self {
        Self {
            covered_lines: summary.covered_lines(),
            coverable_lines: summary.coverable_lines(),
            covered_branches: summary.covered_branches(),
            coverable_branches: summary.coverable_branches(),
            coverage_percent: summary.percent(),
            branch_coverage_percent: summary.percent_branches(),
        }
    }
}

/// Ingest a coverage report (raw file content as the request body) against
/// a project's most recent analysis.
#[utoipa::path(
    post,
    path = "/api/projects/{key}/coverage",
    params(
        ("key" = String, Path, description = "Project key"),
        CoverageIngestQuery,
    ),
    request_body(
        content = String,
        description = "Raw coverage report content (LCOV, Cobertura, JaCoCo, llvm-cov or Istanbul)",
        content_type = "text/plain",
    ),
    responses(
        (status = 200, description = "Coverage ingested and persisted", body = CoverageSummaryDto),
        (status = 400, description = "Report could not be parsed"),
        (status = 404, description = "No analysis exists yet for this project/branch — run a scan first"),
        (status = 502, description = "Storage backend failure"),
    )
)]
pub(crate) async fn ingest_coverage(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    Query(query): Query<CoverageIngestQuery>,
    body: String,
) -> Result<Json<CoverageSummaryDto>, (StatusCode, String)> {
    let format =
        query.format.as_deref().map(parse_format).transpose().map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let report = yunq_infra_fs::parse_coverage_report(&body, format)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    let summary =
        report.summary().map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    let project_id = state
        .coverage
        .ensure_project(key)
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;
    let analysis_id = state
        .coverage
        .latest_analysis_id(project_id, query.branch)
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                "no analysis exists yet for this project/branch — run a scan first".to_string(),
            )
        })?;

    state
        .coverage
        .save_coverage(analysis_id, summary)
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;

    // Per-line detail alongside the summary above (issue #26): the sources
    // endpoint's coverage annotation needs line-level hit data, which the
    // summary alone can't provide. `report` already computed it — this
    // just keeps it instead of discarding it.
    state
        .coverage
        .save_file_coverage_lines(analysis_id, report.files().to_vec())
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;

    Ok(Json(CoverageSummaryDto::from(summary)))
}

/// The most recently persisted coverage summary for a project, if any
/// report has been ingested yet.
#[utoipa::path(
    get,
    path = "/api/projects/{key}/coverage",
    params(("key" = String, Path, description = "Project key")),
    responses(
        (status = 200, description = "Latest coverage summary", body = CoverageSummaryDto),
        (status = 404, description = "No coverage report ingested yet for this project"),
        (status = 502, description = "Storage backend failure"),
    )
)]
pub(crate) async fn latest_coverage(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
) -> Result<Json<CoverageSummaryDto>, (StatusCode, String)> {
    let result = state
        .coverage
        .latest_coverage(key)
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "no coverage report ingested yet".to_string()))?;
    Ok(Json(CoverageSummaryDto::from(result.summary)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_known_formats_case_insensitively() {
        assert!(matches!(parse_format("LCOV"), Ok(CoverageFormat::Lcov)));
        assert!(matches!(parse_format("cobertura"), Ok(CoverageFormat::Cobertura)));
        assert!(matches!(parse_format("JaCoCo"), Ok(CoverageFormat::Jacoco)));
        assert!(matches!(parse_format("llvm-cov"), Ok(CoverageFormat::LlvmCov)));
        assert!(matches!(parse_format("llvmcov"), Ok(CoverageFormat::LlvmCov)));
        assert!(matches!(parse_format("istanbul"), Ok(CoverageFormat::Istanbul)));
    }

    #[test]
    fn rejects_unknown_format() {
        assert!(parse_format("bogus").is_err());
    }

    #[test]
    fn dto_carries_derived_percentages() {
        let mut summary = CoverageSummary::default();
        summary.add(8, 10).unwrap();
        summary.add_branches(3, 4).unwrap();
        let dto = CoverageSummaryDto::from(summary);
        assert_eq!(dto.covered_lines, 8);
        assert_eq!(dto.coverable_lines, 10);
        assert_eq!(dto.coverage_percent, Some(80.0));
        assert_eq!(dto.branch_coverage_percent, Some(75.0));
    }
}
