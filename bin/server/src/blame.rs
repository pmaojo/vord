//! SCM blame ingestion (issue #26's now-unblocked follow-up to #33):
//! `POST /api/projects/{key}/blame` accepts exactly the JSON the CLI's
//! `--blame-output` writes (`bin/cli/src/blame.rs`) — a map of file path to
//! an ordered list of per-line blame — and persists it against a project's
//! most recent analysis, the same "attach to the latest scan" relationship
//! `ingest_coverage` already uses. The `sources` endpoint reads it back to
//! annotate lines with who last touched them.
//!
//! No new capture mechanism here: the CLI already computes this via
//! `git blame --porcelain`. This is just a place to put what it computes so
//! a CI job can upload it the same way it uploads a coverage report.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use utoipa::{IntoParams, ToSchema};
use yunq_rules_engine::{BlameLineInfo, FileBlame};

use crate::AppState;

fn default_branch() -> String {
    "main".to_string()
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct BlameIngestQuery {
    /// Branch of the analysis the blame data attaches to (default "main").
    #[serde(default = "default_branch")]
    branch: String,
}

/// One line's blame as the CLI's `--blame-output` JSON encodes it — field
/// names match `blame::BlameLine` exactly so that file can be POSTed as-is.
#[derive(Deserialize, ToSchema)]
pub(crate) struct BlameLineInput {
    line: u32,
    commit: String,
    author: String,
    author_mail: String,
    author_time: i64,
    summary: String,
}

/// Ingest per-line SCM blame (the CLI's `--blame-output` JSON, unmodified)
/// against a project's most recent analysis.
#[utoipa::path(
    post,
    path = "/api/projects/{key}/blame",
    params(("key" = String, Path, description = "Project key"), BlameIngestQuery),
    request_body(
        content = BTreeMap<String, Vec<BlameLineInput>>,
        description = "The CLI's `--blame-output` JSON: file path -> ordered per-line blame",
    ),
    responses(
        (status = 200, description = "Blame ingested and persisted"),
        (status = 404, description = "No analysis exists yet for this project/branch — run a scan first"),
        (status = 502, description = "Storage backend failure"),
    )
)]
pub(crate) async fn ingest_blame(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    Query(query): Query<BlameIngestQuery>,
    Json(body): Json<BTreeMap<String, Vec<BlameLineInput>>>,
) -> Result<StatusCode, (StatusCode, String)> {
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

    let files: Vec<FileBlame> = body
        .into_iter()
        .map(|(path, blame_lines)| {
            let mut file = FileBlame::new(path);
            for input in blame_lines {
                file.record_line(
                    input.line,
                    BlameLineInfo {
                        commit: input.commit,
                        author: input.author,
                        author_mail: input.author_mail,
                        author_time: input.author_time,
                        summary: input.summary,
                    },
                );
            }
            file
        })
        .collect();

    state
        .coverage
        .save_file_blame_lines(analysis_id, files)
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;

    Ok(StatusCode::OK)
}
