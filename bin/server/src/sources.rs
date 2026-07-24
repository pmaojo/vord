//! Line-level source annotations (issue #26): `GET
//! /api/projects/{key}/sources` returns, per line of one file, the issues
//! raised on it and its coverage hit count — mirrors SonarQube's
//! `api/sources/lines`, with two deliberate, documented scope cuts:
//!
//! - **No source line text.** yunq's server never persists checked-out
//!   source content — the worker analyzes a transient filesystem checkout
//!   it does not retain, and no component stores file bodies. Returning
//!   real text would need a wholly new persistence path (a source blob
//!   store) well beyond this slice; callers are expected to already have
//!   the file (e.g. a CI job's own checkout, or a client that fetches from
//!   its git host) and overlay these annotations onto it by line number.
//! - **No duplication or SCM blame annotation.** Duplication blocks
//!   (`yunq_cpd::DuplicateBlock`) exist only in-memory on `AnalysisReport`
//!   during a scan and are never persisted anywhere; persisting them would
//!   need its own migration/table, deferred rather than rushed into this
//!   slice's `0017` migration. Blame requires a `git blame`-equivalent
//!   capability that doesn't exist anywhere in this codebase today (checked
//!   `core/rules-engine/src/alm.rs` — ALM status reporting, not blame — and
//!   `infra/github`, which has none either); fabricating blame data instead
//!   of leaving it out was explicitly ruled out.
//!
//! Issues come from the existing global `issues` table (via `state.reader`,
//! the same port `GET /api/issues` uses), filtered to this file's exact
//! path — inheriting that table's existing, pre-existing-to-this-feature
//! limitation of having no project or branch column at all (see the
//! `analysis_measures` migration's doc comment for the same point). Two
//! projects that happen to share a file path would see each other's issues
//! here; fixing that is a schema change to `issues` far outside this
//! issue's scope. Coverage, by contrast, *is* correctly project/branch/file
//! scoped, since it rides on `analysis_file_coverage_lines` (new in this
//! change, scoped by `analysis_id` -> `project_id`).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use yunq_rules_engine::IssueQuery;

use crate::AppState;

fn default_branch() -> String {
    "main".to_string()
}

/// Issues table pages cap at 500 (`IssueQuery::normalized_page_size`); a
/// single file with more open issues than that only gets its first page
/// annotated. Acceptable for v1 — pagination on `sources` itself is a
/// straightforward follow-up if a file ever needs it.
const MAX_ISSUES_PER_FILE: usize = 500;

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct SourcesQuery {
    /// Exact file path to annotate (as recorded on `issues.file` / ingested
    /// coverage reports).
    file: String,
    /// Branch coverage is scoped to (default "main"). Issues are not
    /// branch-scoped in the current schema — see module docs.
    #[serde(default = "default_branch")]
    branch: String,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct SourceIssueDto {
    id: i64,
    rule: String,
    severity: String,
    message: String,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct SourceLineDto {
    /// 1-based line number.
    line: u32,
    issues: Vec<SourceIssueDto>,
    /// Times this line executed in the most recently ingested coverage
    /// report for this file/branch; absent when that line carries no
    /// coverage instrumentation data (or no report has been ingested at
    /// all — see `coverage_available`).
    coverage_hits: Option<usize>,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct SourcesDto {
    file: String,
    /// True once a coverage report has ever been ingested that instrumented
    /// this file — distinguishes "measured, zero hits anywhere" (every
    /// `coverage_hits` is `Some(0)`) from "never measured" (every line's
    /// `coverage_hits` is absent because this is `false`).
    coverage_available: bool,
    /// Only lines with at least one issue or coverage data point are
    /// present — this is an annotation overlay, not the full file (see
    /// module docs on why source text isn't returned).
    lines: Vec<SourceLineDto>,
}

/// Groups a page of issues by their 1-based start line, keeping only issues
/// on the exact file (the underlying `IssueQuery::file` filter is a
/// substring match, same as `GET /api/issues`, so this narrows it back to
/// an exact match for `sources`' single-file view).
fn issues_by_line(issues: &[yunq_rules_engine::StoredIssue], file: &str) -> BTreeMap<u32, Vec<SourceIssueDto>> {
    let mut by_line: BTreeMap<u32, Vec<SourceIssueDto>> = BTreeMap::new();
    for stored in issues.iter().filter(|s| s.issue.file() == file) {
        by_line.entry(stored.issue.span().start_line).or_default().push(SourceIssueDto {
            id: stored.id,
            rule: stored.issue.rule().to_string(),
            severity: stored.issue.severity().to_string(),
            message: stored.issue.message().to_string(),
        });
    }
    by_line
}

/// Merges per-line issues and per-line coverage hits into the sorted line
/// list the DTO carries — pure so the merge logic is unit-testable without
/// touching the network.
fn merge_lines(
    mut issues_by_line: BTreeMap<u32, Vec<SourceIssueDto>>,
    hits_by_line: &BTreeMap<u32, usize>,
) -> Vec<SourceLineDto> {
    let mut line_numbers: BTreeSet<u32> = issues_by_line.keys().copied().collect();
    line_numbers.extend(hits_by_line.keys().copied());

    line_numbers
        .into_iter()
        .map(|line| SourceLineDto {
            line,
            issues: issues_by_line.remove(&line).unwrap_or_default(),
            coverage_hits: hits_by_line.get(&line).copied(),
        })
        .collect()
}

/// Per-line issue and coverage annotations for one file — mirrors
/// SonarQube's `api/sources/lines`; see module docs for what's deliberately
/// out of scope (source text, duplication, blame).
#[utoipa::path(
    get,
    path = "/api/projects/{key}/sources",
    params(("key" = String, Path, description = "Project key"), SourcesQuery),
    responses(
        (status = 200, description = "Per-line issue/coverage annotations for the file", body = SourcesDto),
        (status = 502, description = "Storage backend failure"),
    )
)]
pub(crate) async fn sources(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    Query(query): Query<SourcesQuery>,
) -> Result<Json<SourcesDto>, (StatusCode, String)> {
    let issue_query =
        IssueQuery { file: Some(query.file.clone()), page_size: MAX_ISSUES_PER_FILE, ..Default::default() };
    let issues_page = state
        .reader
        .search_issues(&issue_query)
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;
    let by_line = issues_by_line(&issues_page.items, &query.file);

    let coverage = state
        .coverage
        .file_coverage_lines(key, query.branch, query.file.clone())
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;
    let coverage_available = coverage.is_some();
    let hits_by_line = coverage.map(|c| c.lines).unwrap_or_default();

    let lines = merge_lines(by_line, &hits_by_line);

    Ok(Json(SourcesDto { file: query.file, coverage_available, lines }))
}

#[cfg(test)]
mod tests {
    use yunq_ast::Span;
    use yunq_rules_engine::{Issue, RuleId, Severity, StoredIssue};

    use super::*;

    fn stored(id: i64, file: &str, line: u32, severity: Severity) -> StoredIssue {
        StoredIssue {
            id,
            issue: Issue::new(RuleId::new("owasp:x").unwrap(), severity, "boom", file, Span::new(line, 0, line, 1)),
        }
    }

    #[test]
    fn issues_by_line_filters_to_the_exact_file_and_groups_by_start_line() {
        let issues = vec![
            stored(1, "src/a.rs", 3, Severity::Major),
            stored(2, "src/a.rs", 3, Severity::Minor),
            stored(3, "src/aa.rs", 3, Severity::Blocker), // substring match, wrong file
            stored(4, "src/a.rs", 7, Severity::Info),
        ];
        let by_line = issues_by_line(&issues, "src/a.rs");
        assert_eq!(by_line.len(), 2);
        assert_eq!(by_line[&3].len(), 2);
        assert_eq!(by_line[&7].len(), 1);
    }

    #[test]
    fn issues_by_line_is_empty_without_matches() {
        let issues = vec![stored(1, "src/b.rs", 1, Severity::Major)];
        assert!(issues_by_line(&issues, "src/a.rs").is_empty());
    }

    #[test]
    fn merge_lines_unions_issue_and_coverage_line_numbers() {
        let mut issues_by_line = BTreeMap::new();
        issues_by_line.insert(
            3u32,
            vec![SourceIssueDto { id: 1, rule: "r".to_string(), severity: "major".to_string(), message: "m".to_string() }],
        );
        let mut hits_by_line = BTreeMap::new();
        hits_by_line.insert(3u32, 1usize);
        hits_by_line.insert(5u32, 0usize);

        let lines = merge_lines(issues_by_line, &hits_by_line);
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].line, 3);
        assert_eq!(lines[0].issues.len(), 1);
        assert_eq!(lines[0].coverage_hits, Some(1));
        assert_eq!(lines[1].line, 5);
        assert!(lines[1].issues.is_empty());
        assert_eq!(lines[1].coverage_hits, Some(0));
    }

    #[test]
    fn merge_lines_is_empty_with_no_issues_or_coverage() {
        assert!(merge_lines(BTreeMap::new(), &BTreeMap::new()).is_empty());
    }
}
