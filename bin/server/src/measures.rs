//! Measure history and component-tree navigation (issue #26): SonarQube-style
//! `api/measures/search_history` and `api/components/tree`, over the
//! `analysis_measures` rows persisted per analysis by `bin/worker`
//! (`MeasureStorage::save_measures`, called from `persist_gate_result`).
//!
//! `GET /api/projects/{key}/measures/history` returns one metric (or every
//! persisted metric) as a time series across the project's — or, with
//! `component`, one of its files' — analyses.
//!
//! `GET /api/projects/{key}/components/tree` returns the project's known
//! files (a **flat list, not a nested directory tree**) with their latest
//! measures as of the most recent analysis, sortable/filterable in the
//! SonarQube style. Scoped down from a real nested tree deliberately: the
//! persisted data is a flat `(analysis_id, file, metric, value)` table with
//! no notion of directories, and building one on the fly from file paths
//! would be presentation logic with no server-side test value beyond a
//! string split — better done client-side if/when a real tree UI needs it.
//! A flat, correctly project/analysis-scoped file list is the honest v1
//! here (see the module docs on `analysis_measures` in migration `0017` for
//! why "project/analysis-scoped" specifically mattered: the existing
//! `issues` table has no project linkage at all, so it could not have been
//! the source of a safe per-project file list).

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use yunq_rules_engine::ComponentMeasures;

use crate::AppState;

fn default_branch() -> String {
    "main".to_string()
}

/// Splits a comma-separated `metrics=coverage,issue_total` query value into
/// trimmed, non-empty keys. Empty/absent input means "every persisted
/// metric" (the storage layer treats an empty key list as no filter).
fn parse_metric_keys(raw: Option<&str>) -> Vec<String> {
    raw.map(|raw| raw.split(',').map(str::trim).filter(|s| !s.is_empty()).map(String::from).collect())
        .unwrap_or_default()
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct MeasureHistoryQuery {
    /// Branch the history is scoped to (default "main").
    #[serde(default = "default_branch")]
    branch: String,
    /// File path to scope the history to one file's measures instead of
    /// the project as a whole.
    component: Option<String>,
    /// Comma-separated metric keys, e.g. `coverage,issue_total` (default:
    /// every metric persisted for that analysis).
    metrics: Option<String>,
    /// Inclusive lower bound, ISO-8601 (e.g. `2024-01-01T00:00:00Z`).
    from: Option<String>,
    /// Inclusive upper bound, ISO-8601.
    to: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct MeasureValueDto {
    metric: String,
    value: f64,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct MeasureHistoryPointDto {
    analysis_id: i64,
    /// ISO-8601 timestamp of the analysis this point belongs to.
    date: String,
    measures: Vec<MeasureValueDto>,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct MeasureHistoryDto {
    /// The project key, or `{project key}:{file path}` when `component`
    /// was given in the request.
    component: String,
    history: Vec<MeasureHistoryPointDto>,
}

fn component_label(project_key: &str, component: Option<&str>) -> String {
    match component {
        Some(path) => format!("{project_key}:{path}"),
        None => project_key.to_string(),
    }
}

/// Time series of a project's (or one of its files') measures across its
/// analyses — mirrors SonarQube's `api/measures/search_history`.
#[utoipa::path(
    get,
    path = "/api/projects/{key}/measures/history",
    params(("key" = String, Path, description = "Project key"), MeasureHistoryQuery),
    responses(
        (status = 200, description = "Measure time series, oldest analysis first", body = MeasureHistoryDto),
        (status = 502, description = "Storage backend failure"),
    )
)]
pub(crate) async fn measure_history(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    Query(query): Query<MeasureHistoryQuery>,
) -> Result<Json<MeasureHistoryDto>, (StatusCode, String)> {
    let metric_keys = parse_metric_keys(query.metrics.as_deref());
    let label = component_label(&key, query.component.as_deref());

    let points = state
        .coverage
        .measure_history(key, query.branch, query.component, metric_keys, query.from, query.to)
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;

    let history = points
        .into_iter()
        .map(|point| MeasureHistoryPointDto {
            analysis_id: point.analysis_id,
            date: point.date,
            measures: point
                .values
                .into_iter()
                .map(|(metric, value)| MeasureValueDto { metric, value })
                .collect(),
        })
        .collect();

    Ok(Json(MeasureHistoryDto { component: label, history }))
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct ComponentTreeQuery {
    /// Branch the tree is scoped to (default "main").
    #[serde(default = "default_branch")]
    branch: String,
    /// Sort field: `name` or a measure key present on the components, e.g.
    /// `issue_total` (default "name").
    #[serde(default = "default_sort")]
    sort: String,
    /// Sort direction: `asc` or `desc` (default "asc").
    #[serde(default = "default_direction")]
    direction: String,
    /// Case-sensitive substring filter on file path.
    q: Option<String>,
}

fn default_sort() -> String {
    "name".to_string()
}

fn default_direction() -> String {
    "asc".to_string()
}

#[derive(Serialize, ToSchema)]
pub(crate) struct ComponentDto {
    path: String,
    measures: Vec<MeasureValueDto>,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct ComponentTreeDto {
    analysis_id: i64,
    total: usize,
    components: Vec<ComponentDto>,
}

/// Filters components to those whose path contains `q` (a no-op when `q`
/// is absent).
fn filter_components(components: Vec<ComponentMeasures>, q: Option<&str>) -> Vec<ComponentMeasures> {
    match q {
        Some(needle) if !needle.is_empty() => {
            components.into_iter().filter(|c| c.path.contains(needle)).collect()
        }
        _ => components,
    }
}

/// Sorts by path (`"name"`) or by a named measure's value (any other sort
/// key, e.g. `"issue_total"` — components without that measure sort as if
/// it were `0.0`, last among equals rather than erroring, since "this file
/// has no issues" and "this file was never measured for X" are both
/// legitimately representable as absence). Reverses the whole ordering for
/// `descending`.
fn sort_components(mut components: Vec<ComponentMeasures>, sort: &str, descending: bool) -> Vec<ComponentMeasures> {
    if sort == "name" {
        components.sort_by(|a, b| a.path.cmp(&b.path));
    } else {
        components.sort_by(|a, b| {
            let a_value = a.measures.get(sort).copied().unwrap_or(0.0);
            let b_value = b.measures.get(sort).copied().unwrap_or(0.0);
            a_value.partial_cmp(&b_value).unwrap_or(std::cmp::Ordering::Equal)
        });
    }
    if descending {
        components.reverse();
    }
    components
}

/// A project's components (currently: files only — see module docs) with
/// their latest measures, as of the most recent analysis — mirrors
/// SonarQube's `api/components/tree` navigation, minus directory nesting.
#[utoipa::path(
    get,
    path = "/api/projects/{key}/components/tree",
    params(("key" = String, Path, description = "Project key"), ComponentTreeQuery),
    responses(
        (status = 200, description = "The project's known files with their latest measures", body = ComponentTreeDto),
        (status = 404, description = "No analysis exists yet for this project/branch — run a scan first"),
        (status = 502, description = "Storage backend failure"),
    )
)]
pub(crate) async fn component_tree(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    Query(query): Query<ComponentTreeQuery>,
) -> Result<Json<ComponentTreeDto>, (StatusCode, String)> {
    let tree = state
        .coverage
        .component_tree(key, query.branch)
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?
        .ok_or_else(|| {
            (StatusCode::NOT_FOUND, "no analysis exists yet for this project/branch".to_string())
        })?;

    let components = filter_components(tree.components, query.q.as_deref());
    let descending = query.direction.eq_ignore_ascii_case("desc");
    let components = sort_components(components, &query.sort, descending);

    let total = components.len();
    let components = components
        .into_iter()
        .map(|c| ComponentDto {
            path: c.path,
            measures: c.measures.into_iter().map(|(metric, value)| MeasureValueDto { metric, value }).collect(),
        })
        .collect();

    Ok(Json(ComponentTreeDto { analysis_id: tree.analysis_id, total, components }))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    fn component(path: &str, issue_total: f64) -> ComponentMeasures {
        let mut measures = BTreeMap::new();
        measures.insert("issue_total".to_string(), issue_total);
        ComponentMeasures { path: path.to_string(), measures }
    }

    #[test]
    fn parse_metric_keys_splits_trims_and_drops_empties() {
        assert_eq!(parse_metric_keys(Some(" coverage, issue_total ,,")), vec!["coverage", "issue_total"]);
        assert_eq!(parse_metric_keys(None), Vec::<String>::new());
        assert_eq!(parse_metric_keys(Some("")), Vec::<String>::new());
    }

    #[test]
    fn component_label_includes_the_file_only_when_given() {
        assert_eq!(component_label("proj", None), "proj");
        assert_eq!(component_label("proj", Some("src/a.rs")), "proj:src/a.rs");
    }

    #[test]
    fn filter_components_keeps_only_matching_paths() {
        let components = vec![component("src/a.rs", 1.0), component("src/b.rs", 2.0)];
        let filtered = filter_components(components, Some("a.rs"));
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].path, "src/a.rs");
    }

    #[test]
    fn filter_components_is_a_no_op_without_a_query() {
        let components = vec![component("src/a.rs", 1.0), component("src/b.rs", 2.0)];
        assert_eq!(filter_components(components.clone(), None).len(), 2);
        assert_eq!(filter_components(components, Some("")).len(), 2);
    }

    #[test]
    fn sort_components_by_name_ascending_and_descending() {
        let components = vec![component("b.rs", 1.0), component("a.rs", 2.0)];
        let sorted = sort_components(components.clone(), "name", false);
        assert_eq!(sorted[0].path, "a.rs");
        let sorted = sort_components(components, "name", true);
        assert_eq!(sorted[0].path, "b.rs");
    }

    #[test]
    fn sort_components_by_measure_value() {
        let components = vec![component("a.rs", 5.0), component("b.rs", 1.0)];
        let sorted = sort_components(components, "issue_total", false);
        assert_eq!(sorted[0].path, "b.rs");
        assert_eq!(sorted[1].path, "a.rs");
    }

    #[test]
    fn sort_components_treats_a_missing_measure_as_zero() {
        let mut with_measure = component("a.rs", 3.0);
        let without_measure = ComponentMeasures { path: "b.rs".to_string(), measures: BTreeMap::new() };
        with_measure.measures.insert("coverage".to_string(), 90.0);
        let components = vec![with_measure, without_measure];
        let sorted = sort_components(components, "coverage", false);
        assert_eq!(sorted[0].path, "b.rs");
        assert_eq!(sorted[1].path, "a.rs");
    }
}
