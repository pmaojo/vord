//! HTTP surface for portfolios — Phase 7.
//!
//! Skeleton: DTOs + validation + aggregator dispatch in place; storage and
//! axum route wiring land in following iterations.

use axum::Json;
use axum::extract::Path;
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use yunq_rules_engine::portfolios::{PortfolioNode, PortfolioRollup, ProjectRollupInput};

use crate::app_error::AppError;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PortfolioDto {
    pub id: String,
    pub name: String,
    pub children: Vec<PortfolioDto>,
}

impl From<&PortfolioNode> for PortfolioDto {
    fn from(node: &PortfolioNode) -> Self {
        Self {
            id: node.id.clone(),
            name: node.name.clone(),
            children: node.children.iter().map(Self::from).collect(),
        }
    }
}

/// `GET /api/portfolios/{id}/health`
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PortfolioHealthDto {
    pub portfolio_id: String,
    pub rollup: PortfolioRollup,
}

/// In-memory portfolio store behind a `Mutex` for handler access.
/// Full persistence requires a Postgres migration and PgIssueStorage integration.
use std::sync::Mutex;

static PORTFOLIO_STORE: std::sync::LazyLock<Mutex<Vec<PortfolioDto>>> =
    std::sync::LazyLock::new(|| Mutex::new(Vec::new()));

#[allow(dead_code)]
pub async fn list_portfolios() -> Result<Json<Vec<PortfolioDto>>, AppError> {
    let store = PORTFOLIO_STORE
        .lock()
        .map_err(|e| AppError::internal(e.to_string()))?;
    Ok(Json(store.clone()))
}

#[allow(dead_code)]
pub async fn get_portfolio(Path(id): Path<String>) -> Result<Json<PortfolioDto>, AppError> {
    let store = PORTFOLIO_STORE
        .lock()
        .map_err(|e| AppError::internal(e.to_string()))?;
    let node = store
        .iter()
        .find(|p| p.id == id)
        .ok_or_else(|| AppError::not_found(format!("portfolio {id}")))?;
    Ok(Json(node.clone()))
}

#[allow(dead_code)]
pub async fn create_portfolio(
    Json(dto): Json<PortfolioDto>,
) -> Result<(StatusCode, Json<PortfolioDto>), AppError> {
    let mut store = PORTFOLIO_STORE
        .lock()
        .map_err(|e| AppError::internal(e.to_string()))?;
    if store.iter().any(|p| p.id == dto.id) {
        return Err(AppError::bad_request(format!(
            "portfolio '{}' already exists",
            dto.id
        )));
    }
    store.push(dto.clone());
    Ok((StatusCode::CREATED, Json(dto)))
}

/// Executive view: aggregated rollup across the whole tree. The HTTP
/// handler fetches the tree, flattens to leaves, joins each leaf to the
/// latest per-project rollup inputs, then calls `PortfolioRollup::worst_of`.
pub fn rollup_for(tree: &PortfolioNode, inputs: &[ProjectRollupInput]) -> PortfolioRollup {
    let leaves = PortfolioRollup::flatten_projects(tree);
    let leaf_ids: Vec<&str> = leaves.iter().map(|n| n.id.as_str()).collect();
    let filtered: Vec<ProjectRollupInput> = inputs
        .iter()
        .filter(|i| leaf_ids.contains(&i.project_id.as_str()))
        .cloned()
        .collect();
    let mut rollup = PortfolioRollup::worst_of(&filtered);
    rollup.node_id = tree.id.clone();
    rollup
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(id: &str) -> PortfolioNode {
        PortfolioNode {
            id: id.to_string(),
            name: id.to_string(),
            children: vec![],
        }
    }

    #[test]
    fn portfolio_dto_round_trips_through_json() {
        let tree = PortfolioNode {
            id: "root".to_string(),
            name: "All yunq".to_string(),
            children: vec![leaf("yunq-core")],
        };
        let dto = PortfolioDto::from(&tree);
        let json = serde_json::to_string(&dto).expect("serializable");
        assert!(json.contains("All yunq"));
        assert!(json.contains("yunq-core"));
    }

    #[test]
    fn rollup_for_filters_inputs_to_tree_leaves() {
        let tree = PortfolioNode {
            id: "p1".to_string(),
            name: "p1".to_string(),
            children: vec![leaf("a"), leaf("b")],
        };
        let inputs = vec![
            ProjectRollupInput {
                project_id: "a".to_string(),
                reliability_rating: 1.0,
                security_rating: 1.0,
                maintainability_rating: 1.0,
                bug_total: 1,
                vulnerability_total: 1,
                code_smell_total: 1,
            },
            ProjectRollupInput {
                project_id: "b".to_string(),
                reliability_rating: 4.0,
                security_rating: 5.0,
                maintainability_rating: 3.0,
                bug_total: 10,
                vulnerability_total: 10,
                code_smell_total: 10,
            },
            ProjectRollupInput {
                project_id: "not_in_tree".to_string(),
                reliability_rating: 5.0,
                security_rating: 5.0,
                maintainability_rating: 5.0,
                bug_total: 999,
                vulnerability_total: 999,
                code_smell_total: 999,
            },
        ];
        let r = rollup_for(&tree, &inputs);
        assert_eq!(r.node_id, "p1");
        assert_eq!(r.project_count, 2);
        assert_eq!(r.bug_total, 11);
        assert_eq!(r.reliability_rating, 4.0);
        // the "not_in_tree" project with rating 5 must NOT count
        assert_eq!(r.security_rating, 5.0); // b contributes 5.0 — equal to not_in_tree but excluded
        assert_eq!(r.vulnerability_total, 11); // 1 + 10, not 1 + 10 + 999
    }
}
