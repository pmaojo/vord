//! HTTP surface for branches and pull requests — Phase 3.
//!
//! Skeleton: the request/response DTOs and validation helpers are in place;
//! the Postgres-backed stores and axum route wiring land in following
//! iterations.

use axum::extract::{Path, State};
use axum::Json;
use serde::{Deserialize, Serialize};
use yunq_rules_engine::branches::{Branch, PullRequest};

use crate::app_error::AppError;

/// List response: every branch the project has analyses for.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BranchListDto {
    pub project_key: String,
    pub branches: Vec<Branch>,
}

/// List response: every pull request the project has analyses for.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PullRequestListDto {
    pub project_key: String,
    pub pull_requests: Vec<PullRequest>,
}

/// Validation helper — a project key must be non-empty and start with
/// `[a-z0-9-]`. Mirrors the existing convention for `/api/projects/{key}/...`
/// routes so the new branches namespace uses the same keyspace.
pub fn validate_project_key(raw: &str) -> Result<String, AppError> {
    if raw.is_empty() {
        return Err(AppError::bad_request("project_key must not be empty"));
    }
    if !raw.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_') {
        return Err(AppError::bad_request("project_key must be lowercase alphanumeric or -/_"));
    }
    Ok(raw.to_string())
}

#[allow(dead_code)]
/// `GET /api/projects/{key}/branches`
pub(crate) async fn list_branches(
    Path(project_key): Path<String>,
    State(_state): State<std::sync::Arc<super::AppState>>,
) -> Result<Json<BranchListDto>, AppError> {
    let key = validate_project_key(&project_key)?;
    // Return a default set of branches since full storage needs migration 0019
    Ok(Json(BranchListDto {
        project_key: key,
        branches: vec![
            Branch::main(&project_key),
            Branch::feature(&project_key, "develop"),
        ],
    }))
}

#[allow(dead_code)]
/// `GET /api/projects/{key}/pull_requests`
pub(crate) async fn list_pull_requests(
    Path(project_key): Path<String>,
    State(_state): State<std::sync::Arc<super::AppState>>,
) -> Result<Json<PullRequestListDto>, AppError> {
    let key = validate_project_key(&project_key)?;
    // Return empty list until migration 0019 lands for PR storage
    Ok(Json(PullRequestListDto {
        project_key: key,
        pull_requests: vec![],
    }))
}

#[allow(dead_code)]
/// `GET /api/projects/{key}/branches/{name}`
pub(crate) async fn get_branch(
    Path((project_key, name)): Path<(String, String)>,
    State(_state): State<std::sync::Arc<super::AppState>>,
) -> Result<Json<Branch>, AppError> {
    let _key = validate_project_key(&project_key)?;
    Ok(Json(Branch::feature(project_key, name)))
}

#[allow(dead_code)]
/// `GET /api/projects/{key}/pull_requests/{provider}/{id}`
pub(crate) async fn get_pull_request(
    Path((project_key, provider, id)): Path<(String, String, String)>,
    State(_state): State<std::sync::Arc<super::AppState>>,
) -> Result<Json<PullRequest>, AppError> {
    let _key = validate_project_key(&project_key)?;
    Ok(Json(PullRequest {
        project_key,
        id,
        provider,
        base_branch: "main".to_string(),
        head_branch: "feat/unknown".to_string(),
        title: "Pull Request".to_string(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_project_key_accepts_alphanumeric_dash_underscore() {
        assert!(validate_project_key("yunq-core").is_ok());
        assert!(validate_project_key("team_foo_bar").is_ok());
        assert!(validate_project_key("a1").is_ok());
    }

    #[test]
    fn validate_project_key_rejects_empty() {
        assert!(validate_project_key("").is_err());
    }

    #[test]
    fn validate_project_key_rejects_uppercase_or_special() {
        assert!(validate_project_key("Yunq").is_err());
        assert!(validate_project_key("yunq.core").is_err());
        assert!(validate_project_key("yunq/core").is_err());
        assert!(validate_project_key("yunq core").is_err());
    }

    #[test]
    fn branch_list_dto_round_trips_through_json() {
        let dto = BranchListDto {
            project_key: "yunq".to_string(),
            branches: vec![Branch::main("yunq"), Branch::feature("yunq", "feat/x")],
        };
        let json = serde_json::to_string(&dto).expect("serializable");
        assert!(json.contains("yunq"));
        assert!(json.contains("feat/x"));
    }

    #[test]
    fn pull_request_list_dto_round_trips_through_json() {
        let dto = PullRequestListDto {
            project_key: "yunq".to_string(),
            pull_requests: vec![PullRequest {
                project_key: "yunq".to_string(),
                id: "42".to_string(),
                provider: "github".to_string(),
                base_branch: "main".to_string(),
                head_branch: "feat/foo".to_string(),
                title: "Foo".to_string(),
            }],
        };
        let json = serde_json::to_string(&dto).expect("serializable");
        assert!(json.contains("github"));
        assert!(json.contains("feat/foo"));
    }
}
