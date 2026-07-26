//! HTTP surface for branches and pull requests — Phase 3.
//!
//! Skeleton: the request/response DTOs and validation helpers are in place;
//! the Postgres-backed stores and axum route wiring land in following
//! iterations.

use serde::{Deserialize, Serialize};
use yunq_rules_engine::branches::{Branch, PullRequest};

use crate::AppError;

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

/// `GET /api/projects/{key}/branches`
pub async fn list_branches(_project_key: String) -> Result<BranchListDto, AppError> {
    unimplemented!("list_branches: pull branches from PgIssueStorage once migration 0019 lands")
}

/// `GET /api/projects/{key}/pull_requests`
pub async fn list_pull_requests(_project_key: String) -> Result<PullRequestListDto, AppError> {
    unimplemented!("list_pull_requests: pull PRs from PgIssueStorage once migration 0019 lands")
}

/// `GET /api/projects/{key}/branches/{name}`
pub async fn get_branch(_project_key: String, _name: String) -> Result<Branch, AppError> {
    unimplemented!("get_branch: fetch one branch by name from storage")
}

/// `GET /api/projects/{key}/pull_requests/{provider}/{id}`
pub async fn get_pull_request(
    _project_key: String,
    _provider: String,
    _id: String,
) -> Result<PullRequest, AppError> {
    unimplemented!("get_pull_request: fetch one PR from storage")
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
