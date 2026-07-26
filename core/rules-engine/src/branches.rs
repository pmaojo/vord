//! Branches and Pull Requests as first-class domain entities.
//!
//! ROADMAP §Phase 3 — every analysis attaches to (project, branch|PR).
//! New Code tracking flows through this entity; the AlmGateway reads from it.
//!
//! Skeleton: the type definitions and constructors are in place; the
//! Postgres-backed stores, HTTP routes and serialization live elsewhere and
//! will be wired in following iterations.

use serde::{Deserialize, Serialize};

/// A branch within a project. The `is_main` and `is_protected` flags are
/// data yunq needs (long-lived `main`, no force-push on `release/x`), not
/// Git's local file concept.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Branch {
    pub project_key: String,
    pub name: String,
    pub is_main: bool,
    pub is_protected: bool,
}

impl Branch {
    pub fn main(project_key: impl Into<String>) -> Self {
        Self { project_key: project_key.into(), name: "main".to_string(), is_main: true, is_protected: true }
    }

    pub fn feature(project_key: impl Into<String>, name: impl Into<String>) -> Self {
        Self { project_key: project_key.into(), name: name.into(), is_main: false, is_protected: false }
    }
}

/// A pull request identified by (provider, project_key, id). Provider is
/// the SCM slug (`github`, `gitlab`, `bitbucket`, `azure`).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PullRequest {
    pub project_key: String,
    pub id: String,
    pub provider: String,
    pub base_branch: String,
    pub head_branch: String,
    pub title: String,
}

/// Where an analysis was attached — the cross-cutting "what slice of code
/// are we looking at?" answer the rest of the platform reads.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BranchRef {
    Main,
    Branch(String),
    PullRequest { provider: String, id: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn main_branch_factory_marks_main_and_protected() {
        let b = Branch::main("yunq");
        assert_eq!(b.project_key, "yunq");
        assert_eq!(b.name, "main");
        assert!(b.is_main);
        assert!(b.is_protected);
    }

    #[test]
    fn feature_branch_factory_marks_non_main_and_unprotected() {
        let b = Branch::feature("yunq", "feat/new-thing");
        assert_eq!(b.name, "feat/new-thing");
        assert!(!b.is_main);
        assert!(!b.is_protected);
    }

    #[test]
    fn branch_ref_serializes_with_kind_tag() {
        let r = BranchRef::Branch("feat/foo".to_string());
        let json = serde_json::to_string(&r).expect("serializable");
        assert!(json.contains("branch"));
        assert!(json.contains("feat/foo"));

        let pr = BranchRef::PullRequest { provider: "github".to_string(), id: "42".to_string() };
        let json = serde_json::to_string(&pr).expect("serializable");
        assert!(json.contains("pull_request"));
        assert!(json.contains("github"));
        assert!(json.contains("42"));
    }

    #[test]
    fn pull_request_carries_base_and_head_branches() {
        let pr = PullRequest {
            project_key: "yunq".to_string(),
            id: "42".to_string(),
            provider: "github".to_string(),
            base_branch: "main".to_string(),
            head_branch: "feat/foo".to_string(),
            title: "Foo".to_string(),
        };
        assert_eq!(pr.base_branch, "main");
        assert_eq!(pr.head_branch, "feat/foo");
    }

    #[test]
    fn branch_equality_holds_for_same_data() {
        let a = Branch::feature("yunq", "feat/x");
        let b = Branch::feature("yunq", "feat/x");
        let c = Branch::feature("yunq", "feat/y");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
