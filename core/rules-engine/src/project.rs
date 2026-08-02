//! Project topology: validated identities for projects, branches and pull
//! requests, and the New Code definition modes (Clean as You Code).

use std::fmt;

/// A validated project key, e.g. `my-org:payments-service`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ProjectKey(String);

#[derive(Debug, thiserror::Error)]
#[error("project key must be non-empty and use only [A-Za-z0-9 -_.:], got {0:?}")]
pub struct InvalidProjectKeyError(String);

impl ProjectKey {
    pub fn new(raw: &str) -> Result<Self, InvalidProjectKeyError> {
        let valid = !raw.is_empty()
            && raw
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "-_.:".contains(c));
        if valid {
            Ok(Self(raw.to_string()))
        } else {
            Err(InvalidProjectKeyError(raw.to_string()))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ProjectKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A validated git branch name (non-empty, no whitespace).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct BranchName(String);

#[derive(Debug, thiserror::Error)]
#[error("branch name must be non-empty without whitespace, got {0:?}")]
pub struct InvalidBranchNameError(String);

impl BranchName {
    pub fn new(raw: &str) -> Result<Self, InvalidBranchNameError> {
        if raw.is_empty() || raw.chars().any(char::is_whitespace) {
            return Err(InvalidBranchNameError(raw.to_string()));
        }
        Ok(Self(raw.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for BranchName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A validated pull-request number (strictly positive).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PullRequestNumber(u32);

#[derive(Debug, thiserror::Error)]
#[error("pull request number must be positive")]
pub struct InvalidPullRequestNumberError;

impl PullRequestNumber {
    pub fn new(raw: u32) -> Result<Self, InvalidPullRequestNumberError> {
        if raw == 0 {
            Err(InvalidPullRequestNumberError)
        } else {
            Ok(Self(raw))
        }
    }

    pub fn get(&self) -> u32 {
        self.0
    }
}

/// What an analysis is attached to: a long-lived branch, or a pull request
/// targeting one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AnalysisScope {
    Branch(BranchName),
    PullRequest {
        number: PullRequestNumber,
        target: BranchName,
    },
}

/// The full identity of one analysis: which project, on which scope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnalysisContext {
    project: ProjectKey,
    scope: AnalysisScope,
}

impl AnalysisContext {
    pub fn new(project: ProjectKey, scope: AnalysisScope) -> Self {
        Self { project, scope }
    }

    pub fn project(&self) -> &ProjectKey {
        &self.project
    }

    pub fn scope(&self) -> &AnalysisScope {
        &self.scope
    }
}

/// How the "new code" baseline is chosen for a project or branch — four
/// modes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NewCodeDefinition {
    /// New code is everything since the previous analysis.
    PreviousAnalysis,
    /// New code is everything from the last N days.
    NumberOfDays(u32),
    /// New code is the diff against a long-lived reference branch.
    ReferenceBranch(BranchName),
    /// New code is everything since an explicitly chosen analysis id.
    SpecificAnalysis(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_identities() {
        assert!(ProjectKey::new("my-org:payments.service_2").is_ok());
        assert!(ProjectKey::new("bad key").is_err());
        assert!(ProjectKey::new("").is_err());

        assert!(BranchName::new("feature/new-parser").is_ok());
        assert!(BranchName::new("has space").is_err());

        assert!(PullRequestNumber::new(42).is_ok());
        assert!(PullRequestNumber::new(0).is_err());
    }

    #[test]
    fn analysis_context_carries_scope() {
        let context = AnalysisContext::new(
            ProjectKey::new("vord").unwrap(),
            AnalysisScope::PullRequest {
                number: PullRequestNumber::new(7).unwrap(),
                target: BranchName::new("main").unwrap(),
            },
        );
        assert_eq!(context.project().as_str(), "vord");
        assert!(matches!(context.scope(), AnalysisScope::PullRequest { .. }));
    }
}
