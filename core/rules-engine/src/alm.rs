//! ALM/SCM integration vocabulary: reporting analysis results back onto a
//! commit, regardless of which platform hosts it (GitHub today; the port is
//! the seam a GitLab/Bitbucket/Azure DevOps adapter would implement next).

use std::fmt;
use std::future::Future;

/// A validated git commit SHA: 7–40 lowercase hex characters (short or full).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CommitSha(String);

#[derive(Debug, thiserror::Error)]
#[error("commit sha must be 7-40 lowercase hex characters, got {0:?}")]
pub struct InvalidCommitShaError(String);

impl CommitSha {
    pub fn new(raw: &str) -> Result<Self, InvalidCommitShaError> {
        let valid = (7..=40).contains(&raw.len())
            && raw.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase());
        if valid { Ok(Self(raw.to_string())) } else { Err(InvalidCommitShaError(raw.to_string())) }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CommitSha {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The state of an analysis as reported on a commit — mirrors GitHub's
/// (and every other ALM's) commit-status vocabulary directly, so adapters
/// don't need to invent a mapping.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommitStatusState {
    Pending,
    Success,
    Failure,
    Error,
}

impl CommitStatusState {
    pub fn as_str(&self) -> &'static str {
        match self {
            CommitStatusState::Pending => "pending",
            CommitStatusState::Success => "success",
            CommitStatusState::Failure => "failure",
            CommitStatusState::Error => "error",
        }
    }
}

impl fmt::Display for CommitStatusState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One status report to attach to a commit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitStatus {
    pub state: CommitStatusState,
    pub description: String,
    /// Distinguishes this status from others on the same commit
    /// (CI, other bots, …) — shown as the status's label.
    pub context: String,
    /// Where "details" should link to, if anywhere.
    pub target_url: Option<String>,
}

impl CommitStatus {
    pub fn new(state: CommitStatusState, description: impl Into<String>) -> Self {
        Self { state, description: description.into(), context: "yunq".to_string(), target_url: None }
    }

    pub fn with_target_url(mut self, url: impl Into<String>) -> Self {
        self.target_url = Some(url.into());
        self
    }
}

#[derive(Debug, thiserror::Error)]
#[error("ALM backend failure: {0}")]
pub struct AlmError(pub String);

/// Outbound port: reports an analysis outcome back onto a commit on
/// whichever platform hosts it — the seam GitHub/GitLab/Bitbucket adapters
/// implement (`AlmGateway` in the roadmap).
pub trait AlmStatusReporter: Send + Sync {
    fn report_commit_status(
        &self,
        sha: &CommitSha,
        status: &CommitStatus,
    ) -> impl Future<Output = Result<(), AlmError>> + Send;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_commit_sha() {
        assert!(CommitSha::new("a1b2c3d").is_ok());
        assert!(CommitSha::new(&"f".repeat(40)).is_ok());
        assert!(CommitSha::new("short").is_err());
        assert!(CommitSha::new(&"a".repeat(41)).is_err());
        assert!(CommitSha::new("A1B2C3D").is_err());
        assert!(CommitSha::new("not-hex!").is_err());
    }

    #[test]
    fn status_builder_defaults_context_to_yunq() {
        let status = CommitStatus::new(CommitStatusState::Success, "gate passed");
        assert_eq!(status.context, "yunq");
        assert_eq!(status.state.as_str(), "success");
        assert!(status.target_url.is_none());
    }
}
