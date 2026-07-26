//! AlmGateway — the cross-SCM abstraction over GitHub / GitLab / Bitbucket /
//! Azure DevOps. ROADMAP §Phase 5: "GitHub / GitLab / Bitbucket / Azure
//! DevOps behind the same `AlmGateway` port".
//!
//! Lives alongside the existing `alm` module (commit status reporters) —
//! the two share the SCM domain but answer different questions: status
//! reporters answer "did the last commit pass CI?" (server→SCM, no auth
//! gating), this module answers "post a PR decoration, open a check run"
//! (interactive, user-authenticated).
//!
//! Every provider implements these methods against its own REST API; the
//! rest of the platform only ever depends on this trait, never on a
//! provider-specific SDK.

use serde::{Deserialize, Serialize};

/// One inline review comment to post on a pull request. Coordinates are
/// in the SCM's own units (line numbers for GitHub-style, line+column for
/// Bitbucket).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InlineComment {
    pub path: String,
    pub line: u32,
    pub body: String,
}

/// One gate-evaluation result suitable for posting as a check run (GitHub)
/// or pipeline status (GitLab/Bitbucket/Azure).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckRunReport {
    pub name: String,
    pub conclusion: CheckConclusion,
    pub title: String,
    pub summary: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckConclusion {
    Success,
    Failure,
    Neutral,
}

/// One PR decoration request — bundle of comment + check + summary that
/// each gateway adapter translates into the SCM's native payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrDecoration {
    pub project_key: String,
    pub provider: String,
    pub repo: String,
    pub pr_id: String,
    pub comments: Vec<InlineComment>,
    pub check: Option<CheckRunReport>,
    pub summary: Option<String>,
}

/// Unified error across providers. Renamed from `AlmError` (which the
/// existing `alm` module owns for status reporters) — this one is for
/// gateway adapters. Callers pattern-match, never branch on provider.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AlmGatewayError {
    NotFound,
    Unauthorized,
    RateLimited { retry_after_ms: u64 },
    Conflict,
    ServerError { provider: String },
    Other { message: String },
}

impl std::fmt::Display for AlmGatewayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => f.write_str("not found"),
            Self::Unauthorized => f.write_str("unauthorized"),
            Self::RateLimited { retry_after_ms } => write!(f, "rate-limited (retry after {retry_after_ms} ms)"),
            Self::Conflict => f.write_str("conflict"),
            Self::ServerError { provider } => write!(f, "{provider} server error"),
            Self::Other { message } => write!(f, "{message}"),
        }
    }
}

impl std::error::Error for AlmGatewayError {}

/// The single trait every SCM provider implements. Object-safe by design
/// (no `where Self: Sized`, no generic methods) so callers can hold
/// `Box<dyn AlmGateway>`.
pub trait AlmGateway: Send + Sync {
    /// Post the entire decoration request as one logical operation. A
    /// failure to post a single comment must not roll back the others.
    fn decorate_pr(&self, decoration: PrDecoration) -> Result<DecorationReceipt, AlmGatewayError>;

    /// Update a check run (or create one if none exists yet). Returns the
    /// provider-assigned check id so subsequent updates can reference it.
    fn upsert_check_run(
        &self,
        project_key: String,
        repo: String,
        pr_id: String,
        report: CheckRunReport,
    ) -> Result<String, AlmGatewayError>;

    /// Provider name — `github`, `gitlab`, `bitbucket`, `azure`.
    fn name(&self) -> &'static str;
}

/// Confirmation that the decoration landed. Carries enough info for audit
/// log + UI display, regardless of provider.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecorationReceipt {
    pub posted_comments: usize,
    pub check_run_id: Option<String>,
    pub provider: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alm_gateway_is_object_safe() {
        fn _takes_dyn(_: &dyn AlmGateway) {}
        // If this compiles, the trait is object-safe.
    }

    #[test]
    fn alm_gateway_error_display_does_not_leak_provider_secrets() {
        let e = AlmGatewayError::RateLimited { retry_after_ms: 60_000 };
        assert_eq!(e.to_string(), "rate-limited (retry after 60000 ms)");

        let e = AlmGatewayError::ServerError { provider: "github".to_string() };
        assert_eq!(e.to_string(), "github server error");
    }

    #[test]
    fn inline_comment_carries_file_line_and_body() {
        let c = InlineComment {
            path: "src/auth.rs".to_string(),
            line: 42,
            body: "Use bcrypt".to_string(),
        };
        assert_eq!(c.path, "src/auth.rs");
        assert_eq!(c.line, 42);
        assert!(c.body.contains("bcrypt"));
    }

    #[test]
    fn check_conclusion_serializes_snake_case() {
        assert_eq!(serde_json::to_string(&CheckConclusion::Success).unwrap(), "\"success\"");
        assert_eq!(serde_json::to_string(&CheckConclusion::Failure).unwrap(), "\"failure\"");
        assert_eq!(serde_json::to_string(&CheckConclusion::Neutral).unwrap(), "\"neutral\"");
    }

    #[test]
    fn decoration_receipt_carries_provider_name() {
        let r = DecorationReceipt {
            posted_comments: 3,
            check_run_id: Some("check_123".to_string()),
            provider: "github".to_string(),
        };
        assert_eq!(r.posted_comments, 3);
        assert_eq!(r.check_run_id.as_deref(), Some("check_123"));
        assert_eq!(r.provider, "github");
    }

    #[test]
    fn pr_decoration_bundles_comments_check_and_summary() {
        let d = PrDecoration {
            project_key: "yunq".to_string(),
            provider: "github".to_string(),
            repo: "pmaojo/yunq".to_string(),
            pr_id: "42".to_string(),
            comments: vec![InlineComment { path: "src/main.rs".to_string(), line: 12, body: "Bug".to_string() }],
            check: Some(CheckRunReport {
                name: "yunq-quality-gate".to_string(),
                conclusion: CheckConclusion::Failure,
                title: "Quality gate failed".to_string(),
                summary: "3 blocker issues".to_string(),
            }),
            summary: Some("Blocker issue on src/main.rs:12".to_string()),
        };
        assert_eq!(d.comments.len(), 1);
        assert_eq!(d.check.unwrap().conclusion, CheckConclusion::Failure);
    }
}
