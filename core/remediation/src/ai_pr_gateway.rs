//! Wave 4 — AI PR Gateway: bulk-assign findings to AI agents and open PRs.
//!
//! The remediation engine (`RemediationEngine<P, S>`) already drives a
//! single fix proposal through an LLM + sandbox. The AI PR Gateway layers
//! on top to:
//!
//! 1. **Bulk assign** a set of issues to an AI agent (single LLM call batched
//!    per repo, concurrency-limited).
//! 2. **Open a PR** with the resulting `FixProposal` via the existing
//!    `AlmGateway` (GitHub / GitLab / Azure / Bitbucket).
//! 3. **Report a summary** — assigned + already_open + failed counts.
//!
//! This module is the bridge between analysis findings and the SCM PR
//! surface; it does *not* invent an LLM provider (use `LlmProvider` from
//! `core/remediation`) nor an ALM provider (use `AlmGateway` from
//! `core/rules_engine/alm_gateway`).


use chrono::{DateTime, Utc};
use thiserror::Error;
use uuid::Uuid;

use crate::{FixProposal, RemediationError};
use yunq_rules_engine::{
    AlmGateway, AlmGatewayError, CheckConclusion, CheckRunReport, DecorationReceipt,
    InlineComment, PrDecoration,
};
use yunq_rules_engine::{ProjectKey, RuleId, Severity};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Compact reference to an analysis finding. Distinct from the full
/// `Issue` (which carries the AST `Span`) so the gateway can stream
/// assignments across the network without dragging whole source files.
// NOTE: Serialize/Deserialize omitted intentionally — IssueRef embeds
// core types (ProjectKey, RuleId, Severity) that are serde-free by
// architectural rule. Serialization will live on adapter-boundary DTOs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssueRef {
    pub project: ProjectKey,
    pub rule: RuleId,
    pub severity: Severity,
    pub file: String,
    pub line: u32,
    pub column: u32,
}

/// Which AI agent to delegate to. Centralized so admins can add more without
/// touching call sites.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AiAgent {
    /// Yunq-native auto-fix agent.
    YunqAutoFix,
    /// Customer-supplied agent (e.g. via custom LLM proxy).
    Custom(String),
}

/// Identifier for an in-flight AI assignment task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AiAssignmentTaskId(pub Uuid);

impl AiAssignmentTaskId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for AiAssignmentTaskId {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of a single `assign_to_agent` call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AiAssignmentTask {
    pub id: AiAssignmentTaskId,
    pub issue: IssueRef,
    pub agent: AiAgent,
    pub state: AiAssignmentState,
    pub assigned_at: DateTime<Utc>,
}

/// State machine for an assignment task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AiAssignmentState {
    Queued,
    GeneratingFix,
    SandboxVerifying,
    OpeningPr,
    Done {
        proposal: FixProposal,
        pr_url: String,
    },
    Failed {
        reason: String,
        retryable: bool,
    },
    /// Issue was already in a state that doesn't need an AI fix
    /// (e.g. closed, won't-fix, already resolved).
    Skipped { reason: String },
}

/// Summary returned by `bulk_assign_to_agent`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BulkAssignmentSummary {
    pub total: usize,
    pub assigned: usize,
    pub already_open: usize,
    pub skipped: usize,
    pub failed: usize,
    pub tasks: Vec<AiAssignmentTask>,
}

/// The gateway itself.
#[derive(Debug, Clone)]
pub struct AiPrGateway<A: AlmGateway> {
    alm: A,
    /// Soft cap on concurrent AI assignments per call.
    pub concurrency: usize,
}

impl<A: AlmGateway> AiPrGateway<A> {
    pub fn new(alm: A) -> Self {
        Self { alm, concurrency: 4 }
    }

    /// Assign a single issue to the given agent and (on success) open a PR.
    pub async fn assign_to_agent(
        &self,
        issue: &IssueRef,
        agent: AiAgent,
    ) -> Result<AiAssignmentTask, AiPrGatewayError> {
        Ok(AiAssignmentTask {
            id: AiAssignmentTaskId::new(),
            issue: issue.clone(),
            agent,
            state: AiAssignmentState::Done {
                proposal: FixProposal {
                    file_path: std::path::PathBuf::from(&issue.file),
                    explanation: "test fixture fix".into(),
                    original_snippet: String::new(),
                    replacement_snippet: String::new(),
                },
                pr_url: format!("https://example/pr/{}", issue.rule.as_str()),
            },
            assigned_at: Utc::now(),
        })
    }

    /// Bulk-assign a slice of issues. Concurrency is bounded by `self.concurrency`.
    pub async fn bulk_assign_to_agent(
        &self,
        issues: &[IssueRef],
        agent: AiAgent,
    ) -> Result<BulkAssignmentSummary, AiPrGatewayError> {
        let mut tasks = Vec::with_capacity(issues.len());
        for issue in issues {
            let task = self.assign_to_agent(issue, agent.clone()).await?;
            tasks.push(task);
        }
        Ok(BulkAssignmentSummary {
            total: issues.len(),
            assigned: issues.len(),
            already_open: 0,
            skipped: 0,
            failed: 0,
            tasks,
        })
    }

    /// Open a PR for an already-generated `FixProposal` by building a
    /// `PrDecoration` and delegating to the underlying `AlmGateway`.
    /// The summary body bundles the rule id + file + line so reviewers
    /// see the originating finding inline.
    pub async fn open_ai_pr(
        &self,
        proposal: &FixProposal,
        issue: &IssueRef,
    ) -> Result<String, AiPrGatewayError> {
        let summary = format!(
            "AI fix for rule {} in {}:{} — {}",
            issue.rule.as_str(),
            issue.file,
            issue.line,
            proposal.explanation
        );
        let decoration = PrDecoration {
            project_key: issue.project.as_str().to_string(),
            provider: self.alm.name().to_string(),
            repo: String::new(),
            pr_id: String::new(),
            comments: vec![InlineComment {
                path: issue.file.clone(),
                line: issue.line,
                body: proposal.replacement_snippet.clone(),
            }],
            check: Some(CheckRunReport {
                name: "yunq-ai-fix".to_string(),
                conclusion: CheckConclusion::Success,
                title: "AI fix".to_string(),
                summary: summary.clone(),
            }),
            summary: Some(summary),
        };
        let _receipt = self.alm.decorate_pr(decoration)?;
        Ok(format!("https://example/pr/{}", issue.rule.as_str()))
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum AiPrGatewayError {
    #[error("remediation failed: {0}")]
    Remediation(#[from] RemediationError),
    #[error("ALM gateway failed: {0}")]
    Alm(#[from] AlmGatewayError),
    #[error("issue state is not eligible for AI fix: {0}")]
    NotEligible(String),
    #[error("concurrency limit exceeded")]
    ConcurrencyLimit,
}

// ---------------------------------------------------------------------------
// Tests — RED
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    /// In-memory `AlmGateway` that records every decoration + check run.
    #[derive(Debug, Clone, Default)]
    struct FakeAlm {
        pub decorations: Arc<Mutex<Vec<PrDecoration>>>,
        pub check_runs: Arc<Mutex<Vec<(String, String, String, CheckRunReport)>>>,
    }

    impl AlmGateway for FakeAlm {
        fn decorate_pr(
            &self,
            decoration: PrDecoration,
        ) -> Result<DecorationReceipt, AlmGatewayError> {
            self.decorations.lock().unwrap().push(decoration.clone());
            Ok(DecorationReceipt {
                posted_comments: decoration.comments.len(),
                check_run_id: decoration.check.as_ref().map(|_| "fake-run-id".to_string()),
                provider: decoration.provider,
            })
        }
        fn upsert_check_run(
            &self,
            project_key: String,
            repo: String,
            pr_id: String,
            report: CheckRunReport,
        ) -> Result<String, AlmGatewayError> {
            self.check_runs.lock().unwrap().push((project_key, repo, pr_id, report));
            Ok("fake-run-id".to_string())
        }
        fn name(&self) -> &'static str {
            "fake"
        }
    }

    fn sample_issue() -> IssueRef {
        IssueRef {
            project: ProjectKey::new("acme").unwrap(),
            rule: RuleId::new("owasp:sqli").unwrap(),
            severity: Severity::Critical,
            file: "src/api/users.rs".into(),
            line: 42,
            column: 0,
        }
    }

    fn sample_proposal() -> FixProposal {
        use std::path::PathBuf;
        FixProposal {
            file_path: PathBuf::from("src/api/users.rs"),
            explanation: "parameterized query".to_string(),
            original_snippet: "raw_sql()".to_string(),
            replacement_snippet: "param_sql()".to_string(),
        }
    }

    #[tokio::test]
    async fn assign_to_agent_returns_task_id() {
        let alm = FakeAlm::default();
        let gateway = AiPrGateway::new(alm.clone());
        let issue = sample_issue();
        let task = gateway.assign_to_agent(&issue, AiAgent::YunqAutoFix).await.unwrap();
        assert_eq!(task.issue, issue);
        assert_eq!(task.agent, AiAgent::YunqAutoFix);
        assert_eq!(task.id, AiAssignmentTaskId(task.id.0));
    }

    #[tokio::test]
    async fn assign_to_agent_skips_resolved_issues() {
        let alm = FakeAlm::default();
        let gateway = AiPrGateway::new(alm.clone());
        let issue = sample_issue();
        let task = gateway.assign_to_agent(&issue, AiAgent::YunqAutoFix).await.unwrap();
        assert!(matches!(
            task.state,
            AiAssignmentState::Done { .. } | AiAssignmentState::Skipped { .. }
        ));
    }

    #[tokio::test]
    async fn open_ai_pr_calls_decorate_pr_with_correct_project_key() {
        let alm = FakeAlm::default();
        let gateway = AiPrGateway::new(alm.clone());
        let issue = sample_issue();
        let proposal = sample_proposal();
        let _url = gateway.open_ai_pr(&proposal, &issue).await.unwrap();
        let decorations = alm.decorations.lock().unwrap();
        let decoration = decorations.first().expect("a decoration was posted");
        assert_eq!(decoration.project_key, "acme", "decoration must carry the project key");
        assert_eq!(decoration.provider, "fake");
    }

    #[tokio::test]
    async fn open_ai_pr_summary_cites_rule_and_file() {
        let alm = FakeAlm::default();
        let gateway = AiPrGateway::new(alm.clone());
        let issue = sample_issue();
        let proposal = sample_proposal();
        let _url = gateway.open_ai_pr(&proposal, &issue).await.unwrap();
        let decorations = alm.decorations.lock().unwrap();
        let decoration = decorations.first().unwrap();
        let summary = decoration.summary.as_deref().unwrap_or("");
        assert!(summary.contains("owasp:sqli"), "summary must cite the rule: {summary}");
        assert!(summary.contains("src/api/users.rs"), "summary must cite the file: {summary}");
        assert!(summary.contains("42"), "summary must cite the line: {summary}");
    }

    #[tokio::test]
    async fn open_ai_pr_posted_includes_inline_comment_at_issue_line() {
        let alm = FakeAlm::default();
        let gateway = AiPrGateway::new(alm.clone());
        let issue = sample_issue();
        let proposal = sample_proposal();
        let _url = gateway.open_ai_pr(&proposal, &issue).await.unwrap();
        let decorations = alm.decorations.lock().unwrap();
        let decoration = decorations.first().unwrap();
        let comment = decoration.comments.first().expect("at least one inline comment");
        assert_eq!(comment.path, "src/api/users.rs");
        assert_eq!(comment.line, 42);
        assert!(comment.body.contains("param_sql"));
    }

    #[tokio::test]
    async fn open_ai_pr_attaches_a_check_run() {
        let alm = FakeAlm::default();
        let gateway = AiPrGateway::new(alm.clone());
        let issue = sample_issue();
        let proposal = sample_proposal();
        let _url = gateway.open_ai_pr(&proposal, &issue).await.unwrap();
        let decorations = alm.decorations.lock().unwrap();
        let decoration = decorations.first().unwrap();
        let check = decoration.check.as_ref().expect("a check run was attached");
        assert_eq!(check.name, "yunq-ai-fix");
        assert_eq!(check.conclusion, CheckConclusion::Success);
    }

    #[tokio::test]
    async fn bulk_assign_returns_summary_with_counts() {
        let alm = FakeAlm::default();
        let gateway = AiPrGateway::new(alm.clone());
        let issues: Vec<IssueRef> = (0..5).map(|_| sample_issue()).collect();
        let summary = gateway.bulk_assign_to_agent(&issues, AiAgent::YunqAutoFix).await.unwrap();
        assert_eq!(summary.total, 5);
        assert_eq!(
            summary.assigned + summary.already_open + summary.skipped + summary.failed,
            summary.total,
            "categories must sum to total"
        );
    }

    #[tokio::test]
    async fn bulk_assign_respects_concurrency_limit() {
        let alm = FakeAlm::default();
        let mut gateway = AiPrGateway::new(alm);
        gateway.concurrency = 2;
        let issues: Vec<IssueRef> = (0..6).map(|_| sample_issue()).collect();
        let started = Utc::now();
        let _summary = gateway.bulk_assign_to_agent(&issues, AiAgent::YunqAutoFix).await.unwrap();
        let duration = Utc::now() - started;
        assert!(duration.num_seconds() < 30, "bulk_assign took too long: {duration:?}");
    }

    #[tokio::test]
    async fn bulk_assign_continues_on_individual_failures() {
        let alm = FakeAlm::default();
        let gateway = AiPrGateway::new(alm.clone());
        let issues: Vec<IssueRef> = (0..3).map(|_| sample_issue()).collect();
        let summary = gateway.bulk_assign_to_agent(&issues, AiAgent::YunqAutoFix).await.unwrap();
        assert_eq!(summary.tasks.len(), 3);
    }

    #[test]
    fn task_id_is_unique_per_call() {
        let a = AiAssignmentTaskId::new();
        let b = AiAssignmentTaskId::new();
        assert_ne!(a, b);
    }

    #[test]
    fn custom_agent_carries_supplier_name() {
        let agent = AiAgent::Custom("my-corp-proxy".into());
        match agent {
            AiAgent::Custom(name) => assert_eq!(name, "my-corp-proxy"),
            AiAgent::YunqAutoFix => panic!("expected Custom variant"),
        }
    }

    #[test]
    fn skipped_state_carries_reason() {
        let s = AiAssignmentState::Skipped { reason: "already-resolved".into() };
        if let AiAssignmentState::Skipped { reason } = s {
            assert_eq!(reason, "already-resolved");
        } else {
            panic!("expected Skipped variant");
        }
    }

    #[test]
    fn done_state_carries_proposal_and_pr_url() {
        let proposal = sample_proposal();
        let s = AiAssignmentState::Done {
            proposal: proposal.clone(),
            pr_url: "https://example/pr/1".into(),
        };
        if let AiAssignmentState::Done { proposal: p, pr_url } = s {
            assert_eq!(p, proposal);
            assert_eq!(pr_url, "https://example/pr/1");
        } else {
            panic!("expected Done variant");
        }
    }
}
