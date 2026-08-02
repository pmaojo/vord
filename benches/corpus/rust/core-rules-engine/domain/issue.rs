use std::collections::BTreeMap;
use std::fmt;

use vord_ast::Span;
use vord_profiles::{RuleId, Severity};

/// Workflow state of a tracked issue.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum IssueStatus {
    Open,
    Confirmed,
    Resolved,
    Closed,
}

impl IssueStatus {
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "open" => Some(IssueStatus::Open),
            "confirmed" => Some(IssueStatus::Confirmed),
            "resolved" => Some(IssueStatus::Resolved),
            "closed" => Some(IssueStatus::Closed),
            _ => None,
        }
    }
}

impl fmt::Display for IssueStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            IssueStatus::Open => "open",
            IssueStatus::Confirmed => "confirmed",
            IssueStatus::Resolved => "resolved",
            IssueStatus::Closed => "closed",
        })
    }
}

/// Why a resolved issue was resolved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Resolution {
    Fixed,
    WontFix,
    FalsePositive,
}

impl Resolution {
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "fixed" => Some(Resolution::Fixed),
            "wont-fix" => Some(Resolution::WontFix),
            "false-positive" => Some(Resolution::FalsePositive),
            _ => None,
        }
    }
}

impl fmt::Display for Resolution {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Resolution::Fixed => "fixed",
            Resolution::WontFix => "wont-fix",
            Resolution::FalsePositive => "false-positive",
        })
    }
}

/// A workflow action on an issue.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IssueTransition {
    Confirm,
    Resolve(Resolution),
    Reopen,
    Close,
}

#[derive(Debug, thiserror::Error)]
#[error("cannot apply {transition:?} to an issue in status {from}")]
pub struct InvalidTransitionError {
    pub from: IssueStatus,
    pub transition: IssueTransition,
}

#[derive(Debug, thiserror::Error)]
#[error("inconsistent stored issue state: status {status} with resolution {resolution:?}")]
pub struct InvalidIssueStateError {
    pub status: IssueStatus,
    pub resolution: Option<Resolution>,
}

/// An issue as persisted by a storage adapter, carrying its storage identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredIssue {
    pub id: i64,
    pub issue: Issue,
}

/// Facet counts over a filtered issue search.
#[derive(Clone, Debug, Default)]
pub struct IssueFacets {
    pub by_severity: BTreeMap<Severity, usize>,
    pub by_status: Vec<(IssueStatus, usize)>,
    pub by_rule: Vec<(RuleId, usize)>,
}

/// One workflow action recorded against an issue, for audit/history display.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChangelogAction {
    Transitioned { from: IssueStatus, transition: IssueTransition },
    Assigned { assignee: Option<String> },
}

/// A single changelog entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChangelogEntry {
    pub issue_id: i64,
    pub action: ChangelogAction,
    pub at: String,
}

/// The outcome of one bulk operation on a single issue.
#[derive(Clone, Debug)]
pub enum BulkOutcome {
    Applied(StoredIssue),
    Failed { issue_id: i64, reason: String },
}

/// A single detected problem, located in a file, with its workflow state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Issue {
    rule: RuleId,
    severity: Severity,
    message: String,
    file: String,
    span: Span,
    status: IssueStatus,
    resolution: Option<Resolution>,
    assignee: Option<String>,
}

impl Issue {
    pub fn new(
        rule: RuleId,
        severity: Severity,
        message: impl Into<String>,
        file: impl Into<String>,
        span: Span,
    ) -> Self {
        Self {
            rule,
            severity,
            message: message.into(),
            file: file.into(),
            span,
            status: IssueStatus::Open,
            resolution: None,
            assignee: None,
        }
    }

    pub fn rule(&self) -> &RuleId {
        &self.rule
    }

    pub fn severity(&self) -> Severity {
        self.severity
    }

    pub fn message(&self) -> &str {
        &self.message
    }

    pub fn file(&self) -> &str {
        &self.file
    }

    pub fn span(&self) -> Span {
        self.span
    }

    #[allow(clippy::too_many_arguments)]
    pub fn restore(
        rule: RuleId,
        severity: Severity,
        message: impl Into<String>,
        file: impl Into<String>,
        span: Span,
        status: IssueStatus,
        resolution: Option<Resolution>,
        assignee: Option<String>,
    ) -> Result<Self, InvalidIssueStateError> {
        let valid = matches!(
            (status, resolution),
            (IssueStatus::Open | IssueStatus::Confirmed, None)
                | (IssueStatus::Resolved, Some(_))
                | (IssueStatus::Closed, _)
        );
        if !valid {
            return Err(InvalidIssueStateError { status, resolution });
        }
        let mut issue = Self::new(rule, severity, message, file, span);
        issue.status = status;
        issue.resolution = resolution;
        issue.assignee = assignee;
        Ok(issue)
    }

    pub fn status(&self) -> IssueStatus {
        self.status
    }

    pub fn resolution(&self) -> Option<Resolution> {
        self.resolution
    }

    pub fn assignee(&self) -> Option<&str> {
        self.assignee.as_deref()
    }

    pub fn assign(&mut self, user: impl Into<String>) {
        self.assignee = Some(user.into());
    }

    pub fn unassign(&mut self) {
        self.assignee = None;
    }

    pub fn apply(&mut self, transition: IssueTransition) -> Result<(), InvalidTransitionError> {
        let next = match (self.status, transition) {
            (IssueStatus::Open, IssueTransition::Confirm) => (IssueStatus::Confirmed, None),
            (IssueStatus::Open | IssueStatus::Confirmed, IssueTransition::Resolve(resolution)) => {
                (IssueStatus::Resolved, Some(resolution))
            }
            (IssueStatus::Resolved, IssueTransition::Reopen) => (IssueStatus::Open, None),
            (IssueStatus::Resolved, IssueTransition::Close) => (IssueStatus::Closed, self.resolution),
            (from, transition) => return Err(InvalidTransitionError { from, transition }),
        };
        (self.status, self.resolution) = next;
        Ok(())
    }
}
