//! Ports: the abstractions the core requires from the outside world.
//! Adapters (infra/*, parsers/*) depend on this crate and implement them —
//! never the other way around. Traits are segregated per consumer (ISP):
//! a worker needs `IssueStorage`, the dashboard only `IssueReader`.

use std::future::Future;

use yunq_ast::{AstNode, LanguageIdentifier, SourceFile};
use yunq_profiles::{RuleId, Severity};

use crate::domain::{
    BulkOutcome, ChangelogEntry, Hotspot, HotspotStatus, InvalidTransitionError, Issue,
    IssueFacets, IssueStatus, IssueTransition, Metrics, ScanJob, StoredHotspot, StoredIssue,
};

/// Inbound port: turns raw source text into the neutral AST.
/// Object-safe on purpose so the service can hold a registry of parsers.
pub trait AstParser: Send + Sync {
    fn language(&self) -> LanguageIdentifier;
    fn parse(&self, file: &SourceFile) -> Result<AstNode, ParseError>;
}

#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("failed to parse {file}: {detail}")]
    Syntax { file: String, detail: String },
    #[error("parser backend failure: {0}")]
    Backend(String),
}

/// Outbound port: persists detected issues.
pub trait IssueStorage: Send + Sync {
    fn save_issues(&self, issues: &[Issue]) -> impl Future<Output = Result<(), StorageError>> + Send;
}

/// Conjunctive filters plus pagination for issue search.
#[derive(Clone, Debug, Default)]
pub struct IssueQuery {
    pub severity: Option<Severity>,
    pub status: Option<IssueStatus>,
    pub rule: Option<RuleId>,
    /// Substring match on the file path.
    pub file: Option<String>,
    pub assignee: Option<String>,
    /// 1-based; 0 is treated as 1.
    pub page: usize,
    /// Clamped to 1..=500; 0 means the default (50).
    pub page_size: usize,
}

impl IssueQuery {
    pub fn normalized_page(&self) -> usize {
        self.page.max(1)
    }

    pub fn normalized_page_size(&self) -> usize {
        if self.page_size == 0 { 50 } else { self.page_size.clamp(1, 500) }
    }

    pub fn offset(&self) -> usize {
        (self.normalized_page() - 1) * self.normalized_page_size()
    }
}

/// One page of results plus the pagination envelope.
#[derive(Clone, Debug)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub page: usize,
    pub page_size: usize,
    pub total: usize,
}

/// Outbound port: reads persisted issues (dashboard/API side).
pub trait IssueReader: Send + Sync {
    fn search_issues(
        &self,
        query: &IssueQuery,
    ) -> impl Future<Output = Result<Page<StoredIssue>, StorageError>> + Send;
}

/// Outbound port: loads one issue for a focused workflow such as agent remediation.
pub trait IssueFetcher: Send + Sync {
    fn fetch_issue(
        &self,
        issue_id: i64,
    ) -> impl Future<Output = Result<StoredIssue, WorkflowError>> + Send;
}

/// Outbound port: aggregates issue counts per dimension for a filtered
/// search — the sidebar facet counts a real Issues workspace needs.
pub trait IssueFacetReader: Send + Sync {
    fn facets(
        &self,
        query: &IssueQuery,
    ) -> impl Future<Output = Result<IssueFacets, StorageError>> + Send;
}

/// Outbound port: applies the same transition to many issues in one call.
/// Each issue succeeds or fails independently — one illegal transition does
/// not abort the rest — mirroring the bulk-change UX of the Issues page.
pub trait IssueBulkWorkflow: Send + Sync {
    fn bulk_transition(
        &self,
        issue_ids: &[i64],
        transition: IssueTransition,
    ) -> impl Future<Output = Result<Vec<BulkOutcome>, StorageError>> + Send;
}

/// Outbound port: reads the recorded history of workflow actions on an
/// issue (audit trail for the Issues page).
pub trait IssueChangelogReader: Send + Sync {
    fn changelog(
        &self,
        issue_id: i64,
    ) -> impl Future<Output = Result<Vec<ChangelogEntry>, StorageError>> + Send;
}

/// Outbound port: persists detected security hotspots.
pub trait HotspotStorage: Send + Sync {
    fn save_hotspots(
        &self,
        hotspots: &[Hotspot],
    ) -> impl Future<Output = Result<(), StorageError>> + Send;
}

/// Outbound port: reads persisted hotspots.
pub trait HotspotReader: Send + Sync {
    fn recent_hotspots(
        &self,
        limit: usize,
    ) -> impl Future<Output = Result<Vec<StoredHotspot>, StorageError>> + Send;
}

/// Outbound port: records a reviewer's verdict on a hotspot.
pub trait HotspotReview: Send + Sync {
    fn review_hotspot(
        &self,
        hotspot_id: i64,
        status: HotspotStatus,
    ) -> impl Future<Output = Result<StoredHotspot, WorkflowError>> + Send;
}

#[derive(Debug, thiserror::Error)]
pub enum WorkflowError {
    #[error("issue {0} not found")]
    NotFound(i64),
    #[error(transparent)]
    InvalidTransition(#[from] InvalidTransitionError),
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error("stored issue {0} is corrupt: {1}")]
    Corrupt(i64, String),
}

/// Outbound port: mutates the workflow state of persisted issues. The state
/// machine itself lives in the domain (`Issue::apply`); adapters only load,
/// delegate, and store.
pub trait IssueWorkflow: Send + Sync {
    fn apply_transition(
        &self,
        issue_id: i64,
        transition: IssueTransition,
    ) -> impl Future<Output = Result<StoredIssue, WorkflowError>> + Send;

    fn set_assignee(
        &self,
        issue_id: i64,
        assignee: Option<String>,
    ) -> impl Future<Output = Result<StoredIssue, WorkflowError>> + Send;
}

/// Outbound port: records analysis metrics.
pub trait MetricsTracker: Send + Sync {
    fn record(&self, metrics: &Metrics) -> impl Future<Output = Result<(), StorageError>> + Send;
}

#[derive(Debug, thiserror::Error)]
#[error("storage backend failure: {0}")]
pub struct StorageError(pub String);

/// Key identifying one file analysis under one engine configuration.
/// `content_hash` covers (path, language, content); `config_hash` covers the
/// registered rules, profile activations, parser roster and engine version —
/// any config change invalidates every entry, fail-open.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CacheKey {
    pub content_hash: u64,
    pub config_hash: u64,
}

/// The reusable result of a single-file analysis.
#[derive(Clone, Debug)]
pub struct CachedAnalysis {
    pub lines: usize,
    pub debt_minutes: usize,
    pub issues: Vec<Issue>,
    pub hotspots: Vec<Hotspot>,
}

/// Outbound port: memoizes per-file analysis so unchanged files are never
/// re-parsed or re-analyzed. Methods are sync — they are called from inside
/// the parallel per-file workers.
pub trait AnalysisCache: Send + Sync {
    fn get(&self, key: &CacheKey) -> Option<CachedAnalysis>;
    fn put(&self, key: CacheKey, value: CachedAnalysis);
}

/// Outbound port: enqueues scan jobs for asynchronous workers.
pub trait JobQueue: Send + Sync {
    fn enqueue_scan(&self, job: ScanJob) -> impl Future<Output = Result<(), QueueError>> + Send;
}

#[derive(Debug, thiserror::Error)]
#[error("queue backend failure: {0}")]
pub struct QueueError(pub String);
