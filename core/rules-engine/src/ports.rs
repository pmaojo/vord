//! Ports: the abstractions the core requires from the outside world.
//! Adapters (infra/*, parsers/*) depend on this crate and implement them —
//! never the other way around. Traits are segregated per consumer (ISP):
//! a worker needs `IssueStorage`, the dashboard only `IssueReader`.

use std::future::Future;

use yunq_ast::{AstNode, LanguageIdentifier, SourceFile};

use crate::domain::{
    Hotspot, InvalidTransitionError, Issue, IssueTransition, Metrics, ScanJob, StoredIssue,
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

/// Outbound port: reads persisted issues (dashboard/API side).
pub trait IssueReader: Send + Sync {
    fn recent_issues(
        &self,
        limit: usize,
    ) -> impl Future<Output = Result<Vec<StoredIssue>, StorageError>> + Send;
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
