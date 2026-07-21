//! Ports: the abstractions the core requires from the outside world.
//! Adapters (infra/*, parsers/*) depend on this crate and implement them —
//! never the other way around. Traits are segregated per consumer (ISP):
//! a worker needs `IssueStorage`, the dashboard only `IssueReader`.

use std::future::Future;

use yunq_ast::{AstNode, LanguageIdentifier, SourceFile};

use crate::domain::{Issue, Metrics, ScanJob};

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
    fn recent_issues(&self, limit: usize) -> impl Future<Output = Result<Vec<Issue>, StorageError>> + Send;
}

/// Outbound port: records analysis metrics.
pub trait MetricsTracker: Send + Sync {
    fn record(&self, metrics: &Metrics) -> impl Future<Output = Result<(), StorageError>> + Send;
}

#[derive(Debug, thiserror::Error)]
#[error("storage backend failure: {0}")]
pub struct StorageError(pub String);

/// Outbound port: enqueues scan jobs for asynchronous workers.
pub trait JobQueue: Send + Sync {
    fn enqueue_scan(&self, job: ScanJob) -> impl Future<Output = Result<(), QueueError>> + Send;
}

#[derive(Debug, thiserror::Error)]
#[error("queue backend failure: {0}")]
pub struct QueueError(pub String);
