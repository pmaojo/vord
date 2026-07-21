//! The analysis use-cases: domain types (`Issue`, `Metrics`), the ports the
//! core needs from the outside world, the `Rule` extension point, and the
//! `AnalyzerService` that orchestrates parse → rules → persist.

mod domain;
mod ports;
mod rule;
mod service;

pub use domain::{
    AnalysisReport, InvalidIssueStateError, InvalidScanJobError, InvalidTransitionError, Issue,
    IssueStatus, IssueTransition, Metrics, Resolution, ScanJob, StoredIssue,
};
pub use ports::{
    AnalysisCache, AstParser, CacheKey, CachedAnalysis, IssueReader, IssueStorage, IssueWorkflow,
    JobQueue, MetricsTracker, ParseError, QueueError, StorageError, WorkflowError,
};
pub use rule::{Finding, Rule};
pub use service::{AnalyzeError, AnalyzerService};

// Re-export the quality model so consumers depend on one facade.
pub use yunq_profiles::{
    ComparisonOperator, Condition, ConditionResult, ConditionStatus, GateEvaluation, GateStatus,
    InvalidMetricKeyError, InvalidRuleIdError, MetricKey, QualityGate, QualityProfile, Rating,
    RuleId, Severity,
};
