//! The analysis use-cases: domain types (`Issue`, `Metrics`), the ports the
//! core needs from the outside world, the `Rule` extension point, and the
//! `AnalyzerService` that orchestrates parse → rules → persist.

mod domain;
mod new_code;
mod ports;
mod project;
mod rule;
mod service;

pub use domain::{
    AnalysisReport, Hotspot, HotspotStatus, InvalidIssueStateError, InvalidScanJobError,
    InvalidTransitionError, Issue, IssueStatus, IssueTransition, Metrics, Resolution, ScanJob,
    StoredHotspot, StoredIssue,
};
pub use new_code::{Baseline, NewCodeAnalysis, issue_fingerprint};
pub use project::{
    AnalysisContext, AnalysisScope, BranchName, InvalidBranchNameError, InvalidProjectKeyError,
    InvalidPullRequestNumberError, NewCodeDefinition, ProjectKey, PullRequestNumber,
};
pub use ports::{
    AnalysisCache, AstParser, CacheKey, CachedAnalysis, HotspotReader, HotspotReview,
    HotspotStorage, IssueQuery, IssueReader, IssueStorage, IssueWorkflow, JobQueue, MetricsTracker,
    Page, ParseError, QueueError, StorageError, WorkflowError,
};
pub use rule::{Finding, FindingKind, Rule};
pub use service::{AnalyzeError, AnalyzerService};

// Re-export the quality model so consumers depend on one facade.
pub use yunq_profiles::{
    ComparisonOperator, Condition, ConditionResult, ConditionStatus, GateEvaluation, GateStatus,
    InvalidMetricKeyError, InvalidRuleIdError, MetricKey, QualityGate, QualityProfile, Rating,
    RuleId, Severity,
};
