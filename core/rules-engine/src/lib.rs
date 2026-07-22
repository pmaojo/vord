//! The analysis use-cases: domain types (`Issue`, `Metrics`), the ports the
//! core needs from the outside world, the `Rule` extension point, and the
//! `AnalyzerService` that orchestrates parse → rules → persist.

mod alm;
mod domain;
mod gate_defaults;
mod new_code;
mod ports;
mod project;
mod rule;
mod service;
mod structural_metrics;

pub use alm::{
    AlmError, AlmPullRequestReporter, AlmStatusReporter, CommitSha, CommitStatus,
    CommitStatusState, InvalidCommitShaError,
};

pub use domain::{
    AnalysisReport, BulkOutcome, ChangelogAction, ChangelogEntry, CoverageReport, CoverageSummary,
    FileCoverage, Hotspot, HotspotStatus, InvalidCoverageError, InvalidIssueStateError,
    InvalidScanJobError, InvalidTransitionError, Issue, IssueFacets, IssueStatus, IssueTransition,
    Metrics, Resolution, ScanJob, StoredHotspot, StoredIssue, TestReportSummary, TestSuiteSummary,
};
pub use gate_defaults::default_gate;
pub use new_code::{Baseline, NewCodeAnalysis, issue_fingerprint, line_hash};
pub use project::{
    AnalysisContext, AnalysisScope, BranchName, InvalidBranchNameError, InvalidProjectKeyError,
    InvalidPullRequestNumberError, NewCodeDefinition, ProjectKey, PullRequestNumber,
};
pub use ports::{
    AnalysisCache, AstParser, CacheKey, CachedAnalysis, GateResultReader, GateResultSummary,
    HotspotReader, HotspotReview, HotspotStorage, IssueBulkWorkflow, IssueChangelogReader,
    IssueFacetReader, IssueQuery, IssueFetcher, IssueReader, IssueStorage, IssueWorkflow, JobQueue,
    MetricsTracker, Page, ParseError, QueueError, StorageError, WorkflowError,
};
pub use rule::{CrossFileRule, Finding, FindingKind, Rule, RuleMetadata};
pub use structural_metrics::StructuralCounts;

// Re-export duplication vocabulary so consumers depend on one facade.
pub use yunq_cpd::{BlockRef, DuplicateBlock, DuplicationConfig};
pub use service::{AnalyzeError, AnalyzerService};

// Re-export the quality model so consumers depend on one facade.
pub use yunq_profiles::{
    ComparisonOperator, Condition, ConditionResult, ConditionStatus, GateEvaluation, GateStatus,
    InvalidMetricKeyError, InvalidRuleIdError, MetricKey, QualityGate, QualityProfile, Rating,
    RuleId, Severity,
};
