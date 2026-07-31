//! The analysis use-cases: domain types (`Issue`, `Metrics`), the ports the
//! core needs from the outside world, the `Rule` extension point, and the
//! `AnalyzerService` that orchestrates parse → rules → persist.

#![feature(let_chains)]

mod alm;
mod alm_gateway;
pub mod branches;
pub mod datalog;
mod domain;
mod function_complexity;
mod gate_defaults;
mod new_code;
mod new_code_overrides;
pub mod portfolios;
mod ports;
mod project;
mod rule;
mod service;
mod structural_metrics;
mod suppression;
mod test_code;

pub use alm::{
    AlmError, AlmPullRequestReporter, AlmStatusReporter, CommitSha, CommitStatus,
    CommitStatusState, InvalidCommitShaError,
};
pub use alm_gateway::{
    AlmGateway, AlmGatewayError, CheckConclusion, CheckRunReport, DecorationReceipt, InlineComment,
    PrDecoration,
};
pub use branches::{Branch, BranchRef, PullRequest};
pub use datalog::{DatalogEngine, Fact as DatalogFact, Rule as DatalogRule};

pub use domain::{
    AnalysisReport, BlameLineInfo, BulkOutcome, ChangelogAction, ChangelogEntry, CoverageReport,
    CoverageSummary, ExternalIssue, FileBlame, FileCoverage, FileFunctionComplexity, Hotspot,
    HotspotStatus, InvalidCoverageError, InvalidIssueStateError, InvalidScanJobError,
    InvalidTransitionError, Issue, IssueFacets, IssueStatus, IssueTransition, Metrics,
    MutationSummary, Resolution, ScanJob, StoredHotspot, StoredIssue, TestReportSummary,
    TestSuiteSummary,
};
pub use function_complexity::{FunctionComplexity, compute as function_complexities};
pub use gate_defaults::default_gate;
pub use new_code::{Baseline, NewCodeAnalysis, issue_fingerprint, line_hash};
pub use new_code_overrides::{
    NewCodeOverride, OverrideScope, OverrideSource, resolve_baseline,
    resolve_baseline_for_new_code_definition, resolve_new_code_definition,
};
pub use portfolios::{PortfolioNode, PortfolioRollup, ProjectRollupInput};
pub use ports::{
    AnalysisCache, AnalysisHistoryReader, AstParser, CacheKey, CachedAnalysis, ComponentMeasures,
    ComponentTree, ComponentTreeReader, CoverageResultReader, CoverageResultSummary,
    CoverageStorage, FileBlameLineReader, FileBlameLineStorage, FileBlameLines,
    FileCoverageLineReader, FileCoverageLineStorage, FileCoverageLines, GateResultReader,
    GateResultSummary, HotspotReader, HotspotReview, HotspotStorage, IssueBulkWorkflow,
    IssueChangelogReader, IssueFacetReader, IssueFetcher, IssueQuery, IssueReader, IssueScope,
    IssueStorage, IssueWorkflow, JobQueue, MeasureHistoryPoint, MeasureHistoryReader,
    MeasureStorage, MetricsTracker, Page, ParseError, QueueError, StorageError, WorkflowError,
};
pub use project::{
    AnalysisContext, AnalysisScope, BranchName, InvalidBranchNameError, InvalidProjectKeyError,
    InvalidPullRequestNumberError, NewCodeDefinition, ProjectKey, PullRequestNumber,
};
pub use rule::{CrossFileRule, Finding, FindingKind, Rule, RuleMetadata};
pub use structural_metrics::StructuralCounts;
pub use suppression::is_suppressed;
pub use test_code::{LineRange, in_ranges, is_test_only_path, rust_test_module_ranges};

// Re-export duplication vocabulary so consumers depend on one facade.
pub use yunq_cpd::{CloneRegion, CloneSet, DuplicationConfig, TokenNormalization};
// Re-export CRAP vocabulary so consumers depend on one facade.
pub use service::{AnalyzeError, AnalyzerService};
pub use yunq_crap::{CrapFinding, HIGH_RISK_THRESHOLD, REFACTOR_CANDIDATE_THRESHOLD};

// Re-export the quality model so consumers depend on one facade.
pub use yunq_profiles::{
    ComparisonOperator, Condition, ConditionResult, ConditionStatus, DEFAULT_PROFILE_NAME,
    GateEvaluation, GateStatus, ImpactSeverity, InvalidMetricKeyError, InvalidRuleIdError,
    IssueType, MetricKey, ProfileBackup, ProfileDiff, QualityGate, QualityProfile, Rating,
    RemediationEffortSummary, RestoreError, RestorePolicy, RuleId, Severity, SeverityDifference,
    SoftwareQuality, SoftwareQualityImpact, backup, compare, copy_profile, default_impact,
    default_profile, default_profile_for_language, restore,
};
