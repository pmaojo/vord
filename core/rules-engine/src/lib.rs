//! The analysis use-cases: domain types (`Issue`, `Metrics`), the ports the
//! core needs from the outside world, the `Rule` extension point, and the
//! `AnalyzerService` that orchestrates parse → rules → persist.

mod domain;
mod ports;
mod rule;
mod service;

pub use domain::{AnalysisReport, InvalidScanJobError, Issue, Metrics, ScanJob};
pub use ports::{
    AnalysisCache, AstParser, CacheKey, CachedAnalysis, IssueReader, IssueStorage, JobQueue,
    MetricsTracker, ParseError, QueueError, StorageError,
};
pub use rule::{Finding, Rule};
pub use service::{AnalyzeError, AnalyzerService};

// Re-export the quality model so consumers depend on one facade.
pub use yunq_profiles::{InvalidRuleIdError, QualityProfile, RuleId, Severity};
