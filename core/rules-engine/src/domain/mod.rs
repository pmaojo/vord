//! Modularized domain model: issues, hotspots, reports, and scan jobs.

pub mod hotspot;
pub mod issue;
pub mod job;
pub mod report;

pub use hotspot::{Hotspot, HotspotStatus, StoredHotspot};
pub use issue::{
    BulkOutcome, ChangelogAction, ChangelogEntry, InvalidIssueStateError, InvalidTransitionError,
    Issue, IssueFacets, IssueStatus, IssueTransition, Resolution, StoredIssue,
};
pub use job::{InvalidScanJobError, ScanJob};
pub use report::{
    AnalysisReport, BlameLineInfo, CoverageReport, CoverageSummary, ExternalIssue, FileBlame,
    FileCoverage, InvalidCoverageError, Metrics, MutationSummary, TestReportSummary,
    TestSuiteSummary,
};
