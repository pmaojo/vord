//! Ports: the abstractions the core requires from the outside world.
//! Adapters (infra/*, parsers/*) depend on this crate and implement them —
//! never the other way around. Traits are segregated per consumer (ISP):
//! a worker needs `IssueStorage`, the dashboard only `IssueReader`.

use std::collections::BTreeMap;
use std::future::Future;

use yunq_ast::{AstNode, LanguageIdentifier, SourceFile};
use yunq_profiles::{GateStatus, RuleId, Severity};

use crate::domain::{
    BlameLineInfo, BulkOutcome, ChangelogEntry, CoverageSummary, FileBlame, FileCoverage, Hotspot,
    HotspotStatus, InvalidTransitionError, Issue, IssueFacets, IssueStatus, IssueTransition,
    Metrics, ScanJob, StoredHotspot, StoredIssue,
};
use crate::new_code::Baseline;
use crate::structural_metrics::StructuralCounts;

/// Inbound port: turns raw source text into the neutral AST.
/// Object-safe on purpose so the service can hold a registry of parsers.
pub trait AstParser: Send + Sync {
    fn language(&self) -> LanguageIdentifier;
    fn parse(&self, file: &SourceFile) -> Result<AstNode, ParseError>;

    /// Per-line, normalized tokens for copy-paste detection: `(1-based line
    /// number, normalized token text)`, omitting insignificant lines. The
    /// default falls back to treating each trimmed non-blank line as its own
    /// single token (`yunq_cpd::fallback_tokenize`); adapters backed by a
    /// real tokenizer (tree-sitter leaf walk collapsing literals to a shared
    /// placeholder and dropping comments — `yunq-treesitter-tokens`)
    /// override this so duplication matching is token-accurate rather than
    /// sensitive to literal values and incidental whitespace.
    /// Per-line normalized tokens for copy-paste detection. `normalization`
    /// decides which clone kinds are visible (see
    /// [`yunq_cpd::TokenNormalization`]); a parser that cannot honor it
    /// still returns usable Type-1 tokens rather than nothing.
    fn tokenize_for_duplication(
        &self,
        file: &SourceFile,
        normalization: yunq_cpd::TokenNormalization,
    ) -> yunq_cpd::TokenizedSource {
        let _ = normalization;
        yunq_cpd::TokenizedSource {
            lines: yunq_cpd::fallback_tokenize(file),
            declaration_lines: Vec::new(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("failed to parse {file}: {detail}")]
    Syntax { file: String, detail: String },
    #[error("parser backend failure: {0}")]
    Backend(String),
}

/// Optional project/analysis scoping for a batch of persisted issues or
/// hotspots. `None` in either field means "not yet known" — local, one-off
/// callers (the CLI, the LSP, remediation's verify-before-suggest loop) run
/// against `InMemoryIssueStorage` and never resolve a project at all, so
/// they use `IssueScope::default()` (via the unscoped `analyze_files`).
/// The composition root that actually persists to Postgres (`yunq-worker`)
/// is the only layer that knows about projects/analyses, so it's the only
/// one that ever constructs a non-default scope — the pure engine stays
/// agnostic of what a "project" is.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IssueScope {
    pub project_id: Option<i64>,
    pub analysis_id: Option<i64>,
}

/// Outbound port: persists detected issues.
pub trait IssueStorage: Send + Sync {
    fn save_issues(
        &self,
        issues: &[Issue],
        scope: IssueScope,
    ) -> impl Future<Output = Result<(), StorageError>> + Send;
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
        scope: IssueScope,
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

/// One project's most recently persisted quality gate outcome — the source
/// of truth for the status badge, so it always reflects the real result of
/// the last analysis rather than a hardcoded value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GateResultSummary {
    pub status: GateStatus,
    /// ISO-8601 timestamp of the analysis the result was evaluated for.
    pub evaluated_at: String,
}

/// Outbound port: reads the latest persisted gate result for a project, if
/// any analysis has run yet.
pub trait GateResultReader: Send + Sync {
    fn latest_gate_result(
        &self,
        project_key: &str,
    ) -> impl Future<Output = Result<Option<GateResultSummary>, StorageError>> + Send;
}

/// Outbound port: persists an ingested coverage report's summary against one
/// analysis — the server-side counterpart to the CLI's `--coverage`/
/// `--cobertura`/etc. flags, which only ever computed coverage locally.
pub trait CoverageStorage: Send + Sync {
    fn save_coverage(
        &self,
        analysis_id: i64,
        summary: CoverageSummary,
    ) -> impl Future<Output = Result<(), StorageError>> + Send;
}

/// One project's most recently persisted coverage summary — the source of
/// truth for a coverage measure/badge, mirroring [`GateResultSummary`].
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CoverageResultSummary {
    pub summary: CoverageSummary,
}

/// Outbound port: reads the latest persisted coverage summary for a
/// project, if any analysis has had a coverage report ingested yet.
pub trait CoverageResultReader: Send + Sync {
    fn latest_coverage(
        &self,
        project_key: &str,
    ) -> impl Future<Output = Result<Option<CoverageResultSummary>, StorageError>> + Send;
}

/// Outbound port: resolves a New Code override (see `new_code_overrides`) to
/// the analysis history it refers to, so the pure engine can build a
/// `Baseline` without knowing how or where analyses are persisted.
pub trait AnalysisHistoryReader: Send + Sync {
    /// The most recent analysis id for `(project_key, branch)`, or `None` if
    /// that project/branch has never been analyzed — the lookup behind a
    /// `ReferenceBranch` override. Distinct name from the existing
    /// `PgAnalysisStore::latest_analysis_id(project_id, branch)` (used by
    /// coverage ingestion) to avoid an inherent-vs-trait method name clash
    /// on the same adapter type — that one takes an already-resolved
    /// `project_id`, this one resolves from a `project_key`.
    fn latest_analysis_id_on_branch(
        &self,
        project_key: &str,
        branch: &str,
    ) -> impl Future<Output = Result<Option<i64>, StorageError>> + Send;

    /// The analysis id closest to (at or before) `days_ago` days before now,
    /// on `branch` — the lookup behind a `Days` override.
    fn analysis_id_days_ago(
        &self,
        project_key: &str,
        branch: &str,
        days_ago: u32,
    ) -> impl Future<Output = Result<Option<i64>, StorageError>> + Send;

    /// Rebuilds the issue-fingerprint `Baseline` one specific past analysis
    /// run produced — the last step for all three override kinds, once
    /// they've been resolved to a concrete analysis id.
    fn baseline_for_analysis(
        &self,
        analysis_id: i64,
    ) -> impl Future<Output = Result<Baseline, StorageError>> + Send;

    /// The most recent analysis for `(project_key, branch)` strictly before
    /// `before_analysis_id`, or `None` if there isn't one — the lookup
    /// behind `NewCodeDefinition::PreviousAnalysis`. Distinct from
    /// `latest_analysis_id_on_branch`: the caller's own in-progress scan has
    /// typically already been recorded (see `record_analysis_pending`) by
    /// the time it asks "what came before me", so "most recent" would
    /// otherwise resolve to itself.
    fn previous_analysis_id(
        &self,
        project_key: &str,
        branch: &str,
        before_analysis_id: i64,
    ) -> impl Future<Output = Result<Option<i64>, StorageError>> + Send;
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
    pub structural: StructuralCounts,
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

/// Outbound port: persists one analysis' full set of scalar measures —
/// project-level (`AnalysisReport::all_measures`) and, where derivable,
/// per-file (`AnalysisReport::file_issue_measures`) — the write side behind
/// measure history and the component tree (issue #26). Called once per
/// completed analysis, right after the analysis row itself is recorded.
pub trait MeasureStorage: Send + Sync {
    fn save_measures(
        &self,
        analysis_id: i64,
        project_measures: &[(String, f64)],
        file_measures: &BTreeMap<String, BTreeMap<String, f64>>,
    ) -> impl Future<Output = Result<(), StorageError>> + Send;
}

/// One analysis' worth of measures in a metric time series — the unit
/// `api/measures/search_history`-style endpoints return one of per
/// analysis, oldest or newest first depending on the query.
#[derive(Clone, Debug, PartialEq)]
pub struct MeasureHistoryPoint {
    pub analysis_id: i64,
    /// ISO-8601 timestamp of the analysis.
    pub date: String,
    /// Requested metric key -> value, absent when that analysis has no
    /// value for a requested metric (e.g. `coverage` before it was ever
    /// ingested) rather than a fabricated zero.
    pub values: BTreeMap<String, f64>,
}

/// Outbound port: reads a component's (project or file) measure history
/// across a project's analyses, optionally restricted to a metric-key
/// subset and/or a date range.
pub trait MeasureHistoryReader: Send + Sync {
    #[allow(clippy::too_many_arguments)]
    fn measure_history(
        &self,
        project_key: &str,
        branch: &str,
        component: Option<&str>,
        metric_keys: &[String],
        from: Option<&str>,
        to: Option<&str>,
    ) -> impl Future<Output = Result<Vec<MeasureHistoryPoint>, StorageError>> + Send;
}

/// One file's measures as of a project's most recent analysis — one row of
/// a component tree listing.
#[derive(Clone, Debug, PartialEq)]
pub struct ComponentMeasures {
    pub path: String,
    pub measures: BTreeMap<String, f64>,
}

/// A project's component tree as of its most recent analysis. Deliberately
/// flat (files only, no directory nesting) for this first slice — see the
/// `sources`/`measures` module docs in `bin/server` for why a full nested
/// tree was scoped out.
#[derive(Clone, Debug, PartialEq)]
pub struct ComponentTree {
    pub analysis_id: i64,
    pub components: Vec<ComponentMeasures>,
}

/// Outbound port: reads a project's component (file) list with their latest
/// measures — the read side of `api/components/tree`-style navigation.
/// `None` when the project has no analysis yet.
pub trait ComponentTreeReader: Send + Sync {
    fn component_tree(
        &self,
        project_key: &str,
        branch: &str,
    ) -> impl Future<Output = Result<Option<ComponentTree>, StorageError>> + Send;
}

/// One file's per-line coverage detail (1-based line number -> hit count) —
/// the read side behind the `sources` endpoint's coverage annotation.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct FileCoverageLines {
    pub lines: BTreeMap<u32, usize>,
}

/// Outbound port: persists per-line coverage detail for every instrumented
/// file in an ingested coverage report — the counterpart to `CoverageStorage`
/// that keeps line-level detail instead of reducing straight to the report-
/// wide summary, so the `sources` endpoint has real (not fabricated)
/// per-line coverage to annotate with.
pub trait FileCoverageLineStorage: Send + Sync {
    fn save_file_coverage_lines(
        &self,
        analysis_id: i64,
        files: &[FileCoverage],
    ) -> impl Future<Output = Result<(), StorageError>> + Send;
}

/// Outbound port: reads one file's per-line coverage detail as of a
/// project's most recently coverage-ingested analysis. `None` when no
/// coverage report has ever been ingested for this file.
pub trait FileCoverageLineReader: Send + Sync {
    fn file_coverage_lines(
        &self,
        project_key: &str,
        branch: &str,
        file: &str,
    ) -> impl Future<Output = Result<Option<FileCoverageLines>, StorageError>> + Send;
}

/// One file's per-line SCM blame detail (1-based line number -> commit
/// attribution) — the read side behind the `sources` endpoint's blame
/// annotation (issue #26's now-unblocked follow-up, once #33 added blame
/// capture to the CLI).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct FileBlameLines {
    pub lines: BTreeMap<u32, BlameLineInfo>,
}

/// Outbound port: persists per-line SCM blame for every file the CLI's
/// `--blame-output` captured — the server-side counterpart, ingested via
/// `POST /api/projects/{key}/blame` from that same JSON output.
pub trait FileBlameLineStorage: Send + Sync {
    fn save_file_blame_lines(
        &self,
        analysis_id: i64,
        files: &[FileBlame],
    ) -> impl Future<Output = Result<(), StorageError>> + Send;
}

/// Outbound port: reads one file's per-line blame detail as of a project's
/// most recently blame-ingested analysis. `None` when no blame has ever been
/// ingested for this file.
pub trait FileBlameLineReader: Send + Sync {
    fn file_blame_lines(
        &self,
        project_key: &str,
        branch: &str,
        file: &str,
    ) -> impl Future<Output = Result<Option<FileBlameLines>, StorageError>> + Send;
}
