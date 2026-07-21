use std::collections::BTreeMap;

use yunq_ast::Span;
use yunq_profiles::{RuleId, Severity};

/// A single detected problem, located in a file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Issue {
    rule: RuleId,
    severity: Severity,
    message: String,
    file: String,
    span: Span,
}

impl Issue {
    pub fn new(
        rule: RuleId,
        severity: Severity,
        message: impl Into<String>,
        file: impl Into<String>,
        span: Span,
    ) -> Self {
        Self { rule, severity, message: message.into(), file: file.into(), span }
    }

    pub fn rule(&self) -> &RuleId {
        &self.rule
    }

    pub fn severity(&self) -> Severity {
        self.severity
    }

    pub fn message(&self) -> &str {
        &self.message
    }

    pub fn file(&self) -> &str {
        &self.file
    }

    pub fn span(&self) -> Span {
        self.span
    }
}

/// Aggregated counters for one analysis run.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Metrics {
    files_scanned: usize,
    files_skipped: usize,
    parse_failures: usize,
    cache_hits: usize,
    lines_of_code: usize,
    by_severity: BTreeMap<Severity, usize>,
}

impl Metrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_file(&mut self, lines: usize) {
        self.files_scanned += 1;
        self.lines_of_code += lines;
    }

    pub fn add_skipped_file(&mut self) {
        self.files_skipped += 1;
    }

    pub fn add_parse_failure(&mut self) {
        self.parse_failures += 1;
    }

    pub fn add_cache_hit(&mut self) {
        self.cache_hits += 1;
    }

    pub fn count_issue(&mut self, severity: Severity) {
        *self.by_severity.entry(severity).or_default() += 1;
    }

    pub fn files_scanned(&self) -> usize {
        self.files_scanned
    }

    pub fn files_skipped(&self) -> usize {
        self.files_skipped
    }

    pub fn parse_failures(&self) -> usize {
        self.parse_failures
    }

    /// Files whose analysis was reused from the incremental cache.
    pub fn cache_hits(&self) -> usize {
        self.cache_hits
    }

    pub fn lines_of_code(&self) -> usize {
        self.lines_of_code
    }

    pub fn issues_by_severity(&self) -> &BTreeMap<Severity, usize> {
        &self.by_severity
    }

    pub fn issue_total(&self) -> usize {
        self.by_severity.values().sum()
    }
}

/// The outcome of one analysis run.
#[derive(Clone, Debug)]
pub struct AnalysisReport {
    issues: Vec<Issue>,
    metrics: Metrics,
}

impl AnalysisReport {
    pub fn new(issues: Vec<Issue>, metrics: Metrics) -> Self {
        Self { issues, metrics }
    }

    pub fn issues(&self) -> &[Issue] {
        &self.issues
    }

    pub fn metrics(&self) -> &Metrics {
        &self.metrics
    }

    /// Highest severity present in the report, if any issue was found.
    pub fn max_severity(&self) -> Option<Severity> {
        self.issues.iter().map(Issue::severity).max()
    }
}

/// A request to analyze a project checked out at a path reachable by a worker.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScanJob {
    project: String,
    path: String,
}

#[derive(Debug, thiserror::Error)]
#[error("scan job requires non-empty project and path")]
pub struct InvalidScanJobError;

impl ScanJob {
    pub fn new(project: impl Into<String>, path: impl Into<String>) -> Result<Self, InvalidScanJobError> {
        let (project, path) = (project.into(), path.into());
        if project.is_empty() || path.is_empty() {
            return Err(InvalidScanJobError);
        }
        Ok(Self { project, path })
    }

    pub fn project(&self) -> &str {
        &self.project
    }

    pub fn path(&self) -> &str {
        &self.path
    }
}
