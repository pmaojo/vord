use std::collections::BTreeMap;
use std::fmt;

use yunq_ast::Span;
use yunq_profiles::{MetricKey, Rating, RuleId, Severity};

/// Workflow state of a tracked issue.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IssueStatus {
    Open,
    Confirmed,
    Resolved,
    Closed,
}

impl IssueStatus {
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "open" => Some(IssueStatus::Open),
            "confirmed" => Some(IssueStatus::Confirmed),
            "resolved" => Some(IssueStatus::Resolved),
            "closed" => Some(IssueStatus::Closed),
            _ => None,
        }
    }
}

impl fmt::Display for IssueStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            IssueStatus::Open => "open",
            IssueStatus::Confirmed => "confirmed",
            IssueStatus::Resolved => "resolved",
            IssueStatus::Closed => "closed",
        })
    }
}

/// Why a resolved issue was resolved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Resolution {
    Fixed,
    WontFix,
    FalsePositive,
}

impl Resolution {
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "fixed" => Some(Resolution::Fixed),
            "wont-fix" => Some(Resolution::WontFix),
            "false-positive" => Some(Resolution::FalsePositive),
            _ => None,
        }
    }
}

impl fmt::Display for Resolution {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Resolution::Fixed => "fixed",
            Resolution::WontFix => "wont-fix",
            Resolution::FalsePositive => "false-positive",
        })
    }
}

/// A workflow action on an issue.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IssueTransition {
    Confirm,
    Resolve(Resolution),
    Reopen,
    Close,
}

#[derive(Debug, thiserror::Error)]
#[error("cannot apply {transition:?} to an issue in status {from}")]
pub struct InvalidTransitionError {
    pub from: IssueStatus,
    pub transition: IssueTransition,
}

#[derive(Debug, thiserror::Error)]
#[error("inconsistent stored issue state: status {status} with resolution {resolution:?}")]
pub struct InvalidIssueStateError {
    pub status: IssueStatus,
    pub resolution: Option<Resolution>,
}

/// An issue as persisted by a storage adapter, carrying its storage identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredIssue {
    pub id: i64,
    pub issue: Issue,
}

/// A hotspot as persisted by a storage adapter, carrying its storage identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredHotspot {
    pub id: i64,
    pub hotspot: Hotspot,
}

/// A single detected problem, located in a file, with its workflow state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Issue {
    rule: RuleId,
    severity: Severity,
    message: String,
    file: String,
    span: Span,
    status: IssueStatus,
    resolution: Option<Resolution>,
    assignee: Option<String>,
}

impl Issue {
    pub fn new(
        rule: RuleId,
        severity: Severity,
        message: impl Into<String>,
        file: impl Into<String>,
        span: Span,
    ) -> Self {
        Self {
            rule,
            severity,
            message: message.into(),
            file: file.into(),
            span,
            status: IssueStatus::Open,
            resolution: None,
            assignee: None,
        }
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

    /// Rehydrates a persisted issue, validating that the stored workflow
    /// state is one the state machine can actually produce — corrupt rows
    /// become errors at the boundary, never invalid domain values.
    #[allow(clippy::too_many_arguments)]
    pub fn restore(
        rule: RuleId,
        severity: Severity,
        message: impl Into<String>,
        file: impl Into<String>,
        span: Span,
        status: IssueStatus,
        resolution: Option<Resolution>,
        assignee: Option<String>,
    ) -> Result<Self, InvalidIssueStateError> {
        let valid = matches!(
            (status, resolution),
            (IssueStatus::Open | IssueStatus::Confirmed, None)
                | (IssueStatus::Resolved, Some(_))
                | (IssueStatus::Closed, _)
        );
        if !valid {
            return Err(InvalidIssueStateError { status, resolution });
        }
        let mut issue = Self::new(rule, severity, message, file, span);
        issue.status = status;
        issue.resolution = resolution;
        issue.assignee = assignee;
        Ok(issue)
    }

    pub fn status(&self) -> IssueStatus {
        self.status
    }

    pub fn resolution(&self) -> Option<Resolution> {
        self.resolution
    }

    pub fn assignee(&self) -> Option<&str> {
        self.assignee.as_deref()
    }

    pub fn assign(&mut self, user: impl Into<String>) {
        self.assignee = Some(user.into());
    }

    pub fn unassign(&mut self) {
        self.assignee = None;
    }

    /// Applies a workflow transition, enforcing the issue state machine:
    /// open → confirmed → resolved(with resolution) → closed, with reopen
    /// from resolved. Illegal moves are rejected, never silently coerced.
    pub fn apply(&mut self, transition: IssueTransition) -> Result<(), InvalidTransitionError> {
        let next = match (self.status, transition) {
            (IssueStatus::Open, IssueTransition::Confirm) => (IssueStatus::Confirmed, None),
            (IssueStatus::Open | IssueStatus::Confirmed, IssueTransition::Resolve(resolution)) => {
                (IssueStatus::Resolved, Some(resolution))
            }
            (IssueStatus::Resolved, IssueTransition::Reopen) => (IssueStatus::Open, None),
            (IssueStatus::Resolved, IssueTransition::Close) => (IssueStatus::Closed, self.resolution),
            (from, transition) => return Err(InvalidTransitionError { from, transition }),
        };
        (self.status, self.resolution) = next;
        Ok(())
    }
}

/// Review state of a security hotspot. Unlike issues, hotspots are not
/// necessarily problems — they are security-sensitive code that a human must
/// look at and judge.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HotspotStatus {
    ToReview,
    Acknowledged,
    Fixed,
    Safe,
}

impl HotspotStatus {
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "to-review" => Some(HotspotStatus::ToReview),
            "acknowledged" => Some(HotspotStatus::Acknowledged),
            "fixed" => Some(HotspotStatus::Fixed),
            "safe" => Some(HotspotStatus::Safe),
            _ => None,
        }
    }
}

impl fmt::Display for HotspotStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            HotspotStatus::ToReview => "to-review",
            HotspotStatus::Acknowledged => "acknowledged",
            HotspotStatus::Fixed => "fixed",
            HotspotStatus::Safe => "safe",
        })
    }
}

/// Security-sensitive code requiring human review.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hotspot {
    rule: RuleId,
    message: String,
    file: String,
    span: Span,
    status: HotspotStatus,
}

impl Hotspot {
    pub fn new(rule: RuleId, message: impl Into<String>, file: impl Into<String>, span: Span) -> Self {
        Self {
            rule,
            message: message.into(),
            file: file.into(),
            span,
            status: HotspotStatus::ToReview,
        }
    }

    /// Rehydrates a persisted hotspot with its review state.
    pub fn restore(
        rule: RuleId,
        message: impl Into<String>,
        file: impl Into<String>,
        span: Span,
        status: HotspotStatus,
    ) -> Self {
        Self { rule, message: message.into(), file: file.into(), span, status }
    }

    pub fn rule(&self) -> &RuleId {
        &self.rule
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

    pub fn status(&self) -> HotspotStatus {
        self.status
    }

    /// Records the reviewer's verdict.
    pub fn review(&mut self, status: HotspotStatus) {
        self.status = status;
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
    debt_minutes: usize,
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

    pub fn add_debt(&mut self, minutes: usize) {
        self.debt_minutes += minutes;
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

    /// Estimated remediation effort for all detected issues, in minutes.
    pub fn debt_minutes(&self) -> usize {
        self.debt_minutes
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
    hotspots: Vec<Hotspot>,
    metrics: Metrics,
}

impl AnalysisReport {
    pub fn new(issues: Vec<Issue>, hotspots: Vec<Hotspot>, metrics: Metrics) -> Self {
        Self { issues, hotspots, metrics }
    }

    pub fn issues(&self) -> &[Issue] {
        &self.issues
    }

    pub fn hotspots(&self) -> &[Hotspot] {
        &self.hotspots
    }

    pub fn metrics(&self) -> &Metrics {
        &self.metrics
    }

    /// Highest severity present in the report, if any issue was found.
    pub fn max_severity(&self) -> Option<Severity> {
        self.issues.iter().map(Issue::severity).max()
    }

    /// A–E rating derived from the worst severity in the report.
    pub fn rating(&self) -> Rating {
        Rating::from_worst_severity(self.max_severity())
    }

    /// Resolves a measure by key for quality-gate evaluation.
    /// Unknown keys yield `None` (the gate treats them as NoValue).
    pub fn measure(&self, key: &MetricKey) -> Option<f64> {
        let severity_count = |severity: Severity| {
            *self.metrics.issues_by_severity().get(&severity).unwrap_or(&0) as f64
        };
        match key.as_str() {
            "files_scanned" => Some(self.metrics.files_scanned() as f64),
            "lines_of_code" => Some(self.metrics.lines_of_code() as f64),
            "parse_failures" => Some(self.metrics.parse_failures() as f64),
            "issue_total" => Some(self.metrics.issue_total() as f64),
            "blocker_issues" => Some(severity_count(Severity::Blocker)),
            "critical_issues" => Some(severity_count(Severity::Critical)),
            "major_issues" => Some(severity_count(Severity::Major)),
            "minor_issues" => Some(severity_count(Severity::Minor)),
            "info_issues" => Some(severity_count(Severity::Info)),
            "hotspots" => Some(self.hotspots.len() as f64),
            "hotspots_to_review" => Some(
                self.hotspots.iter().filter(|h| h.status() == HotspotStatus::ToReview).count()
                    as f64,
            ),
            "debt_minutes" => Some(self.metrics.debt_minutes() as f64),
            _ => None,
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn issue() -> Issue {
        Issue::new(
            RuleId::new("test:rule").unwrap(),
            Severity::Major,
            "msg",
            "a.rs",
            Span::new(1, 1, 1, 2),
        )
    }

    #[test]
    fn issue_lifecycle_happy_path() {
        let mut issue = issue();
        assert_eq!(issue.status(), IssueStatus::Open);

        issue.apply(IssueTransition::Confirm).unwrap();
        assert_eq!(issue.status(), IssueStatus::Confirmed);

        issue.apply(IssueTransition::Resolve(Resolution::FalsePositive)).unwrap();
        assert_eq!(issue.status(), IssueStatus::Resolved);
        assert_eq!(issue.resolution(), Some(Resolution::FalsePositive));

        issue.apply(IssueTransition::Reopen).unwrap();
        assert_eq!(issue.status(), IssueStatus::Open);
        assert_eq!(issue.resolution(), None);

        issue.apply(IssueTransition::Resolve(Resolution::Fixed)).unwrap();
        issue.apply(IssueTransition::Close).unwrap();
        assert_eq!(issue.status(), IssueStatus::Closed);
        assert_eq!(issue.resolution(), Some(Resolution::Fixed));
    }

    #[test]
    fn illegal_transitions_are_rejected() {
        let mut issue = issue();
        assert!(issue.apply(IssueTransition::Reopen).is_err());
        assert!(issue.apply(IssueTransition::Close).is_err());
        issue.apply(IssueTransition::Resolve(Resolution::Fixed)).unwrap();
        assert!(issue.apply(IssueTransition::Confirm).is_err());
    }

    #[test]
    fn issue_assignment() {
        let mut issue = issue();
        assert_eq!(issue.assignee(), None);
        issue.assign("alice");
        assert_eq!(issue.assignee(), Some("alice"));
        issue.unassign();
        assert_eq!(issue.assignee(), None);
    }

    #[test]
    fn report_measures_and_rating() {
        let mut metrics = Metrics::new();
        metrics.add_file(100);
        metrics.count_issue(Severity::Critical);
        metrics.count_issue(Severity::Info);
        let report = AnalysisReport::new(vec![issue()], vec![], metrics);

        let key = |raw: &str| MetricKey::new(raw).unwrap();
        assert_eq!(report.measure(&key("lines_of_code")), Some(100.0));
        assert_eq!(report.measure(&key("critical_issues")), Some(1.0));
        assert_eq!(report.measure(&key("blocker_issues")), Some(0.0));
        assert_eq!(report.measure(&key("issue_total")), Some(2.0));
        assert_eq!(report.measure(&key("unknown_metric")), None);
        // Rating comes from the worst *issue* severity present.
        assert_eq!(report.rating(), Rating::C);
    }
}
