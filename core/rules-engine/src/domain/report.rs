use std::collections::BTreeMap;
use yunq_cpd::DuplicateBlock;
use yunq_profiles::{IssueType, MetricKey, Rating, RemediationEffortSummary, RuleId, Severity};

use super::hotspot::{Hotspot, HotspotStatus};
use super::issue::Issue;
use crate::structural_metrics::StructuralCounts;

/// Aggregated counters for one analysis run.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Metrics {
    files_scanned: usize,
    files_skipped: usize,
    parse_failures: usize,
    cache_hits: usize,
    lines_of_code: usize,
    debt_minutes: usize,
    duplicated_lines: usize,
    duplicated_blocks: usize,
    by_severity: BTreeMap<Severity, usize>,
    functions: usize,
    classes: usize,
    statements: usize,
    comment_lines: usize,
    max_nesting_depth: usize,
    reliability_rating: Rating,
    security_rating: Rating,
    remediation_effort: RemediationEffortSummary,
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

    pub fn set_duplication(&mut self, duplicated_lines: usize, duplicated_blocks: usize) {
        self.duplicated_lines = duplicated_lines;
        self.duplicated_blocks = duplicated_blocks;
    }

    /// Folds one file's structural counters into the run-wide totals.
    /// `max_nesting_depth` aggregates as a max, not a sum — it is a depth,
    /// not a count.
    pub fn add_structural(&mut self, structural: StructuralCounts) {
        self.functions += structural.functions;
        self.classes += structural.classes;
        self.statements += structural.statements;
        self.comment_lines += structural.comment_lines;
        self.max_nesting_depth = self.max_nesting_depth.max(structural.max_nesting_depth);
    }

    pub fn count_issue(&mut self, severity: Severity) {
        *self.by_severity.entry(severity).or_default() += 1;
    }

    /// Folds one issue's classic type + severity into the running
    /// Reliability/Security ratings — worst [`Rating::from_severity`] wins
    /// within each type, mirroring `reliability_and_security_ratings`, with
    /// code smells touching neither — and its remediation cost into the
    /// by-rule/by-component debt breakdown (every issue counts toward this
    /// regardless of type, same population as [`Self::add_debt`]'s total).
    pub fn record_issue_type_and_effort(
        &mut self,
        issue_type: IssueType,
        severity: Severity,
        rule: RuleId,
        component: &str,
        minutes: u32,
    ) {
        let rating = Rating::from_severity(severity);
        match issue_type {
            IssueType::Bug => self.reliability_rating = self.reliability_rating.max(rating),
            IssueType::Vulnerability => self.security_rating = self.security_rating.max(rating),
            IssueType::CodeSmell => {}
        }
        *self.remediation_effort.by_rule.entry(rule).or_insert(0) += minutes;
        *self.remediation_effort.by_component.entry(component.to_string()).or_insert(0) += minutes;
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

    pub fn cache_hits(&self) -> usize {
        self.cache_hits
    }

    pub fn debt_minutes(&self) -> usize {
        self.debt_minutes
    }

    pub fn duplicated_lines(&self) -> usize {
        self.duplicated_lines
    }

    pub fn duplicated_blocks(&self) -> usize {
        self.duplicated_blocks
    }

    pub fn duplicated_lines_density(&self) -> f64 {
        if self.lines_of_code == 0 {
            0.0
        } else {
            self.duplicated_lines as f64 * 100.0 / self.lines_of_code as f64
        }
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

    pub fn functions(&self) -> usize {
        self.functions
    }

    pub fn classes(&self) -> usize {
        self.classes
    }

    pub fn statements(&self) -> usize {
        self.statements
    }

    pub fn comment_lines(&self) -> usize {
        self.comment_lines
    }

    pub fn max_nesting_depth(&self) -> usize {
        self.max_nesting_depth
    }

    /// Worst [`Rating::from_severity`] among open `Bug` issues (`A` if
    /// there are none) — independent of Maintainability's debt-ratio grid.
    pub fn reliability_rating(&self) -> Rating {
        self.reliability_rating
    }

    /// Same algorithm as [`Self::reliability_rating`], over `Vulnerability`
    /// issues instead of `Bug`s.
    pub fn security_rating(&self) -> Rating {
        self.security_rating
    }

    /// Cumulative remediation effort grouped by rule and by component —
    /// which rule generates the most debt, and which file would benefit
    /// most from cleanup.
    pub fn remediation_effort(&self) -> &RemediationEffortSummary {
        &self.remediation_effort
    }

    /// SonarQube's formula: comments as a share of comments + code lines.
    pub fn comment_lines_density(&self) -> f64 {
        let denominator = self.lines_of_code + self.comment_lines;
        if denominator == 0 {
            0.0
        } else {
            self.comment_lines as f64 * 100.0 / denominator as f64
        }
    }
}

/// Line- and branch-coverage totals ingested from an external test-coverage
/// report (LCOV, Cobertura, JaCoCo, llvm-cov or Istanbul). Branch totals are
/// zero (and `percent_branches()` is `None`) for formats/records that carry
/// no branch data — the same "absent means not reported" convention as
/// `percent()` already uses for lines.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CoverageSummary {
    covered_lines: usize,
    coverable_lines: usize,
    covered_branches: usize,
    coverable_branches: usize,
}

#[derive(Debug, thiserror::Error)]
#[error("covered amount ({covered}) cannot exceed coverable amount ({coverable})")]
pub struct InvalidCoverageError {
    pub covered: usize,
    pub coverable: usize,
}

impl CoverageSummary {
    pub fn new(covered_lines: usize, coverable_lines: usize) -> Result<Self, InvalidCoverageError> {
        if covered_lines > coverable_lines {
            return Err(InvalidCoverageError { covered: covered_lines, coverable: coverable_lines });
        }
        Ok(Self { covered_lines, coverable_lines, covered_branches: 0, coverable_branches: 0 })
    }

    pub fn add(&mut self, covered: usize, coverable: usize) -> Result<(), InvalidCoverageError> {
        if covered > coverable {
            return Err(InvalidCoverageError { covered, coverable });
        }
        self.covered_lines += covered;
        self.coverable_lines += coverable;
        Ok(())
    }

    /// Same contract as [`Self::add`], for branch (not line) totals.
    pub fn add_branches(&mut self, covered: usize, coverable: usize) -> Result<(), InvalidCoverageError> {
        if covered > coverable {
            return Err(InvalidCoverageError { covered, coverable });
        }
        self.covered_branches += covered;
        self.coverable_branches += coverable;
        Ok(())
    }

    pub fn covered_lines(&self) -> usize {
        self.covered_lines
    }

    pub fn coverable_lines(&self) -> usize {
        self.coverable_lines
    }

    pub fn covered_branches(&self) -> usize {
        self.covered_branches
    }

    pub fn coverable_branches(&self) -> usize {
        self.coverable_branches
    }

    pub fn percent(&self) -> Option<f64> {
        if self.coverable_lines == 0 {
            None
        } else {
            Some(self.covered_lines as f64 * 100.0 / self.coverable_lines as f64)
        }
    }

    pub fn percent_branches(&self) -> Option<f64> {
        if self.coverable_branches == 0 {
            None
        } else {
            Some(self.covered_branches as f64 * 100.0 / self.coverable_branches as f64)
        }
    }
}

/// Per-file line-coverage detail: every instrumented line and its hit count.
/// Kept separate from [`CoverageSummary`] (which stays a flat, `Copy`
/// aggregate used everywhere today) so ingesting per-file/per-line detail is
/// additive and does not disturb existing call sites. Used to restrict
/// coverage to a set of "new" (changed) lines — see
/// [`CoverageReport::coverage_on_new_code`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FileCoverage {
    path: String,
    /// 1-based line number -> hit count (0 = instrumented but not executed).
    lines: BTreeMap<u32, usize>,
}

impl FileCoverage {
    pub fn new(path: impl Into<String>) -> Self {
        Self { path: path.into(), lines: BTreeMap::new() }
    }

    /// Records one instrumented line's hit count. When the same line is
    /// recorded more than once (e.g. several statements on one line in an
    /// Istanbul report), the highest count wins — enough to answer "was this
    /// line ever executed", which is all coverage-on-new-code needs.
    pub fn record_line(&mut self, line: u32, hits: usize) {
        self.lines.entry(line).and_modify(|h| *h = (*h).max(hits)).or_insert(hits);
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn lines(&self) -> &BTreeMap<u32, usize> {
        &self.lines
    }

    pub fn covered_lines(&self) -> usize {
        self.lines.values().filter(|&&hits| hits > 0).count()
    }

    pub fn coverable_lines(&self) -> usize {
        self.lines.len()
    }
}

/// Per-file coverage detail for one ingested report, plus the report-wide
/// line/branch totals. The totals are carried explicitly rather than derived
/// by re-summing `files` because several formats have their own authoritative
/// summary counters (LCOV's `LH:`/`LF:`/`BRH:`/`BRF:`, Cobertura's/JaCoCo's
/// root/counter totals) that are preferred over a raw per-line recount when
/// both are present — the per-file detail exists purely to answer
/// "coverage restricted to these lines", not to redefine the totals.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CoverageReport {
    files: Vec<FileCoverage>,
    covered_lines: usize,
    coverable_lines: usize,
    covered_branches: usize,
    coverable_branches: usize,
}

impl CoverageReport {
    pub fn new(
        files: Vec<FileCoverage>,
        covered_lines: usize,
        coverable_lines: usize,
        covered_branches: usize,
        coverable_branches: usize,
    ) -> Self {
        Self { files, covered_lines, coverable_lines, covered_branches, coverable_branches }
    }

    pub fn files(&self) -> &[FileCoverage] {
        &self.files
    }

    /// Folds another ingested report's files and totals into this one — used
    /// when several coverage reports are merged (e.g. one per test
    /// suite/language).
    pub fn merge(&mut self, other: CoverageReport) {
        self.files.extend(other.files);
        self.covered_lines += other.covered_lines;
        self.coverable_lines += other.coverable_lines;
        self.covered_branches += other.covered_branches;
        self.coverable_branches += other.coverable_branches;
    }

    /// The flat aggregate view, equivalent to what the format-specific
    /// `parse_*` functions return directly.
    pub fn summary(&self) -> Result<CoverageSummary, InvalidCoverageError> {
        let mut summary = CoverageSummary::default();
        summary.add(self.covered_lines, self.coverable_lines)?;
        summary.add_branches(self.covered_branches, self.coverable_branches)?;
        Ok(summary)
    }

    /// Coverage restricted to the lines named in `changed_lines` (typically
    /// the added/modified lines of a unified diff against a reference
    /// branch, keyed by file path). `None` when none of the changed lines
    /// carry coverage instrumentation data — e.g. no diff was supplied, the
    /// diff touched no instrumented file, or nothing changed.
    pub fn coverage_on_new_code(
        &self,
        changed_lines: &BTreeMap<String, std::collections::BTreeSet<u32>>,
    ) -> Option<f64> {
        let mut covered = 0usize;
        let mut coverable = 0usize;
        for file in &self.files {
            let Some(changed) = changed_lines.get(file.path()) else { continue };
            for (line, hits) in file.lines() {
                if changed.contains(line) {
                    coverable += 1;
                    if *hits > 0 {
                        covered += 1;
                    }
                }
            }
        }
        if coverable == 0 {
            None
        } else {
            Some(covered as f64 * 100.0 / coverable as f64)
        }
    }
}

/// Counts and timing for one `<testsuite>` element ingested from a JUnit
/// XML test-execution report.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct TestSuiteSummary {
    pub name: String,
    pub tests: usize,
    pub passed: usize,
    pub failures: usize,
    pub errors: usize,
    pub skipped: usize,
    pub time_seconds: f64,
}

/// Aggregated test-execution counts across every `<testsuite>` ingested from
/// a JUnit XML report, plus the per-suite breakdown (`suites`).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct TestReportSummary {
    pub total_tests: usize,
    pub passed_tests: usize,
    pub failed_tests: usize,
    pub errors: usize,
    pub skipped_tests: usize,
    pub time_seconds: f64,
    pub suites: Vec<TestSuiteSummary>,
}

impl TestReportSummary {
    /// Percentage of tests that passed, or `None` when no tests ran.
    pub fn pass_rate(&self) -> Option<f64> {
        if self.total_tests == 0 {
            None
        } else {
            Some(self.passed_tests as f64 * 100.0 / self.total_tests as f64)
        }
    }
}

/// The complete output of one analysis run.
#[derive(Clone, Debug, PartialEq)]
pub struct AnalysisReport {
    issues: Vec<Issue>,
    hotspots: Vec<Hotspot>,
    coverage: Option<CoverageSummary>,
    coverage_report: Option<CoverageReport>,
    duplications: Vec<DuplicateBlock>,
    metrics: Metrics,
    test_report: Option<TestReportSummary>,
}

impl AnalysisReport {
    pub fn new(issues: Vec<Issue>, hotspots: Vec<Hotspot>, metrics: Metrics) -> Self {
        Self {
            issues,
            hotspots,
            coverage: None,
            coverage_report: None,
            duplications: Vec::new(),
            metrics,
            test_report: None,
        }
    }

    pub fn set_coverage(&mut self, coverage: CoverageSummary) {
        self.coverage = Some(coverage);
    }

    /// Ingest per-file coverage detail (line-level hit data), enabling
    /// [`AnalysisReport::coverage_on_new_code`]. Independent of
    /// `set_coverage`: callers that have per-file detail should call both,
    /// since the flat `CoverageSummary` remains the source of the `coverage`
    /// / `branch_coverage` measures.
    pub fn set_coverage_report(&mut self, coverage_report: CoverageReport) {
        self.coverage_report = Some(coverage_report);
    }

    /// Ingest a JUnit test-execution report: its aggregate counts become
    /// available as `tests`/`test_failures`/`test_errors`/`test_skipped`/
    /// `test_execution_time` measures (see [`AnalysisReport::measure`]).
    pub fn set_test_report(&mut self, test_report: TestReportSummary) {
        self.test_report = Some(test_report);
    }

    pub fn set_duplications(&mut self, duplications: Vec<DuplicateBlock>) {
        self.metrics.set_duplication(
            duplications.iter().map(|b| b.lines).sum(),
            duplications.len(),
        );
        self.duplications = duplications;
    }

    pub fn issues(&self) -> &[Issue] {
        &self.issues
    }

    pub fn hotspots(&self) -> &[Hotspot] {
        &self.hotspots
    }

    pub fn coverage(&self) -> Option<&CoverageSummary> {
        self.coverage.as_ref()
    }

    pub fn coverage_report(&self) -> Option<&CoverageReport> {
        self.coverage_report.as_ref()
    }

    /// Coverage restricted to `changed_lines` (see
    /// [`CoverageReport::coverage_on_new_code`]); `None` when no per-file
    /// coverage detail was ingested via [`Self::set_coverage_report`], or
    /// when the diff touches no instrumented line.
    pub fn coverage_on_new_code(
        &self,
        changed_lines: &BTreeMap<String, std::collections::BTreeSet<u32>>,
    ) -> Option<f64> {
        self.coverage_report.as_ref().and_then(|report| report.coverage_on_new_code(changed_lines))
    }

    pub fn test_report(&self) -> Option<&TestReportSummary> {
        self.test_report.as_ref()
    }

    pub fn duplications(&self) -> &[DuplicateBlock] {
        &self.duplications
    }

    pub fn metrics(&self) -> &Metrics {
        &self.metrics
    }

    pub fn max_severity(&self) -> Option<Severity> {
        self.issues.iter().map(Issue::severity).max()
    }

    /// Maintainability rating (A–E) from the technical debt ratio —
    /// SonarQube's SQALE model, not the worst severity present.
    pub fn rating(&self) -> Rating {
        let ratio = yunq_profiles::debt_ratio(
            self.metrics.debt_minutes() as f64,
            self.metrics.lines_of_code() as f64,
            yunq_profiles::DEFAULT_DEV_COST_MINUTES_PER_LINE,
        );
        Rating::from_debt_ratio(ratio)
    }

    /// Reliability rating (A–E): worst severity among open `Bug` issues.
    /// A different algorithm from [`Self::rating`] — a worst-severity
    /// lookup, not a cost ratio — per SonarQube's
    /// `ReliabilityAndSecurityRatingMeasuresVisitor`.
    pub fn reliability_rating(&self) -> Rating {
        self.metrics.reliability_rating()
    }

    /// Security rating (A–E): same algorithm as [`Self::reliability_rating`]
    /// over `Vulnerability` issues instead of `Bug`s.
    pub fn security_rating(&self) -> Rating {
        self.metrics.security_rating()
    }

    /// Remediation effort (minutes) aggregated by rule and by component —
    /// the drill-down view behind [`Self::rating`]'s total debt.
    pub fn remediation_effort(&self) -> &RemediationEffortSummary {
        self.metrics.remediation_effort()
    }

    pub fn health_score(&self) -> u32 {
        let blocker = *self.metrics.issues_by_severity().get(&Severity::Blocker).unwrap_or(&0) as u32;
        let critical = *self.metrics.issues_by_severity().get(&Severity::Critical).unwrap_or(&0) as u32;
        let major = *self.metrics.issues_by_severity().get(&Severity::Major).unwrap_or(&0) as u32;
        let hotspots = self.hotspots.len() as u32;
        let dup_penalty = (self.metrics.duplicated_lines_density() * 0.5) as u32;

        let penalty = blocker * 10 + critical * 5 + major + hotspots * 2 + dup_penalty;
        100u32.saturating_sub(penalty)
    }

    pub fn measure(&self, key: &MetricKey) -> Option<f64> {
        MEASURE_TABLE.iter().find(|(k, _)| *k == key.as_str()).and_then(|(_, f)| f(self))
    }

    /// Every measure this report can currently produce, keyed by metric key
    /// — the full project-level row persisted per analysis for measure
    /// history / component tree queries (issue #26). A measure absent from
    /// this report (e.g. `coverage` before any report is ingested) is
    /// omitted rather than persisted as a fabricated zero.
    pub fn all_measures(&self) -> Vec<(String, f64)> {
        MEASURE_TABLE.iter().filter_map(|(key, f)| f(self).map(|v| (key.to_string(), v))).collect()
    }

    /// Per-file issue counts (total plus one count per severity), derived
    /// from this report's issues by their `file` field — the only per-file
    /// breakdown available today without persisting per-file structural
    /// metrics (`Metrics` only tracks run-wide totals, not per file). Files
    /// with zero issues are simply absent, not zeroed; keys match the
    /// project-level names in [`MEASURE_TABLE`] (`issue_total`,
    /// `blocker_issues`, ...) so callers can treat project- and file-level
    /// measures uniformly.
    pub fn file_issue_measures(&self) -> BTreeMap<String, BTreeMap<String, f64>> {
        let mut per_file: BTreeMap<String, BTreeMap<String, f64>> = BTreeMap::new();
        for issue in &self.issues {
            let entry = per_file.entry(issue.file().to_string()).or_default();
            *entry.entry("issue_total".to_string()).or_insert(0.0) += 1.0;
            let severity_key = format!("{}_issues", issue.severity().as_str());
            *entry.entry(severity_key).or_insert(0.0) += 1.0;
        }
        per_file
    }
}

fn severity_measure(report: &AnalysisReport, severity: Severity) -> Option<f64> {
    Some(*report.metrics.issues_by_severity().get(&severity).unwrap_or(&0) as f64)
}

/// SonarQube's numeric encoding for the A–E letter ratings (`1.0`..`5.0`),
/// so ratings can drive quality gate conditions like any other measure
/// (e.g. `reliability_rating > 1.0` fails the gate on any open bug).
fn rating_measure(rating: Rating) -> f64 {
    match rating {
        Rating::A => 1.0,
        Rating::B => 2.0,
        Rating::C => 3.0,
        Rating::D => 4.0,
        Rating::E => 5.0,
    }
}

type MeasureFn = fn(&AnalysisReport) -> Option<f64>;

/// `MetricKey` -> measure lookup, replacing a 30-arm `match` (McCabe counts
/// each arm as a branch) with an `.iter().find()` — complexity 1 regardless
/// of table size.
const MEASURE_TABLE: &[(&str, MeasureFn)] = &[
    ("files_scanned", |r| Some(r.metrics.files_scanned() as f64)),
    ("lines_of_code", |r| Some(r.metrics.lines_of_code() as f64)),
    ("parse_failures", |r| Some(r.metrics.parse_failures() as f64)),
    ("issue_total", |r| Some(r.metrics.issue_total() as f64)),
    ("blocker_issues", |r| severity_measure(r, Severity::Blocker)),
    ("critical_issues", |r| severity_measure(r, Severity::Critical)),
    ("major_issues", |r| severity_measure(r, Severity::Major)),
    ("minor_issues", |r| severity_measure(r, Severity::Minor)),
    ("info_issues", |r| severity_measure(r, Severity::Info)),
    ("hotspots", |r| Some(r.hotspots.len() as f64)),
    ("duplicated_lines", |r| Some(r.metrics.duplicated_lines() as f64)),
    ("duplicated_blocks", |r| Some(r.metrics.duplicated_blocks() as f64)),
    ("duplicated_lines_density", |r| Some(r.metrics.duplicated_lines_density())),
    ("coverage", |r| r.coverage.and_then(|c| c.percent())),
    ("branch_coverage", |r| r.coverage.and_then(|c| c.percent_branches())),
    ("tests", |r| r.test_report.as_ref().map(|t| t.total_tests as f64)),
    ("tests_passed", |r| r.test_report.as_ref().map(|t| t.passed_tests as f64)),
    ("test_failures", |r| r.test_report.as_ref().map(|t| t.failed_tests as f64)),
    ("test_errors", |r| r.test_report.as_ref().map(|t| t.errors as f64)),
    ("test_skipped", |r| r.test_report.as_ref().map(|t| t.skipped_tests as f64)),
    ("test_execution_time", |r| r.test_report.as_ref().map(|t| t.time_seconds)),
    ("test_success_density", |r| r.test_report.as_ref().and_then(|t| t.pass_rate())),
    ("hotspots_to_review", |r| {
        Some(r.hotspots.iter().filter(|h| h.status() == HotspotStatus::ToReview).count() as f64)
    }),
    ("debt_minutes", |r| Some(r.metrics.debt_minutes() as f64)),
    ("functions", |r| Some(r.metrics.functions() as f64)),
    ("classes", |r| Some(r.metrics.classes() as f64)),
    ("statements", |r| Some(r.metrics.statements() as f64)),
    ("comment_lines", |r| Some(r.metrics.comment_lines() as f64)),
    ("comment_lines_density", |r| Some(r.metrics.comment_lines_density())),
    ("max_nesting_depth", |r| Some(r.metrics.max_nesting_depth() as f64)),
    ("maintainability_rating", |r| Some(rating_measure(r.rating()))),
    ("reliability_rating", |r| Some(rating_measure(r.metrics.reliability_rating()))),
    ("security_rating", |r| Some(rating_measure(r.metrics.security_rating()))),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_measures_are_absent_until_a_report_is_ingested() {
        let report = AnalysisReport::new(Vec::new(), Vec::new(), Metrics::new());
        for key in [
            "tests",
            "tests_passed",
            "test_failures",
            "test_errors",
            "test_skipped",
            "test_execution_time",
            "test_success_density",
        ] {
            assert_eq!(report.measure(&yunq_profiles::MetricKey::new(key).unwrap()), None);
        }
    }

    #[test]
    fn test_measures_expose_the_ingested_totals() {
        let mut report = AnalysisReport::new(Vec::new(), Vec::new(), Metrics::new());
        report.set_test_report(TestReportSummary {
            total_tests: 10,
            passed_tests: 6,
            failed_tests: 2,
            errors: 1,
            skipped_tests: 1,
            time_seconds: 4.5,
            suites: vec![TestSuiteSummary {
                name: "unit".to_string(),
                tests: 10,
                passed: 6,
                failures: 2,
                errors: 1,
                skipped: 1,
                time_seconds: 4.5,
            }],
        });

        let measure = |key: &str| report.measure(&yunq_profiles::MetricKey::new(key).unwrap());
        assert_eq!(measure("tests"), Some(10.0));
        assert_eq!(measure("tests_passed"), Some(6.0));
        assert_eq!(measure("test_failures"), Some(2.0));
        assert_eq!(measure("test_errors"), Some(1.0));
        assert_eq!(measure("test_skipped"), Some(1.0));
        assert_eq!(measure("test_execution_time"), Some(4.5));
        assert_eq!(measure("test_success_density"), Some(60.0));
        assert_eq!(report.test_report().unwrap().suites.len(), 1);
    }

    #[test]
    fn pass_rate_is_none_with_no_tests() {
        assert_eq!(TestReportSummary::default().pass_rate(), None);
    }

    #[test]
    fn branch_coverage_measure_is_absent_until_branches_are_added() {
        let mut report = AnalysisReport::new(Vec::new(), Vec::new(), Metrics::new());
        let key = |raw: &str| yunq_profiles::MetricKey::new(raw).unwrap();
        assert_eq!(report.measure(&key("branch_coverage")), None);

        let mut summary = CoverageSummary::default();
        summary.add(8, 10).unwrap();
        summary.add_branches(3, 4).unwrap();
        report.set_coverage(summary);

        assert_eq!(report.measure(&key("coverage")), Some(80.0));
        assert_eq!(report.measure(&key("branch_coverage")), Some(75.0));
    }

    #[test]
    fn coverage_summary_add_branches_rejects_covered_over_coverable() {
        let mut summary = CoverageSummary::default();
        assert!(summary.add_branches(2, 1).is_err());
    }

    #[test]
    fn coverage_report_summary_uses_the_explicit_totals() {
        let mut a = FileCoverage::new("src/a.rs");
        a.record_line(1, 1);
        a.record_line(2, 0);
        let mut b = FileCoverage::new("src/b.rs");
        b.record_line(1, 0);
        b.record_line(2, 5);
        b.record_line(3, 0);

        let coverage_report = CoverageReport::new(vec![a, b], 2, 5, 3, 5);
        let summary = coverage_report.summary().unwrap();
        assert_eq!(summary.covered_lines(), 2);
        assert_eq!(summary.coverable_lines(), 5);
        assert_eq!(summary.covered_branches(), 3);
        assert_eq!(summary.coverable_branches(), 5);
    }

    #[test]
    fn coverage_on_new_code_restricts_to_changed_lines() {
        let mut a = FileCoverage::new("src/a.rs");
        a.record_line(1, 1); // unchanged, covered
        a.record_line(2, 0); // changed, uncovered
        a.record_line(3, 4); // changed, covered
        let coverage_report = CoverageReport::new(vec![a], 2, 3, 0, 0);

        let mut changed: BTreeMap<String, std::collections::BTreeSet<u32>> = BTreeMap::new();
        changed.insert("src/a.rs".to_string(), [2u32, 3].into_iter().collect());

        let percent = coverage_report.coverage_on_new_code(&changed).unwrap();
        assert!((percent - 50.0).abs() < f64::EPSILON);
    }

    #[test]
    fn coverage_on_new_code_is_none_without_matching_changed_lines() {
        let mut a = FileCoverage::new("src/a.rs");
        a.record_line(1, 1);
        let coverage_report = CoverageReport::new(vec![a], 1, 1, 0, 0);
        assert_eq!(coverage_report.coverage_on_new_code(&BTreeMap::new()), None);
    }

    #[test]
    fn report_coverage_on_new_code_delegates_to_the_coverage_report() {
        let mut report = AnalysisReport::new(Vec::new(), Vec::new(), Metrics::new());
        assert_eq!(report.coverage_on_new_code(&BTreeMap::new()), None);

        let mut file = FileCoverage::new("src/a.rs");
        file.record_line(10, 0);
        file.record_line(11, 2);
        report.set_coverage_report(CoverageReport::new(vec![file], 1, 2, 0, 0));

        let mut changed: BTreeMap<String, std::collections::BTreeSet<u32>> = BTreeMap::new();
        changed.insert("src/a.rs".to_string(), [10u32, 11].into_iter().collect());
        assert_eq!(report.coverage_on_new_code(&changed), Some(50.0));
    }

    fn rule(id: &str) -> RuleId {
        RuleId::new(id).unwrap()
    }

    #[test]
    fn no_bugs_or_vulnerabilities_recorded_means_both_ratings_default_to_a() {
        let mut metrics = Metrics::new();
        metrics.record_issue_type_and_effort(IssueType::CodeSmell, Severity::Blocker, rule("smells:x"), "a.rs", 5);
        assert_eq!(metrics.reliability_rating(), Rating::A);
        assert_eq!(metrics.security_rating(), Rating::A);
    }

    #[test]
    fn reliability_and_security_ratings_track_worst_severity_independently() {
        let mut metrics = Metrics::new();
        metrics.record_issue_type_and_effort(IssueType::Bug, Severity::Minor, rule("bugs:a"), "a.rs", 5);
        metrics.record_issue_type_and_effort(IssueType::Bug, Severity::Critical, rule("bugs:b"), "b.rs", 10);
        metrics.record_issue_type_and_effort(IssueType::Vulnerability, Severity::Major, rule("owasp:c"), "c.rs", 15);
        // Worst bug (Critical -> D) drives reliability...
        assert_eq!(metrics.reliability_rating(), Rating::D);
        // ...independently of the worst vulnerability (Major -> C).
        assert_eq!(metrics.security_rating(), Rating::C);
    }

    #[test]
    fn remediation_effort_accumulates_by_rule_and_component_across_all_issue_types() {
        let mut metrics = Metrics::new();
        let bug_rule = rule("bugs:null-deref");
        metrics.record_issue_type_and_effort(IssueType::Bug, Severity::Major, bug_rule.clone(), "a.rs", 20);
        metrics.record_issue_type_and_effort(IssueType::Bug, Severity::Major, bug_rule.clone(), "b.rs", 20);
        metrics.record_issue_type_and_effort(IssueType::CodeSmell, Severity::Minor, rule("smells:x"), "a.rs", 30);

        let effort = metrics.remediation_effort();
        assert_eq!(effort.by_rule[&bug_rule], 40);
        assert_eq!(effort.by_component["a.rs"], 50);
        assert_eq!(effort.by_component["b.rs"], 20);
    }

    #[test]
    fn all_measures_omits_measures_absent_from_the_report() {
        let report = AnalysisReport::new(Vec::new(), Vec::new(), Metrics::new());
        let measures = report.all_measures();
        let keys: Vec<&str> = measures.iter().map(|(k, _)| k.as_str()).collect();
        assert!(!keys.contains(&"coverage"));
        assert!(!keys.contains(&"tests"));
        // Always-present counters (defaulted to 0 by `Metrics::default`) are there.
        assert!(keys.contains(&"lines_of_code"));
        assert!(keys.contains(&"issue_total"));
    }

    #[test]
    fn all_measures_includes_ingested_coverage() {
        let mut report = AnalysisReport::new(Vec::new(), Vec::new(), Metrics::new());
        let mut summary = CoverageSummary::default();
        summary.add(8, 10).unwrap();
        report.set_coverage(summary);
        let measures: BTreeMap<String, f64> = report.all_measures().into_iter().collect();
        assert_eq!(measures.get("coverage"), Some(&80.0));
    }

    #[test]
    fn file_issue_measures_groups_by_file_and_severity() {
        let issues = vec![
            Issue::new(
                RuleId::new("owasp:sql-injection").unwrap(),
                Severity::Blocker,
                "boom",
                "src/a.rs",
                yunq_ast::Span::new(1, 0, 1, 1),
            ),
            Issue::new(
                RuleId::new("owasp:sql-injection").unwrap(),
                Severity::Blocker,
                "boom again",
                "src/a.rs",
                yunq_ast::Span::new(2, 0, 2, 1),
            ),
            Issue::new(
                RuleId::new("smells:x").unwrap(),
                Severity::Minor,
                "smell",
                "src/b.rs",
                yunq_ast::Span::new(1, 0, 1, 1),
            ),
        ];
        let report = AnalysisReport::new(issues, Vec::new(), Metrics::new());
        let per_file = report.file_issue_measures();

        let a = &per_file["src/a.rs"];
        assert_eq!(a["issue_total"], 2.0);
        assert_eq!(a["blocker_issues"], 2.0);
        assert!(!a.contains_key("minor_issues"));

        let b = &per_file["src/b.rs"];
        assert_eq!(b["issue_total"], 1.0);
        assert_eq!(b["minor_issues"], 1.0);

        assert_eq!(per_file.len(), 2);
    }

    #[test]
    fn file_issue_measures_is_empty_without_issues() {
        let report = AnalysisReport::new(Vec::new(), Vec::new(), Metrics::new());
        assert!(report.file_issue_measures().is_empty());
    }

    #[test]
    fn rating_measures_are_exposed_on_the_report() {
        let mut metrics = Metrics::new();
        metrics.record_issue_type_and_effort(IssueType::Bug, Severity::Blocker, rule("bugs:a"), "a.rs", 5);
        metrics.record_issue_type_and_effort(IssueType::Vulnerability, Severity::Minor, rule("owasp:b"), "b.rs", 5);
        let report = AnalysisReport::new(Vec::new(), Vec::new(), metrics);

        assert_eq!(report.reliability_rating(), Rating::E);
        assert_eq!(report.security_rating(), Rating::B);
        let key = |raw: &str| yunq_profiles::MetricKey::new(raw).unwrap();
        assert_eq!(report.measure(&key("reliability_rating")), Some(5.0));
        assert_eq!(report.measure(&key("security_rating")), Some(2.0));
        assert_eq!(report.measure(&key("maintainability_rating")), Some(1.0));
    }
}
