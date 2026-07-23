use std::collections::BTreeMap;
use yunq_cpd::DuplicateBlock;
use yunq_profiles::{MetricKey, Rating, Severity};

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
            "duplicated_lines" => Some(self.metrics.duplicated_lines() as f64),
            "duplicated_blocks" => Some(self.metrics.duplicated_blocks() as f64),
            "duplicated_lines_density" => Some(self.metrics.duplicated_lines_density()),
            "coverage" => self.coverage.and_then(|c| c.percent()),
            "branch_coverage" => self.coverage.and_then(|c| c.percent_branches()),
            "tests" => self.test_report.as_ref().map(|t| t.total_tests as f64),
            "tests_passed" => self.test_report.as_ref().map(|t| t.passed_tests as f64),
            "test_failures" => self.test_report.as_ref().map(|t| t.failed_tests as f64),
            "test_errors" => self.test_report.as_ref().map(|t| t.errors as f64),
            "test_skipped" => self.test_report.as_ref().map(|t| t.skipped_tests as f64),
            "test_execution_time" => self.test_report.as_ref().map(|t| t.time_seconds),
            "test_success_density" => self.test_report.as_ref().and_then(|t| t.pass_rate()),
            "hotspots_to_review" => Some(
                self.hotspots.iter().filter(|h| h.status() == HotspotStatus::ToReview).count()
                    as f64,
            ),
            "debt_minutes" => Some(self.metrics.debt_minutes() as f64),
            "functions" => Some(self.metrics.functions() as f64),
            "classes" => Some(self.metrics.classes() as f64),
            "statements" => Some(self.metrics.statements() as f64),
            "comment_lines" => Some(self.metrics.comment_lines() as f64),
            "comment_lines_density" => Some(self.metrics.comment_lines_density()),
            "max_nesting_depth" => Some(self.metrics.max_nesting_depth() as f64),
            _ => None,
        }
    }
}

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
}
