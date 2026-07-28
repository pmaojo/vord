use std::collections::BTreeMap;
use yunq_cpd::{DuplicateBlock, DuplicationReport};
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
    structural: StructuralCounts,
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
        self.structural.functions += structural.functions;
        self.structural.classes += structural.classes;
        self.structural.statements += structural.statements;
        self.structural.comment_lines += structural.comment_lines;
        self.structural.max_nesting_depth = self.structural.max_nesting_depth.max(structural.max_nesting_depth);
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

    /// A percentage, so callers may assume `0.0..=100.0`. `duplicated_lines`
    /// counts distinct *line numbers* the duplication detector touched
    /// (which, inside a matched block, includes any blank/comment lines
    /// straddled by the surrounding duplicate statements), while
    /// `lines_of_code` counts only real code lines — a codebase with heavy
    /// commenting can therefore see `duplicated_lines` exceed
    /// `lines_of_code`. Clamped rather than left to overshoot 100%: a
    /// "density" above the whole is meaningless to every caller of this
    /// measure, not just `AnalysisReport::health_score`, whose duplication
    /// penalty an unclamped value could otherwise blow past any bound.
    pub fn duplicated_lines_density(&self) -> f64 {
        if self.lines_of_code == 0 {
            0.0
        } else {
            (self.duplicated_lines as f64 * 100.0 / self.lines_of_code as f64).min(100.0)
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
        self.structural.functions
    }

    pub fn classes(&self) -> usize {
        self.structural.classes
    }

    pub fn statements(&self) -> usize {
        self.structural.statements
    }

    pub fn comment_lines(&self) -> usize {
        self.structural.comment_lines
    }

    pub fn max_nesting_depth(&self) -> usize {
        self.structural.max_nesting_depth
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

    /// Comments as a share of comments + code lines.
    pub fn comment_lines_density(&self) -> f64 {
        let denominator = self.lines_of_code + self.structural.comment_lines;
        if denominator == 0 {
            0.0
        } else {
            self.structural.comment_lines as f64 * 100.0 / denominator as f64
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

/// One source line's SCM blame: which commit last touched it and who
/// authored that commit. Field-for-field the same shape as the CLI's
/// `blame::BlameLine` (`bin/cli/src/blame.rs`, issue #33) so a
/// `--blame-output` JSON file can be POSTed to `/api/projects/{key}/blame`
/// without any reshaping.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BlameLineInfo {
    pub commit: String,
    pub author: String,
    pub author_mail: String,
    /// Unix timestamp (seconds) from the commit's `author-time`.
    pub author_time: i64,
    pub summary: String,
}

/// Per-file line-blame detail: every line's SCM attribution, keyed by
/// 1-based line number. Analogous to [`FileCoverage`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FileBlame {
    path: String,
    lines: BTreeMap<u32, BlameLineInfo>,
}

impl FileBlame {
    pub fn new(path: impl Into<String>) -> Self {
        Self { path: path.into(), lines: BTreeMap::new() }
    }

    pub fn record_line(&mut self, line: u32, info: BlameLineInfo) {
        self.lines.insert(line, info);
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn lines(&self) -> &BTreeMap<u32, BlameLineInfo> {
        &self.lines
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

/// Per-status mutant counts ingested from an external mutation-testing
/// report (the Stryker "Mutation Testing Elements" JSON schema — StrykerJS,
/// Stryker.NET, and Infection via its Stryker-format exporter all emit it).
/// yunq runs no mutants itself; this only aggregates another tool's
/// verdicts, the same relationship [`CoverageReport`] has to LCOV/Cobertura.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MutationSummary {
    pub total_mutants: usize,
    pub killed_mutants: usize,
    pub survived_mutants: usize,
    pub timeout_mutants: usize,
    pub no_coverage_mutants: usize,
    pub ignored_mutants: usize,
    /// `CompileError` + `RuntimeError` mutants — broken, not undetected.
    pub error_mutants: usize,
    pub pending_mutants: usize,
}

impl MutationSummary {
    /// Stryker's own formula: detected (`killed` + `timeout`) over valid
    /// (`killed` + `timeout` + `survived` + `no_coverage`). `ignored`,
    /// `error` and `pending` mutants count toward neither side — an agent
    /// cannot raise the score by causing compile errors, and a project with
    /// no un-ignored mutants reports no score rather than a fabricated 100%.
    pub fn mutation_score(&self) -> Option<f64> {
        let detected = self.killed_mutants + self.timeout_mutants;
        let valid = detected + self.survived_mutants + self.no_coverage_mutants;
        if valid == 0 {
            None
        } else {
            Some(detected as f64 * 100.0 / valid as f64)
        }
    }
}

/// An issue produced outside the rule engine — imported from another
/// analyzer's report rather than detected by a [`crate::Rule`].
///
/// It carries the two facts the engine would otherwise read off the `Rule`
/// trait object (`issue_type`, `remediation_effort_minutes`) so an imported
/// finding folds into ratings and debt exactly like a native one. Importers
/// that have no basis for an effort estimate should pass `0` rather than
/// invent a number — a fabricated effort silently moves the maintainability
/// rating.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExternalIssue {
    pub issue: Issue,
    pub issue_type: IssueType,
    pub remediation_effort_minutes: u32,
}

impl ExternalIssue {
    /// An imported issue with no effort estimate — the common case, since
    /// no mainstream interchange format carries remediation cost.
    pub fn new(issue: Issue, issue_type: IssueType) -> Self {
        Self { issue, issue_type, remediation_effort_minutes: 0 }
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
    mutation: Option<MutationSummary>,
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
            mutation: None,
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

    /// Ingest a mutation-testing report: its per-status mutant counts
    /// become available as `mutants`/`mutants_killed`/`mutants_survived`/
    /// `mutants_timeout`/`mutants_no_coverage`/`mutation_score` measures
    /// (see [`AnalysisReport::measure`]), so a mutation-testing gate
    /// condition works the same way a coverage one does.
    pub fn set_mutation(&mut self, mutation: MutationSummary) {
        self.mutation = Some(mutation);
    }

    /// Stores the detected duplicate blocks and folds the detector's own
    /// counters into the metrics.
    ///
    /// Takes the whole [`DuplicationReport`] rather than just its blocks
    /// because `duplicated_lines` cannot be recovered from the blocks
    /// alone. Blocks are *pairs*, and one duplicated region shared by `n`
    /// files produces `n*(n-1)/2` of them over the same lines, so summing
    /// each pair's span counts most lines many times over. On a codebase
    /// with a wide clone set — say a rule-per-file layout where every file
    /// carries the same trait-impl skeleton — that sum runs several times
    /// the size of the codebase itself, pushing the density past 100% and
    /// (via the clamp in [`Metrics::duplicated_lines_density`]) pinning the
    /// duplication term of [`AnalysisReport::health_score`] at its
    /// maximum penalty no matter how much duplication there actually is.
    /// [`DuplicationReport::duplicated_lines`] is already the distinct
    /// count, so it is used as-is.
    pub fn set_duplications(&mut self, duplication: DuplicationReport) {
        self.metrics.set_duplication(duplication.duplicated_lines, duplication.blocks.len());
        self.duplications = duplication.blocks;
    }

    /// Merges issues detected by a *different* analyzer (imported from its
    /// report — SARIF today) into this one, folding them into the same
    /// severity counters, debt total and Reliability/Security ratings the
    /// engine's own rules feed. Deliberately the identical treatment: once
    /// imported, an external finding is an ordinary [`Issue`] — it shows up
    /// in the rendered output, counts toward `blocker_issues` and friends,
    /// and can fail the quality gate.
    ///
    /// Imported issues never touch `lines_of_code`: the scan's own file walk
    /// is the single source of truth for size, and an external report may
    /// well cover files yunq did not scan. That keeps the debt *ratio*
    /// (and so the maintainability rating) honest when an importer does
    /// supply a non-zero effort.
    pub fn add_external_issues(&mut self, imported: Vec<ExternalIssue>) {
        for ExternalIssue { issue, issue_type, remediation_effort_minutes } in imported {
            self.metrics.count_issue(issue.severity());
            self.metrics.add_debt(remediation_effort_minutes as usize);
            self.metrics.record_issue_type_and_effort(
                issue_type,
                issue.severity(),
                issue.rule().clone(),
                issue.file(),
                remediation_effort_minutes,
            );
            self.issues.push(issue);
        }
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

    pub fn mutation(&self) -> Option<&MutationSummary> {
        self.mutation.as_ref()
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

    /// Maintainability rating (A–E) from the technical debt ratio, not
    /// from the worst severity present.
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
    /// lookup, not a cost ratio.
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

    /// A single 0-100 blend, unlike [`Self::rating`]/[`Self::reliability_rating`]/
    /// [`Self::security_rating`]'s A-E letter grades — but built the same
    /// way those already are: as a *rate* (findings per thousand lines of
    /// code), never a raw count. A raw-count penalty subtracted from a
    /// fixed 100-point budget is not scale-invariant — the same 44 major
    /// issues that are a real problem in a 2,000-line project are a
    /// healthy rate in a 200,000-line one, and a fixed budget scores both
    /// identically (usually: zero). Per-KLOC keeps this comparable across
    /// project sizes the way the letter grades already are.
    pub fn health_score(&self) -> u32 {
        let kloc = (self.metrics.lines_of_code() as f64 / 1000.0).max(1.0);
        let per_kloc = |count: usize| count as f64 / kloc;

        let blocker = *self.metrics.issues_by_severity().get(&Severity::Blocker).unwrap_or(&0);
        let critical = *self.metrics.issues_by_severity().get(&Severity::Critical).unwrap_or(&0);
        let major = *self.metrics.issues_by_severity().get(&Severity::Major).unwrap_or(&0);
        let hotspots = self.hotspots.len();
        // `duplicated_lines_density` is already a 0.0..=100.0 percentage,
        // not a count — it does not get the per-KLOC treatment the count
        // -based terms above do, only the same weight the original formula
        // gave it.
        let dup_penalty = self.metrics.duplicated_lines_density() * 0.5;

        let penalty =
            per_kloc(blocker) * 10.0 + per_kloc(critical) * 5.0 + per_kloc(major) + per_kloc(hotspots) * 2.0 + dup_penalty;
        (100.0 - penalty).max(0.0).round() as u32
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

/// Numeric encoding for the A–E letter ratings (`1.0`..`5.0`),
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
    ("mutants", |r| r.mutation.map(|m| m.total_mutants as f64)),
    ("mutants_killed", |r| r.mutation.map(|m| m.killed_mutants as f64)),
    ("mutants_survived", |r| r.mutation.map(|m| m.survived_mutants as f64)),
    ("mutants_timeout", |r| r.mutation.map(|m| m.timeout_mutants as f64)),
    ("mutants_no_coverage", |r| r.mutation.map(|m| m.no_coverage_mutants as f64)),
    ("mutation_score", |r| r.mutation.and_then(|m| m.mutation_score())),
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
            "mutants",
            "mutants_killed",
            "mutants_survived",
            "mutants_timeout",
            "mutants_no_coverage",
            "mutation_score",
        ] {
            assert_eq!(report.measure(&yunq_profiles::MetricKey::new(key).unwrap()), None);
        }
    }

    #[test]
    fn mutation_measures_expose_the_ingested_counts() {
        let mut report = AnalysisReport::new(Vec::new(), Vec::new(), Metrics::new());
        report.set_mutation(MutationSummary {
            total_mutants: 12,
            killed_mutants: 6,
            survived_mutants: 2,
            timeout_mutants: 1,
            no_coverage_mutants: 1,
            ignored_mutants: 1,
            error_mutants: 1,
            pending_mutants: 0,
        });

        let measure = |key: &str| report.measure(&yunq_profiles::MetricKey::new(key).unwrap());
        assert_eq!(measure("mutants"), Some(12.0));
        assert_eq!(measure("mutants_killed"), Some(6.0));
        assert_eq!(measure("mutants_survived"), Some(2.0));
        assert_eq!(measure("mutants_timeout"), Some(1.0));
        assert_eq!(measure("mutants_no_coverage"), Some(1.0));
        // detected = killed(6) + timeout(1) = 7; valid = 7 + survived(2) + no_coverage(1) = 10.
        assert_eq!(measure("mutation_score"), Some(70.0));
        assert_eq!(report.mutation().unwrap().total_mutants, 12);
    }

    #[test]
    fn mutation_score_is_none_with_no_valid_mutants() {
        let summary = MutationSummary { ignored_mutants: 3, ..Default::default() };
        assert_eq!(summary.mutation_score(), None);
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

    #[test]
    fn duplicated_lines_density_never_exceeds_100_percent() {
        // The duplication detector's line count and `lines_of_code` use
        // different bases (see `Metrics::duplicated_lines_density`'s doc
        // comment) and can disagree enough that the naive ratio overshoots
        // 100% on a comment-heavy codebase — asserted directly here since
        // nothing else in this file exercises `Metrics` in isolation.
        let mut metrics = Metrics::new();
        metrics.add_file(100);
        metrics.set_duplication(400, 1);
        assert_eq!(metrics.duplicated_lines_density(), 100.0);
    }

    #[test]
    fn set_duplications_does_not_double_count_lines_shared_by_many_pairs() {
        // The regression this guards: duplicate blocks are *pairs*, so one
        // region cloned across n files arrives as n*(n-1)/2 blocks all
        // covering the same lines. Summing each pair's span counted those
        // lines once per pair — on yunq's own rule-per-file layout that
        // turned 12,968 genuinely duplicated lines into 172,087, a density
        // of 281% clamped to 100%, which pinned `health_score`'s
        // duplication penalty at its 50-point maximum and dragged a
        // healthy score down to 49. The detector already reports the
        // distinct count; it must survive the trip into `Metrics`.
        use yunq_cpd::BlockRef;
        let region = |file: &str| BlockRef { file: file.into(), start_line: 1, end_line: 10 };
        let pair = |a: &str, b: &str| DuplicateBlock { first: region(a), second: region(b), lines: 10 };
        // The same 10 lines in each of 4 files: 6 pairs, 40 distinct lines.
        let blocks = vec![
            pair("a.rs", "b.rs"),
            pair("a.rs", "c.rs"),
            pair("a.rs", "d.rs"),
            pair("b.rs", "c.rs"),
            pair("b.rs", "d.rs"),
            pair("c.rs", "d.rs"),
        ];
        let mut metrics = Metrics::new();
        metrics.add_file(400);
        let mut report = AnalysisReport::new(Vec::new(), Vec::new(), metrics);
        report.set_duplications(DuplicationReport { blocks, duplicated_lines: 40 });

        assert_eq!(report.metrics().duplicated_blocks(), 6);
        // Naive summing would report 60 lines here (6 pairs * 10), a 15%
        // density on a 400-line codebase that is really 10%.
        assert_eq!(report.metrics().duplicated_lines(), 40);
        assert_eq!(report.metrics().duplicated_lines_density(), 10.0);
    }

    #[test]
    fn a_large_codebase_with_a_modest_issue_rate_does_not_saturate_health_score_to_zero() {
        // The regression this guards: a raw issue *count* subtracted from a
        // fixed 100-point budget saturates to 0 for any codebase past a few
        // hundred/thousand issues, regardless of how sparse those issues
        // actually are relative to the code. 44 major issues in 60k lines
        // (yunq's own size when this was found) is a healthy ~0.7 per
        // KLOC — nowhere near the two letter-grade ratings' worst-severity
        // algorithm would call risky, and the score must reflect that.
        let mut metrics = Metrics::new();
        metrics.add_file(60_000);
        for _ in 0..44 {
            metrics.count_issue(Severity::Major);
        }
        let report = AnalysisReport::new(Vec::new(), Vec::new(), metrics);
        assert!(report.health_score() > 90, "got {}", report.health_score());
    }

    #[test]
    fn a_small_codebase_with_a_high_issue_rate_still_scores_low() {
        // The other half of the regression guard: normalizing by KLOC must
        // not become a loophole where a small, genuinely bad file scores
        // well just because its raw counts are small.
        let mut metrics = Metrics::new();
        metrics.add_file(50);
        for _ in 0..10 {
            metrics.count_issue(Severity::Blocker);
        }
        let report = AnalysisReport::new(Vec::new(), Vec::new(), metrics);
        assert_eq!(report.health_score(), 0);
    }

    #[test]
    fn health_score_is_100_for_a_clean_report() {
        let mut metrics = Metrics::new();
        metrics.add_file(1_000);
        let report = AnalysisReport::new(Vec::new(), Vec::new(), metrics);
        assert_eq!(report.health_score(), 100);
    }

    #[test]
    fn external_issues_fold_into_severity_counts_debt_and_the_security_rating() {
        let key = |raw: &str| yunq_profiles::MetricKey::new(raw).unwrap();
        let issue = |rule: &str, severity| {
            Issue::new(RuleId::new(rule).unwrap(), severity, "imported", "src/app.py", yunq_ast::Span::new(1, 1, 1, 1))
        };

        let mut report = AnalysisReport::new(Vec::new(), Vec::new(), Metrics::new());
        report.add_external_issues(vec![
            ExternalIssue::new(issue("ruff:e501", Severity::Major), IssueType::CodeSmell),
            ExternalIssue::new(issue("codeql:js-sql-injection", Severity::Blocker), IssueType::Vulnerability),
        ]);

        // Imported issues are ordinary issues: they show up in the report,
        // in the severity facets the gate reads, and in the ratings.
        assert_eq!(report.issues().len(), 2);
        assert_eq!(report.measure(&key("blocker_issues")), Some(1.0));
        assert_eq!(report.measure(&key("major_issues")), Some(1.0));
        assert_eq!(report.security_rating(), Rating::from_severity(Severity::Blocker));
        // Only the vulnerability moved Security; nothing claimed to be a Bug,
        // so Reliability stays at its unblemished default.
        assert_eq!(report.reliability_rating(), Rating::default());
        // No effort was supplied, so no debt was invented.
        assert_eq!(report.metrics().debt_minutes(), 0);
        assert_eq!(report.metrics().lines_of_code(), 0);
    }

    #[test]
    fn an_external_issue_with_an_effort_estimate_adds_debt_and_per_rule_effort() {
        let mut report = AnalysisReport::new(Vec::new(), Vec::new(), Metrics::new());
        let rule = RuleId::new("gosec:g401").unwrap();
        report.add_external_issues(vec![ExternalIssue {
            issue: Issue::new(rule.clone(), Severity::Major, "weak hash", "hash.go", yunq_ast::Span::new(3, 1, 3, 9)),
            issue_type: IssueType::Vulnerability,
            remediation_effort_minutes: 15,
        }]);

        assert_eq!(report.metrics().debt_minutes(), 15);
        assert_eq!(report.remediation_effort().by_rule.get(&rule), Some(&15));
        assert_eq!(report.remediation_effort().by_component.get("hash.go"), Some(&15));
    }
}
