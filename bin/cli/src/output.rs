//! Rendering of analysis reports for the terminal: plain text and JSON.
//! These DTOs are the CLI's own edge representation of the domain.

use serde::Serialize;
use yunq_rules_engine::{
    AnalysisReport, CloneSet, ConditionStatus, CoverageSummary, CrapFinding, GateEvaluation,
    GateStatus, Hotspot, Issue, Metrics, MutationSummary, NewCodeAnalysis,
    RemediationEffortSummary, Severity, TestReportSummary,
};

#[derive(Serialize)]
pub struct ReportDto {
    pub issues: Vec<IssueDto>,
    pub hotspots: Vec<HotspotDto>,
    pub metrics: MetricsDto,
    pub rating: String,
    pub reliability_rating: String,
    pub security_rating: String,
    pub quality_gate: GateDto,
    /// Issues not present in the previous analysis (None on first scan).
    pub new_issue_total: Option<usize>,
    pub duplications: Vec<DuplicationDto>,
    /// The CRAP-ranked refactor list (roadmap item C3), worst score first.
    /// Empty until a coverage report is ingested — see
    /// `AnalysisReport::compute_crap_findings`.
    pub crap: Vec<CrapFindingDto>,
    /// Present when a coverage report (LCOV/Cobertura/JaCoCo/llvm-cov/Istanbul) was ingested.
    pub coverage: Option<CoverageDto>,
    /// Present when a JUnit test report was ingested.
    pub test_report: Option<TestReportDto>,
    /// Present when a mutation-testing report (`--mutation-report`) was ingested.
    pub mutation: Option<MutationDto>,
    /// Coverage restricted to the lines a supplied unified diff marks as
    /// added/modified (see `--coverage-diff`); `None` when no diff was
    /// supplied or it touched no instrumented line.
    pub coverage_new_code: Option<f64>,
    /// Scan identity (`--project`/`--branch`/`--pr`, explicit or
    /// CI-auto-detected) — always present so downstream consumers (e.g. the
    /// sources endpoint) get a stable schema, with fields `None` when
    /// nothing was known.
    pub context: ScanContextDto,
}

/// Scan identity carried alongside the report: which project this is, and
/// what it's attached to (a branch, and optionally a pull request on top of
/// it). Populated from `--project`/`--branch`/`--pr` or CI auto-detection
/// (`ci_detect::detect_ci_context`) — explicit flags win.
#[derive(Clone, Debug, Default, Serialize)]
pub struct ScanContextDto {
    pub project: Option<String>,
    pub branch: Option<String>,
    pub pull_request: Option<u32>,
}

/// One `CrapFinding`, flattened for the wire — `CC² × (1−coverage)³ + CC`
/// alongside both inputs, so a consumer doesn't need to re-derive the score.
#[derive(Serialize)]
pub struct CrapFindingDto {
    pub path: String,
    pub line: u32,
    pub cyclomatic: u32,
    pub coverage_percent: f64,
    pub score: f64,
}

impl From<&CrapFinding> for CrapFindingDto {
    fn from(f: &CrapFinding) -> Self {
        Self {
            path: f.path.clone(),
            line: f.span.start_line,
            cyclomatic: f.cyclomatic,
            coverage_percent: f.coverage_percent,
            score: f.score,
        }
    }
}

#[derive(Serialize)]
pub struct CoverageDto {
    pub percent: Option<f64>,
    pub covered_lines: usize,
    pub coverable_lines: usize,
    pub branch_percent: Option<f64>,
    pub covered_branches: usize,
    pub coverable_branches: usize,
}

#[derive(Serialize)]
pub struct TestReportDto {
    pub total_tests: usize,
    pub passed_tests: usize,
    pub failed_tests: usize,
    pub skipped_tests: usize,
    pub errors: usize,
    pub time_seconds: f64,
    pub pass_rate: Option<f64>,
    pub suites: Vec<TestSuiteDto>,
}

#[derive(Serialize)]
pub struct TestSuiteDto {
    pub name: String,
    pub tests: usize,
    pub passed: usize,
    pub failures: usize,
    pub errors: usize,
    pub skipped: usize,
    pub time_seconds: f64,
}

impl From<&TestReportSummary> for TestReportDto {
    fn from(summary: &TestReportSummary) -> Self {
        Self {
            total_tests: summary.total_tests,
            passed_tests: summary.passed_tests,
            failed_tests: summary.failed_tests,
            skipped_tests: summary.skipped_tests,
            errors: summary.errors,
            time_seconds: summary.time_seconds,
            pass_rate: summary.pass_rate(),
            suites: summary
                .suites
                .iter()
                .map(|s| TestSuiteDto {
                    name: s.name.clone(),
                    tests: s.tests,
                    passed: s.passed,
                    failures: s.failures,
                    errors: s.errors,
                    skipped: s.skipped,
                    time_seconds: s.time_seconds,
                })
                .collect(),
        }
    }
}

#[derive(Serialize)]
pub struct MutationDto {
    pub total_mutants: usize,
    pub killed_mutants: usize,
    pub survived_mutants: usize,
    pub timeout_mutants: usize,
    pub no_coverage_mutants: usize,
    pub ignored_mutants: usize,
    pub error_mutants: usize,
    pub pending_mutants: usize,
    pub mutation_score: Option<f64>,
}

impl From<&MutationSummary> for MutationDto {
    fn from(m: &MutationSummary) -> Self {
        Self {
            total_mutants: m.total_mutants,
            killed_mutants: m.killed_mutants,
            survived_mutants: m.survived_mutants,
            timeout_mutants: m.timeout_mutants,
            no_coverage_mutants: m.no_coverage_mutants,
            ignored_mutants: m.ignored_mutants,
            error_mutants: m.error_mutants,
            pending_mutants: m.pending_mutants,
            mutation_score: m.mutation_score(),
        }
    }
}

#[derive(Serialize)]
pub struct DuplicationDto {
    /// Every place this shape occurs, as `path:start-end`.
    pub occurrences: Vec<String>,
    /// How many places — the number of edits a change to this code costs.
    pub occurrence_count: usize,
    /// Span of one occurrence, in source lines.
    pub lines: usize,
}

#[derive(Serialize)]
pub struct HotspotDto {
    pub rule: String,
    pub file: String,
    pub line: u32,
    pub column: u32,
    pub message: String,
    pub status: String,
}

#[derive(Serialize)]
pub struct GateDto {
    pub status: String,
    pub conditions: Vec<ConditionDto>,
}

#[derive(Serialize)]
pub struct ConditionDto {
    pub metric: String,
    pub operator: String,
    pub threshold: f64,
    pub value: Option<f64>,
    pub status: String,
}

fn gate_dto(evaluation: &GateEvaluation) -> GateDto {
    GateDto {
        status: evaluation.status().to_string(),
        conditions: evaluation
            .results()
            .iter()
            .map(|result| ConditionDto {
                metric: result.condition.metric().to_string(),
                operator: result.condition.operator().symbol().to_string(),
                threshold: result.condition.threshold(),
                value: result.value,
                status: match result.status {
                    ConditionStatus::Passed => "passed",
                    ConditionStatus::Failed => "failed",
                    ConditionStatus::NoValue => "no-value",
                }
                .to_string(),
            })
            .collect(),
    }
}

#[derive(Serialize)]
pub struct IssueDto {
    pub rule: String,
    pub severity: String,
    pub file: String,
    pub line: u32,
    pub column: u32,
    pub message: String,
}

#[derive(Serialize)]
pub struct MetricsDto {
    pub files_scanned: usize,
    pub files_skipped: usize,
    pub parse_failures: usize,
    pub cache_hits: usize,
    pub lines_of_code: usize,
    pub issue_total: usize,
    pub debt_minutes: usize,
    pub functions: usize,
    pub classes: usize,
    pub statements: usize,
    pub comment_lines: usize,
    pub comment_lines_density: f64,
    pub max_nesting_depth: usize,
    /// Remediation effort (minutes) by rule, worst first — which rule is
    /// generating the most technical debt.
    pub remediation_effort_by_rule: Vec<RuleEffortDto>,
    /// Remediation effort (minutes) by file, worst first — which file would
    /// benefit most from cleanup.
    pub remediation_effort_by_component: Vec<ComponentEffortDto>,
}

#[derive(Serialize)]
pub struct RuleEffortDto {
    pub rule: String,
    pub minutes: u32,
}

#[derive(Serialize)]
pub struct ComponentEffortDto {
    pub component: String,
    pub minutes: u32,
}

/// Sorts by descending minutes, breaking ties on the key so JSON output is
/// deterministic across runs regardless of `HashMap` iteration order.
fn sorted_effort(mut entries: Vec<(String, u32)>) -> Vec<(String, u32)> {
    entries.sort_by(|(a_key, a_minutes), (b_key, b_minutes)| {
        b_minutes.cmp(a_minutes).then_with(|| a_key.cmp(b_key))
    });
    entries
}

impl From<&Issue> for IssueDto {
    fn from(issue: &Issue) -> Self {
        Self {
            rule: issue.rule().to_string(),
            severity: issue.severity().to_string(),
            file: issue.file().to_string(),
            line: issue.span().start_line,
            column: issue.span().start_col,
            message: issue.message().to_string(),
        }
    }
}

impl From<&Hotspot> for HotspotDto {
    fn from(h: &Hotspot) -> Self {
        Self {
            rule: h.rule().to_string(),
            file: h.file().to_string(),
            line: h.span().start_line,
            column: h.span().start_col,
            message: h.message().to_string(),
            status: h.status().to_string(),
        }
    }
}

impl From<&CloneSet> for DuplicationDto {
    fn from(set: &CloneSet) -> Self {
        Self {
            occurrences: set
                .regions
                .iter()
                .map(|r| format!("{}:{}-{}", r.file, r.start_line, r.end_line))
                .collect(),
            occurrence_count: set.regions.len(),
            lines: set.lines,
        }
    }
}

impl From<&Metrics> for MetricsDto {
    fn from(metrics: &Metrics) -> Self {
        Self {
            files_scanned: metrics.files_scanned(),
            files_skipped: metrics.files_skipped(),
            parse_failures: metrics.parse_failures(),
            cache_hits: metrics.cache_hits(),
            lines_of_code: metrics.lines_of_code(),
            issue_total: metrics.issue_total(),
            debt_minutes: metrics.debt_minutes(),
            functions: metrics.functions(),
            classes: metrics.classes(),
            statements: metrics.statements(),
            comment_lines: metrics.comment_lines(),
            comment_lines_density: metrics.comment_lines_density(),
            max_nesting_depth: metrics.max_nesting_depth(),
            remediation_effort_by_rule: remediation_effort_by_rule_dto(
                metrics.remediation_effort(),
            ),
            remediation_effort_by_component: remediation_effort_by_component_dto(
                metrics.remediation_effort(),
            ),
        }
    }
}

fn remediation_effort_by_rule_dto(effort: &RemediationEffortSummary) -> Vec<RuleEffortDto> {
    let by_rule = effort
        .by_rule
        .iter()
        .map(|(rule, minutes)| (rule.to_string(), *minutes))
        .collect();
    sorted_effort(by_rule)
        .into_iter()
        .map(|(rule, minutes)| RuleEffortDto { rule, minutes })
        .collect()
}

fn remediation_effort_by_component_dto(
    effort: &RemediationEffortSummary,
) -> Vec<ComponentEffortDto> {
    let by_component = effort
        .by_component
        .iter()
        .map(|(c, m)| (c.clone(), *m))
        .collect();
    sorted_effort(by_component)
        .into_iter()
        .map(|(component, minutes)| ComponentEffortDto { component, minutes })
        .collect()
}

impl From<&CoverageSummary> for CoverageDto {
    fn from(c: &CoverageSummary) -> Self {
        Self {
            percent: c.percent(),
            covered_lines: c.covered_lines(),
            coverable_lines: c.coverable_lines(),
            branch_percent: c.percent_branches(),
            covered_branches: c.covered_branches(),
            coverable_branches: c.coverable_branches(),
        }
    }
}

impl ReportDto {
    pub fn build(
        report: &AnalysisReport,
        gate: &GateEvaluation,
        new_code: Option<&NewCodeAnalysis>,
        test_report: Option<&TestReportSummary>,
        coverage_new_code: Option<f64>,
        context: ScanContextDto,
    ) -> Self {
        Self {
            issues: report.issues().iter().map(IssueDto::from).collect(),
            hotspots: report.hotspots().iter().map(HotspotDto::from).collect(),
            rating: report.rating().to_string(),
            reliability_rating: report.reliability_rating().to_string(),
            security_rating: report.security_rating().to_string(),
            quality_gate: gate_dto(gate),
            new_issue_total: new_code.map(|nc| nc.new_issues().len()),
            coverage: report.coverage().map(CoverageDto::from),
            test_report: test_report.map(TestReportDto::from),
            mutation: report.mutation().map(MutationDto::from),
            coverage_new_code,
            duplications: report
                .duplications()
                .iter()
                .map(DuplicationDto::from)
                .collect(),
            crap: sorted_crap_findings(report),
            metrics: MetricsDto::from(report.metrics()),
            context,
        }
    }
}

/// `AnalysisReport::crap_findings`, worst score first — the ranked refactor
/// list is the deliverable (roadmap item C3), not merely a set.
fn sorted_crap(report: &AnalysisReport) -> Vec<CrapFinding> {
    let mut findings = report.crap_findings();
    findings.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    findings
}

fn sorted_crap_findings(report: &AnalysisReport) -> Vec<CrapFindingDto> {
    sorted_crap(report)
        .iter()
        .map(CrapFindingDto::from)
        .collect()
}

fn render_issues_text(out: &mut String, report: &AnalysisReport) {
    let issues: Vec<&Issue> = report.issues().iter().collect();
    // Group by file, sorting files by issue count (descending) then path.
    let mut by_file: std::collections::BTreeMap<&str, Vec<&Issue>> =
        std::collections::BTreeMap::new();
    for issue in &issues {
        by_file.entry(issue.file()).or_default().push(issue);
    }
    let mut files: Vec<(&str, Vec<&Issue>)> = by_file.into_iter().collect();
    files.sort_by(|(a_file, a_issues), (b_file, b_issues)| {
        b_issues
            .len()
            .cmp(&a_issues.len())
            .then_with(|| a_file.cmp(b_file))
    });
    for (file, mut file_issues) in files {
        file_issues.sort_by(|a, b| {
            b.severity()
                .cmp(&a.severity())
                .then_with(|| a.span().start_line.cmp(&b.span().start_line))
        });
        out.push_str(&format!(
            "\n── {} ({} issue{})\n",
            file,
            file_issues.len(),
            if file_issues.len() == 1 { "" } else { "s" },
        ));
        for issue in &file_issues {
            out.push_str(&format!(
                "{:<8} {:<24}  line {}:{}  {}\n",
                issue.severity().to_string().to_uppercase(),
                issue.rule().to_string(),
                issue.span().start_line,
                issue.span().start_col,
                issue.message(),
            ));
        }
    }
}

fn render_hotspots_text(out: &mut String, report: &AnalysisReport) {
    for hotspot in report.hotspots() {
        out.push_str(&format!(
            "{:<8} {:<24} {}:{}:{}  {} [{}]\n",
            "HOTSPOT",
            hotspot.rule().to_string(),
            hotspot.file(),
            hotspot.span().start_line,
            hotspot.span().start_col,
            hotspot.message(),
            hotspot.status(),
        ));
    }
}

fn render_metrics_summary_text(out: &mut String, report: &AnalysisReport) {
    let metrics = report.metrics();
    let by_severity = metrics
        .issues_by_severity()
        .iter()
        .rev()
        .map(|(sev, count)| format!("{sev}: {count}"))
        .collect::<Vec<_>>()
        .join(", ");
    out.push_str(&format!(
        "\n{} files scanned ({} LOC, {} from cache), {} skipped, {} parse failures — {} issues ({})\n",
        metrics.files_scanned(),
        metrics.lines_of_code(),
        metrics.cache_hits(),
        metrics.files_skipped(),
        metrics.parse_failures(),
        metrics.issue_total(),
        if by_severity.is_empty() { "none".to_string() } else { by_severity },
    ));
    out.push_str(&format!(
        "{} security hotspots to review, technical debt: {} min\n",
        report.hotspots().len(),
        metrics.debt_minutes(),
    ));
    out.push_str(&format!(
        "{} functions, {} classes, {} statements, {} comment lines ({:.1}%), max nesting depth {}\n",
        metrics.functions(),
        metrics.classes(),
        metrics.statements(),
        metrics.comment_lines(),
        metrics.comment_lines_density(),
        metrics.max_nesting_depth(),
    ));
}

fn render_duplications_text(out: &mut String, report: &AnalysisReport) {
    let metrics = report.metrics();
    if metrics.duplicated_blocks() == 0 {
        return;
    }
    let occurrences: usize = report.duplications().iter().map(|s| s.regions.len()).sum();
    out.push_str(&format!(
        "\n── Duplication: {} clone sets, {} occurrences, {} lines ({:.1}%)\n",
        metrics.duplicated_blocks(),
        occurrences,
        metrics.duplicated_lines(),
        metrics.duplicated_lines_density(),
    ));
    // Widest-reaching first (`find_duplicates` already sorts them), each set
    // listing every place it occurs — one finding per duplicated shape, not
    // one per pair of places sharing it.
    for set in report.duplications() {
        out.push_str(&format!(
            "  = {} lines duplicated across {} places:\n",
            set.lines,
            set.regions.len()
        ));
        for region in &set.regions {
            out.push_str(&format!(
                "      {}:{}-{}\n",
                region.file, region.start_line, region.end_line
            ));
        }
    }
}

/// The ranked refactor list CRAP exists to produce (roadmap item C3): every
/// `crap:high-risk-function` finding, worst score first, alongside its two
/// inputs — a raw `blocker_issues`-style count says nothing about *where*
/// the untested code is, which is the whole point of multiplying complexity
/// by untestedness instead of reporting either alone.
fn render_crap_text(out: &mut String, report: &AnalysisReport) {
    let findings = sorted_crap(report);
    if findings.is_empty() {
        return;
    }
    out.push_str(&format!(
        "\nRisk hotspots (CRAP), worst first — {} function(s):\n",
        findings.len()
    ));
    for finding in findings {
        out.push_str(&format!(
            "  {:>6.1}  {}:{}  (cyclomatic complexity {}, {:.0}% line coverage)\n",
            finding.score,
            finding.path,
            finding.span.start_line,
            finding.cyclomatic,
            finding.coverage_percent,
        ));
    }
}

fn render_coverage_text(out: &mut String, report: &AnalysisReport, coverage_new_code: Option<f64>) {
    if let Some(coverage) = report.coverage() {
        out.push_str(&format!(
            "Coverage: {} ({}/{} lines)\n",
            coverage
                .percent()
                .map(|p| format!("{p:.1}%"))
                .unwrap_or_else(|| "n/a".to_string()),
            coverage.covered_lines(),
            coverage.coverable_lines(),
        ));
        if coverage.coverable_branches() > 0 {
            out.push_str(&format!(
                "Branch coverage: {} ({}/{} branches)\n",
                coverage
                    .percent_branches()
                    .map(|p| format!("{p:.1}%"))
                    .unwrap_or_else(|| "n/a".to_string()),
                coverage.covered_branches(),
                coverage.coverable_branches(),
            ));
        }
    }
    if let Some(percent) = coverage_new_code {
        out.push_str(&format!("Coverage on new code: {percent:.1}%\n"));
    }
}

fn render_test_report_text(out: &mut String, test_report: Option<&TestReportSummary>) {
    let Some(tests) = test_report else { return };
    out.push_str(&format!(
        "Tests: {} total, {} passed, {} failed, {} skipped, {} errors ({:.2}s)\n",
        tests.total_tests,
        tests.passed_tests,
        tests.failed_tests,
        tests.skipped_tests,
        tests.errors,
        tests.time_seconds,
    ));
    if tests.suites.len() > 1 {
        for suite in &tests.suites {
            out.push_str(&format!(
                "  - {}: {} total, {} passed, {} failed, {} skipped, {} errors ({:.2}s)\n",
                suite.name,
                suite.tests,
                suite.passed,
                suite.failures,
                suite.errors,
                suite.skipped,
                suite.time_seconds,
            ));
        }
    }
}

fn render_mutation_text(out: &mut String, report: &AnalysisReport) {
    let Some(mutation) = report.mutation() else {
        return;
    };
    out.push_str(&format!(
        "Mutation score: {} ({} killed, {} survived, {} timeout, {} no coverage, {} of {} mutants total)\n",
        mutation.mutation_score().map(|s| format!("{s:.1}%")).unwrap_or_else(|| "n/a".to_string()),
        mutation.killed_mutants,
        mutation.survived_mutants,
        mutation.timeout_mutants,
        mutation.no_coverage_mutants,
        mutation.total_mutants - mutation.ignored_mutants - mutation.error_mutants - mutation.pending_mutants,
        mutation.total_mutants,
    ));
}

fn render_gate_text(out: &mut String, gate: &GateEvaluation) {
    out.push_str(&format!("Quality gate: {}\n", gate.status()));
    if gate.status() == GateStatus::Failed {
        for failed in gate.failed_conditions() {
            out.push_str(&format!(
                "  ✗ {} {} {} (actual: {})\n",
                failed.condition.metric(),
                failed.condition.operator().symbol(),
                failed.condition.threshold(),
                failed.value.unwrap_or_default(),
            ));
        }
    }
}

/// "Project: x | Branch: y | PR: #z" header line, omitting whichever
/// fields weren't known (nothing printed at all when none were).
fn render_context_text(out: &mut String, context: &ScanContextDto) {
    let mut parts = Vec::new();
    if let Some(project) = &context.project {
        parts.push(format!("Project: {project}"));
    }
    if let Some(branch) = &context.branch {
        parts.push(format!("Branch: {branch}"));
    }
    if let Some(pr) = context.pull_request {
        parts.push(format!("PR: #{pr}"));
    }
    if !parts.is_empty() {
        out.push_str(&parts.join(" | "));
        out.push('\n');
    }
}

pub fn render_text(
    report: &AnalysisReport,
    gate: &GateEvaluation,
    new_code: Option<&NewCodeAnalysis>,
    test_report: Option<&TestReportSummary>,
    coverage_new_code: Option<f64>,
    context: &ScanContextDto,
) -> String {
    let mut out = String::new();
    render_context_text(&mut out, context);
    render_issues_text(&mut out, report);
    render_hotspots_text(&mut out, report);
    render_metrics_summary_text(&mut out, report);
    render_duplications_text(&mut out, report);
    render_crap_text(&mut out, report);
    render_coverage_text(&mut out, report, coverage_new_code);
    if let Some(new_code) = new_code {
        out.push_str(&format!(
            "New issues since previous analysis: {}\n",
            new_code.new_issues().len()
        ));
    }
    render_test_report_text(&mut out, test_report);
    render_mutation_text(&mut out, report);
    out.push_str(&format!("Health score: {}/100\n", report.health_score()));
    out.push_str(&format!(
        "Ratings: maintainability {}, reliability {}, security {}\n",
        report.rating(),
        report.reliability_rating(),
        report.security_rating(),
    ));
    render_gate_text(&mut out, gate);
    out
}

/// Renders a ready-to-paste prompt handing the scan's findings to an AI
/// coding agent (Claude Code, Cursor, etc.) — the same "here's what to fix"
/// handoff tools like `react-doctor` print at the end of a run. Always
/// plain text (regardless of `--format`): its only purpose is to be copied
/// into a chat agent, not machine-parsed.
const MAX_PROMPT_LISTED_ISSUES: usize = 50;

fn render_agent_prompt_issue_list(out: &mut String, issues: &[&Issue], scan_path: &str) {
    for (n, issue) in issues.iter().take(MAX_PROMPT_LISTED_ISSUES).enumerate() {
        out.push_str(&format!(
            "{}. [{}] {} — {}:{}:{} — {}\n",
            n + 1,
            issue.severity().to_string().to_uppercase(),
            issue.rule(),
            issue.file(),
            issue.span().start_line,
            issue.span().start_col,
            issue.message(),
        ));
    }
    if issues.len() > MAX_PROMPT_LISTED_ISSUES {
        out.push_str(&format!(
            "... and {} more issue(s) — re-run `yunq scan {scan_path} --format json` for the full list.\n",
            issues.len() - MAX_PROMPT_LISTED_ISSUES,
        ));
    }
}

fn render_agent_prompt_gate_conditions(out: &mut String, gate: &GateEvaluation) {
    if gate.status() != GateStatus::Failed {
        return;
    }
    out.push_str("\nPrioritize the issues blocking the quality gate:\n");
    for failed in gate.failed_conditions() {
        out.push_str(&format!(
            "  - {} {} {} (actual: {})\n",
            failed.condition.metric(),
            failed.condition.operator().symbol(),
            failed.condition.threshold(),
            failed.value.unwrap_or_default(),
        ));
    }
}

pub fn render_agent_prompt(
    report: &AnalysisReport,
    gate: &GateEvaluation,
    scan_path: &str,
) -> String {
    let mut issues: Vec<&Issue> = report.issues().iter().collect();
    issues.sort_by(|a, b| {
        b.severity()
            .cmp(&a.severity())
            .then_with(|| a.file().cmp(b.file()))
            .then_with(|| a.span().start_line.cmp(&b.span().start_line))
    });

    let mut out = String::new();
    out.push_str("---- yunq agent prompt (copy everything below into your AI coding agent) ----\n");

    if issues.is_empty() {
        out.push_str(&format!(
            "yunq analyzed {scan_path} and found no issues. Quality gate: {}. Nothing to fix.\n",
            gate.status(),
        ));
        out.push_str("---- end of yunq agent prompt ----\n");
        return out;
    }

    out.push_str(&format!(
        "yunq analyzed {scan_path} and found {} issue(s) (quality gate: {}). Fix them one at a time, \
         make the smallest change that resolves each one, and re-run `yunq scan {scan_path}` after \
         every fix to confirm the issue is gone and no new one appeared.\n\n",
        issues.len(),
        gate.status(),
    ));

    render_agent_prompt_issue_list(&mut out, &issues, scan_path);
    render_agent_prompt_gate_conditions(&mut out, gate);

    out.push_str("---- end of yunq agent prompt ----\n");
    out
}

pub fn render_json(
    report: &AnalysisReport,
    gate: &GateEvaluation,
    new_code: Option<&NewCodeAnalysis>,
    test_report: Option<&TestReportSummary>,
    coverage_new_code: Option<f64>,
    context: ScanContextDto,
) -> serde_json::Result<String> {
    serde_json::to_string_pretty(&ReportDto::build(
        report,
        gate,
        new_code,
        test_report,
        coverage_new_code,
        context,
    ))
}

#[derive(Serialize)]
struct SarifLogDto {
    #[serde(rename = "$schema")]
    schema: &'static str,
    version: &'static str,
    runs: Vec<SarifRunDto>,
}

#[derive(Serialize)]
struct SarifRunDto {
    tool: SarifToolDto,
    results: Vec<SarifResultDto>,
}

#[derive(Serialize)]
struct SarifToolDto {
    driver: SarifDriverDto,
}

#[derive(Serialize)]
struct SarifDriverDto {
    name: &'static str,
    #[serde(rename = "semanticVersion")]
    semantic_version: &'static str,
}

#[derive(Serialize)]
struct SarifResultDto {
    #[serde(rename = "ruleId")]
    rule_id: String,
    level: &'static str,
    message: SarifMessageDto,
    locations: Vec<SarifLocationDto>,
}

#[derive(Serialize)]
struct SarifMessageDto {
    text: String,
}

#[derive(Serialize)]
struct SarifLocationDto {
    #[serde(rename = "physicalLocation")]
    physical_location: SarifPhysicalLocationDto,
}

#[derive(Serialize)]
struct SarifPhysicalLocationDto {
    #[serde(rename = "artifactLocation")]
    artifact_location: SarifArtifactLocationDto,
    region: SarifRegionDto,
}

#[derive(Serialize)]
struct SarifArtifactLocationDto {
    uri: String,
}

#[derive(Serialize)]
struct SarifRegionDto {
    #[serde(rename = "startLine")]
    start_line: u32,
    #[serde(rename = "startColumn")]
    start_column: u32,
}

pub fn render_sarif(report: &AnalysisReport) -> serde_json::Result<String> {
    let results = report
        .issues()
        .iter()
        .map(|issue| {
            let level = match issue.severity() {
                Severity::Blocker | Severity::Critical => "error",
                Severity::Major => "warning",
                _ => "note",
            };
            SarifResultDto {
                rule_id: issue.rule().to_string(),
                level,
                message: SarifMessageDto {
                    text: issue.message().to_string(),
                },
                locations: vec![SarifLocationDto {
                    physical_location: SarifPhysicalLocationDto {
                        artifact_location: SarifArtifactLocationDto {
                            uri: issue.file().to_string(),
                        },
                        region: SarifRegionDto {
                            start_line: issue.span().start_line,
                            start_column: issue.span().start_col,
                        },
                    },
                }],
            }
        })
        .collect();

    let sarif = SarifLogDto {
        schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        version: "2.1.0",
        runs: vec![SarifRunDto {
            tool: SarifToolDto {
                driver: SarifDriverDto {
                    name: "yunq",
                    semantic_version: env!("CARGO_PKG_VERSION"),
                },
            },
            results,
        }],
    };

    serde_json::to_string_pretty(&sarif)
}
