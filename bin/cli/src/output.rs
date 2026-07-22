//! Rendering of analysis reports for the terminal: plain text and JSON.
//! These DTOs are the CLI's own edge representation of the domain.

use serde::Serialize;
use yunq_rules_engine::{
    AnalysisReport, ConditionStatus, GateEvaluation, GateStatus, Issue, NewCodeAnalysis,
};

#[derive(Serialize)]
pub struct ReportDto {
    pub issues: Vec<IssueDto>,
    pub hotspots: Vec<HotspotDto>,
    pub metrics: MetricsDto,
    pub rating: String,
    pub quality_gate: GateDto,
    /// Issues not present in the previous analysis (None on first scan).
    pub new_issue_total: Option<usize>,
    pub duplications: Vec<DuplicationDto>,
    /// Present when an LCOV report was ingested.
    pub coverage: Option<CoverageDto>,
}

#[derive(Serialize)]
pub struct CoverageDto {
    pub percent: Option<f64>,
    pub covered_lines: usize,
    pub coverable_lines: usize,
}

#[derive(Serialize)]
pub struct DuplicationDto {
    pub first_file: String,
    pub first_lines: String,
    pub second_file: String,
    pub second_lines: String,
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

impl ReportDto {
    pub fn build(
        report: &AnalysisReport,
        gate: &GateEvaluation,
        new_code: Option<&NewCodeAnalysis>,
    ) -> Self {
        let metrics = report.metrics();
        Self {
            issues: report.issues().iter().map(IssueDto::from).collect(),
            hotspots: report
                .hotspots()
                .iter()
                .map(|h| HotspotDto {
                    rule: h.rule().to_string(),
                    file: h.file().to_string(),
                    line: h.span().start_line,
                    column: h.span().start_col,
                    message: h.message().to_string(),
                    status: h.status().to_string(),
                })
                .collect(),
            rating: report.rating().to_string(),
            quality_gate: gate_dto(gate),
            new_issue_total: new_code.map(|nc| nc.new_issues().len()),
            coverage: report.coverage().map(|c| CoverageDto {
                percent: c.percent(),
                covered_lines: c.covered_lines(),
                coverable_lines: c.coverable_lines(),
            }),
            duplications: report
                .duplications()
                .iter()
                .map(|d| DuplicationDto {
                    first_file: d.first.file.clone(),
                    first_lines: format!("{}-{}", d.first.start_line, d.first.end_line),
                    second_file: d.second.file.clone(),
                    second_lines: format!("{}-{}", d.second.start_line, d.second.end_line),
                    lines: d.lines,
                })
                .collect(),
            metrics: MetricsDto {
                files_scanned: metrics.files_scanned(),
                files_skipped: metrics.files_skipped(),
                parse_failures: metrics.parse_failures(),
                cache_hits: metrics.cache_hits(),
                lines_of_code: metrics.lines_of_code(),
                issue_total: metrics.issue_total(),
                debt_minutes: metrics.debt_minutes(),
            },
        }
    }
}

pub fn render_text(
    report: &AnalysisReport,
    gate: &GateEvaluation,
    new_code: Option<&NewCodeAnalysis>,
) -> String {
    let mut issues: Vec<&Issue> = report.issues().iter().collect();
    issues.sort_by(|a, b| {
        b.severity()
            .cmp(&a.severity())
            .then_with(|| a.file().cmp(b.file()))
            .then_with(|| a.span().start_line.cmp(&b.span().start_line))
    });

    let mut out = String::new();
    for issue in &issues {
        out.push_str(&format!(
            "{:<8} {:<24} {}:{}:{}  {}\n",
            issue.severity().to_string().to_uppercase(),
            issue.rule().to_string(),
            issue.file(),
            issue.span().start_line,
            issue.span().start_col,
            issue.message(),
        ));
    }

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
    if metrics.duplicated_blocks() > 0 {
        out.push_str(&format!(
            "Duplication: {} blocks, {} lines ({:.1}%)\n",
            metrics.duplicated_blocks(),
            metrics.duplicated_lines(),
            metrics.duplicated_lines_density(),
        ));
        for block in report.duplications() {
            out.push_str(&format!(
                "  = {}:{}-{} <-> {}:{}-{} ({} lines)\n",
                block.first.file,
                block.first.start_line,
                block.first.end_line,
                block.second.file,
                block.second.start_line,
                block.second.end_line,
                block.lines,
            ));
        }
    }
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
    }
    if let Some(new_code) = new_code {
        out.push_str(&format!("New issues since previous analysis: {}\n", new_code.new_issues().len()));
    }
    out.push_str(&format!("Rating: {}\n", report.rating()));
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
    out
}

pub fn render_json(
    report: &AnalysisReport,
    gate: &GateEvaluation,
    new_code: Option<&NewCodeAnalysis>,
) -> serde_json::Result<String> {
    serde_json::to_string_pretty(&ReportDto::build(report, gate, new_code))
}
