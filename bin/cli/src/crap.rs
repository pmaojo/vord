//! CRAP (`CC² × (1−coverage)³ + CC`, roadmap item C): once a coverage report
//! has been ingested (`ingest_coverage`), joins it with the per-function
//! cyclomatic complexity `AnalyzerService` already computed
//! (`AnalysisReport::function_complexities`) and turns every function above
//! the refactor-candidate band into an ordinary `crap:high-risk-function`
//! issue — the same `add_external_issues` treatment SARIF import already
//! gets, so the finding flows into the gate, SARIF export and PR decoration
//! with no new plumbing.

use vord_rules_engine::{
    AnalysisReport, CrapFinding, ExternalIssue, HIGH_RISK_THRESHOLD, Issue, IssueType, RuleId,
    Severity,
};

const CRAP_RULE_ID: &str = "crap:high-risk-function";

/// Computes CRAP findings and folds them into `report` as ordinary issues.
/// A no-op when no coverage report was ingested. Returns the findings for
/// the caller's own ranked-list rendering (`output::render_text`'s "Risk
/// hotspots" section).
pub fn apply(report: &mut AnalysisReport) -> Vec<CrapFinding> {
    let Some(findings) = report.compute_crap_findings() else {
        return Vec::new();
    };

    let rule_id = RuleId::new(CRAP_RULE_ID).expect("valid rule id");
    let issues: Vec<ExternalIssue> = findings
        .iter()
        .map(|finding| {
            let severity = if finding.score > HIGH_RISK_THRESHOLD {
                Severity::Critical
            } else {
                Severity::Major
            };
            let message = format!(
                "function has CRAP score {:.1} (cyclomatic complexity {}, {:.0}% line coverage)",
                finding.score, finding.cyclomatic, finding.coverage_percent
            );
            ExternalIssue::new(
                Issue::new(
                    rule_id.clone(),
                    severity,
                    message,
                    finding.path.clone(),
                    finding.span,
                ),
                IssueType::CodeSmell,
            )
        })
        .collect();

    report.add_external_issues(issues);
    findings
}

#[cfg(test)]
mod tests {
    use vord_ast::Span;
    use vord_rules_engine::{CoverageReport, FileCoverage, FileFunctionComplexity, Metrics};

    use super::*;

    #[test]
    fn no_coverage_report_produces_no_findings_and_no_issues() {
        let mut report = AnalysisReport::new(Vec::new(), Vec::new(), Metrics::new())
            .with_function_complexities(vec![FileFunctionComplexity {
                path: "a.rs".into(),
                span: Span::new(1, 1, 5, 1),
                cyclomatic: 20,
            }]);

        let findings = apply(&mut report);

        assert!(findings.is_empty());
        assert!(report.issues().is_empty());
    }

    #[test]
    fn a_high_risk_function_becomes_a_critical_issue() {
        let mut report = AnalysisReport::new(Vec::new(), Vec::new(), Metrics::new())
            .with_function_complexities(vec![FileFunctionComplexity {
                path: "a.rs".into(),
                span: Span::new(1, 1, 2, 1),
                cyclomatic: 10,
            }]);
        let mut file_coverage = FileCoverage::new("a.rs");
        file_coverage.record_line(1, 0);
        file_coverage.record_line(2, 0);
        report.set_coverage_report(CoverageReport::new(vec![file_coverage], 0, 2, 0, 0));

        let findings = apply(&mut report);

        assert_eq!(findings.len(), 1);
        assert_eq!(report.issues().len(), 1);
        assert_eq!(report.issues()[0].rule().as_str(), CRAP_RULE_ID);
        assert_eq!(report.issues()[0].severity(), Severity::Critical);
        assert_eq!(report.crap_findings().len(), 1);
    }

    #[test]
    fn a_moderate_risk_function_becomes_a_major_issue() {
        // CC=6, 50% covered: 36*0.125 + 6 = 10.5 - above the refactor
        // threshold (5) but well below the high-risk band (30).
        let mut report = AnalysisReport::new(Vec::new(), Vec::new(), Metrics::new())
            .with_function_complexities(vec![FileFunctionComplexity {
                path: "a.rs".into(),
                span: Span::new(1, 1, 2, 1),
                cyclomatic: 6,
            }]);
        let mut half_covered = FileCoverage::new("a.rs");
        half_covered.record_line(1, 1);
        half_covered.record_line(2, 0);
        report.set_coverage_report(CoverageReport::new(vec![half_covered], 1, 2, 0, 0));

        let findings = apply(&mut report);

        assert_eq!(findings.len(), 1);
        assert_eq!(report.issues()[0].severity(), Severity::Major);
    }
}
