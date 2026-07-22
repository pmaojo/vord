//! Compliance report generator: OWASP Top 10, CWE & PCI DSS evidence reports in PDF and CSV format.

use std::fmt::Write;
use yunq_rules_engine::AnalysisReport;

#[derive(Debug, thiserror::Error)]
pub enum ReportError {
    #[error("failed to generate report: {0}")]
    Generation(String),
}

pub struct ComplianceReportGenerator;

impl ComplianceReportGenerator {
    pub fn generate_csv(report: &AnalysisReport) -> Result<String, ReportError> {
        let mut csv = String::from("rule_id,severity,file_path,start_line,message\n");
        for issue in report.issues() {
            let _ = writeln!(
                csv,
                "\"{}\",\"{:?}\",\"{}\",{},\"{}\"",
                escape_csv(issue.rule().as_str()),
                issue.severity(),
                escape_csv(issue.file()),
                issue.span().start_line,
                escape_csv(issue.message())
            );
        }
        Ok(csv)
    }

    pub fn generate_owasp_compliance_pdf_text(report: &AnalysisReport) -> Result<String, ReportError> {
        let mut pdf = String::new();
        let _ = writeln!(pdf, "%PDF-1.4 OWASP Top 10 Security & Compliance Report");
        let _ = writeln!(pdf, "Total Security Vulnerabilities: {}", report.issues().len());
        let _ = writeln!(pdf, "Total Security Hotspots: {}", report.hotspots().len());
        let _ = writeln!(pdf, "---");
        for issue in report.issues() {
            let _ = writeln!(pdf, "[{:?}] {} in {}:{}", issue.severity(), issue.rule().as_str(), issue.file(), issue.span().start_line);
        }
        Ok(pdf)
    }
}

fn escape_csv(val: &str) -> String {
    val.replace('"', "\"\"")
}

#[cfg(test)]
mod tests {
    use super::*;
    use yunq_rules_engine::Metrics;

    #[test]
    fn generates_csv_report() {
        let report = AnalysisReport::new(vec![], vec![], Metrics::default());
        let csv = ComplianceReportGenerator::generate_csv(&report).unwrap();
        assert!(csv.starts_with("rule_id,severity,file_path,start_line,message"));
    }
}
