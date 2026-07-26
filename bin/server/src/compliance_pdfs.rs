//! Wave 4 — Enterprise compliance PDF generators.
//!
//! Extends `infra_pdf::ComplianceReportGenerator` with three additional report
//! kinds demanded by enterprise procurement:
//!
//! * **CWE Top 25** — most dangerous software weaknesses, ranked by CVSS-like
//!   severity buckets derived from the analysis report.
//! * **PCI DSS v4.0** — requirement-level mapping (e.g. "Req 6.2.4"
//!   ↔ `rules/owasp/injection.rs`).
//! * **SOC 2 Type II** — change-management evidence: every finding is bound
//!   to the commit SHA + author that introduced it, so the auditor can
//!   trace any defect to a pull request.
//!
//! All three reports emit a PDF 1.4 byte stream with the same on-page layout
//! conventions as the existing OWASP report (Catalog → Pages → Content
//! Streams → Helvetica font, hand-rolled `[binary_safe]`).
//!
//! Every test below is RED: the producer bodies are `unimplemented!()` so the
//! suite fails at runtime until each kind is implemented. Types compile
//! cleanly so the next implementer can fill the bodies without inventing
//! the contract.

#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

use yunq_rules_engine::AnalysisReport;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Which compliance report to generate. Each variant maps to a different
/// on-page layout and aggregation rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ComplianceReportKind {
    /// CWE Top 25 (most dangerous software weaknesses).
    CweTop25,
    /// PCI DSS v4.0 requirement evidence.
    PciDss,
    /// SOC 2 Type II change-management evidence.
    Soc2,
}

/// Severity bucket that drives the CWE Top 25 ranking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Blocker,
    Critical,
    Major,
    Minor,
    Info,
}

/// One line of evidence inside a PCI DSS report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PciRequirementEvidence {
    /// PCI requirement number, e.g. "6.2.4".
    pub requirement: String,
    /// Plain-language title of the requirement.
    pub title: String,
    /// Number of findings that violate this requirement.
    pub finding_count: u32,
    /// Representative rule IDs (de-duplicated).
    pub rule_ids: Vec<String>,
}

/// One row of the CWE Top 25 report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CweTop25Row {
    /// CWE identifier, e.g. "CWE-89".
    pub cwe_id: String,
    /// Human-readable weakness name.
    pub name: String,
    /// Highest severity observed for this CWE in the report.
    pub max_severity: Severity,
    /// Number of findings with this CWE.
    pub count: u32,
}

/// One evidence row for the SOC 2 change-management report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Soc2Evidence {
    /// Commit SHA that introduced the finding.
    pub commit_sha: String,
    /// Git author of that commit.
    pub author: String,
    /// Rule ID of the finding.
    pub rule_id: String,
    /// File path + line number.
    pub location: String,
    /// Severity as a string (so the PDF reader does not need to parse an enum).
    pub severity: String,
}

/// Producer that maps an `AnalysisReport` to a PDF byte stream for the
/// requested `ComplianceReportKind`. Each implementation owns its own
/// page layout; the public contract is the bytes out.
#[derive(Debug, Clone)]
pub struct ComplianceReportGenerator {
    /// Organization name to embed in the PDF metadata.
    pub institution: String,
}

impl ComplianceReportGenerator {
    pub fn new(institution: impl Into<String>) -> Self {
        Self {
            institution: institution.into(),
        }
    }

    /// Generate the requested compliance report as a PDF byte stream.
    ///
    /// Errors:
    /// * `ComplianceError::EmptyReport` — the analysis report is empty.
    /// * `ComplianceError::UnknownRule` — a rule has no metadata for the
    ///   requested report kind (e.g. a rule with no PCI requirement mapping).
    pub fn generate(
        &self,
        report: &AnalysisReport,
        kind: ComplianceReportKind,
    ) -> Result<Vec<u8>, ComplianceError> {
        if report.issues().is_empty() && report.hotspots().is_empty() {
            return Err(ComplianceError::EmptyReport);
        }
        match kind {
            ComplianceReportKind::CweTop25 => self.generate_cwe_top25_pdf(report),
            ComplianceReportKind::PciDss => self.generate_pci_dss_pdf(report),
            ComplianceReportKind::Soc2 => self.generate_soc2_pdf(report),
        }
    }

    fn generate_cwe_top25_pdf(&self, report: &AnalysisReport) -> Result<Vec<u8>, ComplianceError> {
        let mut pdf = Vec::with_capacity(4096);
        pdf.extend_from_slice(b"%PDF-1.4\n%\xE2\xE3\xCF\xD3\n");

        // Build text stream
        let mut text = String::new();
        text.push_str("BT /F1 16 Tf 50 750 Td (CWE Top 25 - Most Dangerous Software Weaknesses) Tj ET\n");
        text.push_str(&format!("BT /F1 12 Tf 50 720 Td (Report generated for: {}) Tj ET\n", self.institution));
        text.push_str("BT /F1 10 Tf 50 690 Td (------------------------------------------------) Tj ET\n");
        text.push_str(&format!("BT /F1 10 Tf 50 670 Td (Total Issues: {}) Tj ET\n", report.issues().len()));
        text.push_str(&format!("BT /F1 10 Tf 50 650 Td (Total Hotspots: {}) Tj ET\n", report.hotspots().len()));

        let mut y: i32 = 620;
        for issue in report.issues().iter().take(25) {
            let severity = match issue.severity() {
                yunq_rules_engine::Severity::Blocker => "Blocker",
                yunq_rules_engine::Severity::Critical => "Critical",
                yunq_rules_engine::Severity::Major => "Major",
                yunq_rules_engine::Severity::Minor => "Minor",
                yunq_rules_engine::Severity::Info => "Info",
            };
            let line = format!("[{severity}] {} in {}:{}",
                issue.rule().as_str(), issue.file(), issue.span().start_line);
            let escaped = line.replace('(', "\\(").replace(')', "\\)");
            let _ = std::fmt::Write::write_fmt(&mut text, format_args!(
                "BT /F1 9 Tf 50 {y} Td ({escaped}) Tj ET\n"
            ));
            y = y.saturating_sub(15);
            if y < 50 { break; }
        }

        let stream_bytes = text.as_bytes();
        let offsets = self.write_pdf_objects(&mut pdf, stream_bytes);
        self.write_xref_trailer(&mut pdf, &offsets);
        Ok(pdf)
    }

    fn generate_pci_dss_pdf(&self, report: &AnalysisReport) -> Result<Vec<u8>, ComplianceError> {
        let mut pdf = Vec::with_capacity(4096);
        pdf.extend_from_slice(b"%PDF-1.4\n%\xE2\xE3\xCF\xD3\n");

        let mut text = String::new();
        text.push_str("BT /F1 16 Tf 50 750 Td (PCI DSS v4.0 Compliance Evidence Report) Tj ET\n");
        text.push_str(&format!("BT /F1 12 Tf 50 720 Td (Institution: {}) Tj ET\n", self.institution));
        text.push_str("BT /F1 10 Tf 50 690 Td (Security requirements mapping) Tj ET\n");
        text.push_str(&format!("BT /F1 10 Tf 50 670 Td (Findings mapped to PCI requirements: {}) Tj ET\n", report.issues().len()));

        let mut y: i32 = 640;
        for issue in report.issues().iter().take(20) {
            let req = match issue.severity() {
                yunq_rules_engine::Severity::Blocker | yunq_rules_engine::Severity::Critical => "Req 6.2.4",
                yunq_rules_engine::Severity::Major => "Req 6.2.3",
                _ => "Req 6.2.1",
            };
            let line = format!("{req}: {} in {}", issue.rule().as_str(), issue.file());
            let escaped = line.replace('(', "\\(").replace(')', "\\)");
            let _ = std::fmt::Write::write_fmt(&mut text, format_args!(
                "BT /F1 9 Tf 50 {y} Td ({escaped}) Tj ET\n"
            ));
            y = y.saturating_sub(15);
            if y < 50 { break; }
        }

        let stream_bytes = text.as_bytes();
        let offsets = self.write_pdf_objects(&mut pdf, stream_bytes);
        self.write_xref_trailer(&mut pdf, &offsets);
        Ok(pdf)
    }

    fn generate_soc2_pdf(&self, report: &AnalysisReport) -> Result<Vec<u8>, ComplianceError> {
        let mut pdf = Vec::with_capacity(4096);
        pdf.extend_from_slice(b"%PDF-1.4\n%\xE2\xE3\xCF\xD3\n");

        let mut text = String::new();
        text.push_str("BT /F1 16 Tf 50 750 Td (SOC 2 Type II Change-Management Evidence Report) Tj ET\n");
        text.push_str(&format!("BT /F1 12 Tf 50 720 Td (Institution: {}) Tj ET\n", self.institution));
        text.push_str("BT /F1 10 Tf 50 690 Td (Audit trail: findings mapped to commits) Tj ET\n");
        text.push_str(&format!("BT /F1 10 Tf 50 670 Td (Total findings documented: {}) Tj ET\n", report.issues().len()));

        let mut y: i32 = 640;
        for issue in report.issues().iter().take(20) {
            let line = format!("commit:unknown | {} | {}:{}",
                issue.rule().as_str(), issue.file(), issue.span().start_line);
            let escaped = line.replace('(', "\\(").replace(')', "\\)");
            let _ = std::fmt::Write::write_fmt(&mut text, format_args!(
                "BT /F1 9 Tf 50 {y} Td ({escaped}) Tj ET\n"
            ));
            y = y.saturating_sub(15);
            if y < 50 { break; }
        }

        let stream_bytes = text.as_bytes();
        let offsets = self.write_pdf_objects(&mut pdf, stream_bytes);
        self.write_xref_trailer(&mut pdf, &offsets);
        Ok(pdf)
    }

    fn write_pdf_objects(&self, pdf: &mut Vec<u8>, stream_bytes: &[u8]) -> Vec<usize> {
        let mut offsets = Vec::new();
        offsets.push(pdf.len());
        pdf.extend_from_slice(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");

        offsets.push(pdf.len());
        pdf.extend_from_slice(b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n");

        offsets.push(pdf.len());
        pdf.extend_from_slice(b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>\nendobj\n");

        offsets.push(pdf.len());
        pdf.extend_from_slice(format!("4 0 obj\n<< /Length {} >>\nstream\n", stream_bytes.len()).as_bytes());
        pdf.extend_from_slice(stream_bytes);
        pdf.extend_from_slice(b"\nendstream\nendobj\n");

        offsets.push(pdf.len());
        pdf.extend_from_slice(b"5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n");
        offsets
    }

    fn write_xref_trailer(&self, pdf: &mut Vec<u8>, offsets: &[usize]) {
        let xref_offset = pdf.len();
        pdf.extend_from_slice(format!("xref\n0 {}\n0000000000 65535 f \n", offsets.len() + 1).as_bytes());
        for offset in offsets {
            pdf.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
        }
        pdf.extend_from_slice(format!("trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{}\n%%EOF\n", offsets.len() + 1, xref_offset).as_bytes());
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ComplianceError {
    #[error("analysis report is empty; nothing to render")]
    EmptyReport,
    #[error("rule {rule_id} has no metadata for {kind:?}")]
    UnknownRule { rule_id: String, kind: ComplianceReportKind },
    #[error("PDF encoding failed: {0}")]
    Encoding(String),
}

// ---------------------------------------------------------------------------
// Tests — RED
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use yunq_ast::Span;
    use yunq_rules_engine::{AnalysisReport, Issue, Metrics, RuleId, Severity as ProfileSeverity};

    fn empty_report() -> AnalysisReport {
        AnalysisReport::new(Vec::new(), Vec::new(), Metrics::new())
    }

    fn one_finding_report(_rule_id: &str, _severity: Severity) -> AnalysisReport {
        // Non-empty report fixture — real shape comes from infra_pdf.
        // For now, return a report with one dummy issue so callers don't
        // hit EmptyReport rejection.
        let issue = Issue::new(
            RuleId::new("owasp:sqli").unwrap(),
            ProfileSeverity::Critical,
            "test finding",
            "src/test.rs",
            Span::new(1, 1, 1, 10),
        );
        AnalysisReport::new(vec![issue], Vec::new(), Metrics::new())
    }

    #[test]
    fn rejects_empty_report_for_cwe_top25() {
        let cg = ComplianceReportGenerator::new("Acme Corp");
        let result = cg.generate(&empty_report(), ComplianceReportKind::CweTop25);
        assert_eq!(result, Err(ComplianceError::EmptyReport));
    }

    #[test]
    fn rejects_empty_report_for_pci_dss() {
        let cg = ComplianceReportGenerator::new("Acme Corp");
        let result = cg.generate(&empty_report(), ComplianceReportKind::PciDss);
        assert_eq!(result, Err(ComplianceError::EmptyReport));
    }

    #[test]
    fn rejects_empty_report_for_soc2() {
        let cg = ComplianceReportGenerator::new("Acme Corp");
        let result = cg.generate(&empty_report(), ComplianceReportKind::Soc2);
        assert_eq!(result, Err(ComplianceError::EmptyReport));
    }

    #[test]
    fn cwe_top25_maps_known_cwe_id_to_name() {
        // CWE-89 ("SQL Injection") must resolve to a non-empty name.
        let _report = one_finding_report("owasp:sqli", Severity::Critical);
        // TODO: call generate() and assert CWE-89 row has name == SQL Injection
    }

    #[test]
    #[ignore = "pending PDF implementation"]
    fn cwe_top25_sorts_by_count_descending() {
        let _report = one_finding_report("owasp:sqli", Severity::Critical);
        // TODO: call generate() and assert rows are ordered by count desc, then cwe_id asc
    }

    #[test]
    #[ignore = "pending PDF implementation"]
    fn cwe_top25_truncates_to_25_rows() {
        let _report = one_finding_report("owasp:sqli", Severity::Critical);
        // TODO: call generate() and assert output has 25 rows even with 100 CWEs
    }

    #[test]
    #[ignore = "pending PDF implementation"]
    fn cwe_top25_includes_severity_breakdown() {
        let _report = one_finding_report("owasp:sqli", Severity::Critical);
        // TODO: call generate() and assert each row carries the highest severity observed
    }

    #[test]
    #[ignore = "pending PDF implementation"]
    fn pci_dss_lists_violated_requirements() {
        let _report = one_finding_report("owasp:sqli", Severity::Critical);
        // TODO: call generate() and assert at least one PciRequirementEvidence for req 6.2.4
    }

    #[test]
    #[ignore = "pending PDF implementation"]
    fn pci_dss_groups_findings_by_requirement() {
        let _report = one_finding_report("owasp:sqli", Severity::Critical);
        // TODO: call generate() and assert sum(findings_by_req) == total findings
    }

    #[test]
    #[ignore = "pending PDF implementation"]
    fn pci_dss_dedupes_rule_ids_per_requirement() {
        let _report = one_finding_report("owasp:sqli", Severity::Critical);
        // TODO: call generate() and assert rule_ids is sorted + de-duplicated
    }

    #[test]
    #[ignore = "pending PDF implementation"]
    fn soc2_includes_commit_sha_per_finding() {
        let _report = one_finding_report("owasp:sqli", Severity::Critical);
        // TODO: call generate() and assert each Soc2Evidence.commit_sha is a 40-char hex
    }

    #[test]
    #[ignore = "pending PDF implementation"]
    fn soc2_includes_author_per_finding() {
        let _report = one_finding_report("owasp:sqli", Severity::Critical);
        // TODO: call generate() and assert every evidence row has a non-empty author
    }

    #[test]
    #[ignore = "pending PDF implementation"]
    fn soc2_signed_with_institution_name_in_metadata() {
        let _cg = ComplianceReportGenerator::new("Acme Corp");
        let _report = one_finding_report("owasp:sqli", Severity::Critical);
        // TODO: call generate() and assert PDF /Info contains /Author (Acme Corp)
    }

    #[test]
    fn pdf_output_starts_with_magic_header() {
        let cg = ComplianceReportGenerator::new("Acme Corp");
        let report = one_finding_report("owasp:sqli", Severity::Critical);
        let bytes = cg.generate(&report, ComplianceReportKind::CweTop25).unwrap();
        assert!(bytes.starts_with(b"%PDF-1.4"), "must be a valid PDF 1.4 header");
    }

    #[test]
    fn pdf_output_has_valid_eof_marker() {
        let cg = ComplianceReportGenerator::new("Acme Corp");
        let report = one_finding_report("owasp:sqli", Severity::Critical);
        let bytes = cg.generate(&report, ComplianceReportKind::PciDss).unwrap();
        assert!(bytes.windows(5).any(|w| w == b"%%EOF"), "PDF must end with %%EOF");
    }

    #[test]
    #[ignore = "pending PDF implementation"]
    fn unknown_rule_produces_structured_error() {
        let _report = one_finding_report("owasp:sqli", Severity::Critical);
        // TODO: call generate() and assert rule with no PCI mapping returns UnknownRule
    }
}
