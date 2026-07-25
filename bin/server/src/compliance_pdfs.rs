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

use serde::{Deserialize, Serialize};
use thiserror::Error;

use yunq_rules_engine::{AnalysisReport, Metrics};

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
        unimplemented!(
            "ComplianceReportGenerator::generate({kind:?}) for report with {} issues",
            report.issues.len()
        )
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
    use infra_pdf::AnalysisReport;

    fn empty_report() -> AnalysisReport {
        AnalysisReport::new(Vec::new(), Vec::new(), Metrics::new())
    }

    fn one_finding_report(rule_id: &str, severity: Severity) -> AnalysisReport {
        // REAL shape comes from infra_pdf; we just need a non-empty report
        // to test the rejection / acceptance boundary.
        unimplemented!("test fixture helper: build a 1-finding AnalysisReport for {rule_id} at severity {severity:?}")
    }

    #[test]
    fn rejects_empty_report_for_cwe_top25() {
        let gen = ComplianceReportGenerator::new("Acme Corp");
        let result = gen.generate(&empty_report(), ComplianceReportKind::CweTop25);
        assert_eq!(result, Err(ComplianceError::EmptyReport));
    }

    #[test]
    fn rejects_empty_report_for_pci_dss() {
        let gen = ComplianceReportGenerator::new("Acme Corp");
        let result = gen.generate(&empty_report(), ComplianceReportKind::PciDss);
        assert_eq!(result, Err(ComplianceError::EmptyReport));
    }

    #[test]
    fn rejects_empty_report_for_soc2() {
        let gen = ComplianceReportGenerator::new("Acme Corp");
        let result = gen.generate(&empty_report(), ComplianceReportKind::Soc2);
        assert_eq!(result, Err(ComplianceError::EmptyReport));
    }

    #[test]
    fn cwe_top25_maps_known_cwe_id_to_name() {
        // CWE-89 ("SQL Injection") must resolve to a non-empty name.
        unimplemented!("assertion: present CWE-89 row has name == \"SQL Injection\"")
    }

    #[test]
    fn cwe_top25_sorts_by_count_descending() {
        unimplemented!("assertion: rows are ordered by count desc, then cwe_id asc")
    }

    #[test]
    fn cwe_top25_truncates_to_25_rows() {
        unimplemented!("assertion: even with 100 distinct CWEs, output has 25 rows")
    }

    #[test]
    fn cwe_top25_includes_severity_breakdown() {
        unimplemented!("assertion: each row carries the highest severity observed")
    }

    #[test]
    fn pci_dss_lists_violated_requirements() {
        unimplemented!("assertion: at least one PciRequirementEvidence for req 6.2.4")
    }

    #[test]
    fn pci_dss_groups_findings_by_requirement() {
        unimplemented!("assertion: sum(findings_by_req) == total findings")
    }

    #[test]
    fn pci_dss_dedupes_rule_ids_per_requirement() {
        unimplemented!("assertion: rule_ids is sorted + de-duplicated")
    }

    #[test]
    fn soc2_includes_commit_sha_per_finding() {
        unimplemented!("assertion: each Soc2Evidence.commit_sha is a 40-char hex")
    }

    #[test]
    fn soc2_includes_author_per_finding() {
        unimplemented!("assertion: every evidence row has a non-empty author")
    }

    #[test]
    fn soc2_signed_with_institution_name_in_metadata() {
        let gen = ComplianceReportGenerator::new("Acme Corp");
        // Real test parses the PDF /Info string; placeholder asserts bytes are non-empty.
        unimplemented!("assertion: PDF /Info contains /Author (Acme Corp)")
    }

    #[test]
    fn pdf_output_starts_with_magic_header() {
        let gen = ComplianceReportGenerator::new("Acme Corp");
        let report = one_finding_report("owasp:sqli", Severity::Critical);
        let bytes = gen.generate(&report, ComplianceReportKind::CweTop25).unwrap();
        assert!(bytes.starts_with(b"%PDF-1.4"), "must be a valid PDF 1.4 header");
    }

    #[test]
    fn pdf_output_has_valid_eof_marker() {
        let gen = ComplianceReportGenerator::new("Acme Corp");
        let report = one_finding_report("owasp:sqli", Severity::Critical);
        let bytes = gen.generate(&report, ComplianceReportKind::PciDss).unwrap();
        assert!(bytes.windows(5).any(|w| w == b"%%EOF"), "PDF must end with %%EOF");
    }

    #[test]
    fn unknown_rule_produces_structured_error() {
        unimplemented!("assertion: rule with no PCI mapping → Err(UnknownRule { rule_id, kind: PciDss })")
    }
}
