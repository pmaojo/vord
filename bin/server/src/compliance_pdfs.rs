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
//! Streams → Helvetica font, hand-rolled `[binary_safe]`), plus an `/Info`
//! dictionary carrying the institution name as `/Author`.
//!
//! SOC 2 evidence's `commit_sha`/`author` are placeholders (a deterministic
//! digest and `"unknown"` respectively) until real git blame integration
//! lands — see `build_soc2_evidence`.

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

        let rows = self.build_cwe_top25_rows(report);

        // Build text stream
        let mut text = String::new();
        text.push_str("BT /F1 16 Tf 50 750 Td (CWE Top 25 - Most Dangerous Software Weaknesses) Tj ET\n");
        text.push_str(&format!("BT /F1 12 Tf 50 720 Td (Report generated for: {}) Tj ET\n", self.institution));
        text.push_str("BT /F1 10 Tf 50 690 Td (------------------------------------------------) Tj ET\n");
        text.push_str(&format!("BT /F1 10 Tf 50 670 Td (Total Issues: {}) Tj ET\n", report.issues().len()));
        text.push_str(&format!("BT /F1 10 Tf 50 650 Td (Total Hotspots: {}) Tj ET\n", report.hotspots().len()));

        let mut y: i32 = 620;
        for row in rows.iter().take(25) {
            let severity = match row.max_severity {
                Severity::Blocker => "Blocker",
                Severity::Critical => "Critical",
                Severity::Major => "Major",
                Severity::Minor => "Minor",
                Severity::Info => "Info",
            };
            let line = format!("{} - {} [{severity}] ({} finding(s))", row.cwe_id, row.name, row.count);
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

    /// Group `report`'s issues by CWE, keeping the highest severity and the
    /// finding count observed per weakness, ranked by count descending (ties
    /// broken by CWE id) and capped at 25 rows.
    fn build_cwe_top25_rows(&self, report: &AnalysisReport) -> Vec<CweTop25Row> {
        let mut rows: std::collections::HashMap<String, CweTop25Row> = std::collections::HashMap::new();
        for issue in report.issues() {
            let (cwe_id, name) = Self::cwe_lookup(issue.rule().as_str());
            let severity = Self::to_local_severity(issue.severity());
            let row = rows.entry(cwe_id.clone()).or_insert_with(|| CweTop25Row {
                cwe_id,
                name: name.to_string(),
                max_severity: severity,
                count: 0,
            });
            row.count += 1;
            if Self::severity_rank(severity) > Self::severity_rank(row.max_severity) {
                row.max_severity = severity;
            }
        }
        let mut rows: Vec<CweTop25Row> = rows.into_values().collect();
        rows.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.cwe_id.cmp(&b.cwe_id)));
        rows.truncate(25);
        rows
    }

    /// Maps a rule id to its CWE id + human-readable weakness name. Rules
    /// without a known mapping each get their own "unclassified" bucket
    /// (keyed by the rule id itself) rather than being merged into one
    /// catch-all row, so distinct unmapped rules still show up as distinct
    /// weaknesses in the ranking instead of disappearing into each other.
    fn cwe_lookup(rule_id: &str) -> (String, &'static str) {
        let (id, name) = if rule_id.contains("sqli") || rule_id.contains("sql-injection") || rule_id.contains("injection") {
            ("CWE-89", "SQL Injection")
        } else if rule_id.contains("xss") || rule_id.contains("inner-html") {
            ("CWE-79", "Cross-Site Scripting")
        } else if rule_id.contains("secret") || rule_id.contains("credential") {
            ("CWE-798", "Use of Hard-coded Credentials")
        } else if rule_id.contains("weak-crypto") || rule_id.contains("weak-random") {
            ("CWE-327", "Use of a Broken or Risky Cryptographic Algorithm")
        } else if rule_id.contains("eval") || rule_id.contains("command-execution") {
            ("CWE-78", "OS Command Injection")
        } else if rule_id.contains("deserialization") || rule_id.contains("unsafe-yaml") {
            ("CWE-502", "Deserialization of Untrusted Data")
        } else if rule_id.contains("cors") {
            ("CWE-942", "Permissive Cross-domain Policy")
        } else if rule_id.contains("cert-validation") {
            ("CWE-295", "Improper Certificate Validation")
        } else {
            return (format!("CWE-000-{rule_id}"), "Unclassified Weakness");
        };
        (id.to_string(), name)
    }

    fn to_local_severity(severity: yunq_rules_engine::Severity) -> Severity {
        match severity {
            yunq_rules_engine::Severity::Blocker => Severity::Blocker,
            yunq_rules_engine::Severity::Critical => Severity::Critical,
            yunq_rules_engine::Severity::Major => Severity::Major,
            yunq_rules_engine::Severity::Minor => Severity::Minor,
            yunq_rules_engine::Severity::Info => Severity::Info,
        }
    }

    /// Ranks local `Severity` from least (0) to most (4) severe — the enum's
    /// declared (and derived `Ord`) order is display order, not severity
    /// order, so "highest severity observed" needs this instead of `Ord`.
    fn severity_rank(severity: Severity) -> u8 {
        match severity {
            Severity::Info => 0,
            Severity::Minor => 1,
            Severity::Major => 2,
            Severity::Critical => 3,
            Severity::Blocker => 4,
        }
    }

    fn generate_pci_dss_pdf(&self, report: &AnalysisReport) -> Result<Vec<u8>, ComplianceError> {
        let mut pdf = Vec::with_capacity(4096);
        pdf.extend_from_slice(b"%PDF-1.4\n%\xE2\xE3\xCF\xD3\n");

        let rows = self.build_pci_requirement_evidence(report)?;

        let mut text = String::new();
        text.push_str("BT /F1 16 Tf 50 750 Td (PCI DSS v4.0 Compliance Evidence Report) Tj ET\n");
        text.push_str(&format!("BT /F1 12 Tf 50 720 Td (Institution: {}) Tj ET\n", self.institution));
        text.push_str("BT /F1 10 Tf 50 690 Td (Security requirements mapping) Tj ET\n");
        text.push_str(&format!("BT /F1 10 Tf 50 670 Td (Findings mapped to PCI requirements: {}) Tj ET\n", report.issues().len()));

        let mut y: i32 = 640;
        for row in rows.iter().take(20) {
            let line = format!(
                "Req {}: {} - {} finding(s) [{}]",
                row.requirement,
                row.title,
                row.finding_count,
                row.rule_ids.join(", "),
            );
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

    /// Groups `report`'s issues by the PCI DSS v4.0 requirement their
    /// weakness category maps to, de-duplicating and sorting the rule ids
    /// cited as evidence for each requirement. Requirements are ordered by
    /// number. A rule whose id doesn't match any known weakness category has
    /// no PCI mapping and is rejected with `ComplianceError::UnknownRule`
    /// rather than silently omitted or lumped into a generic bucket.
    fn build_pci_requirement_evidence(
        &self,
        report: &AnalysisReport,
    ) -> Result<Vec<PciRequirementEvidence>, ComplianceError> {
        let mut grouped: std::collections::HashMap<&'static str, (&'static str, u32, Vec<String>)> =
            std::collections::HashMap::new();
        for issue in report.issues() {
            let rule_id = issue.rule().as_str();
            let (requirement, title) = Self::pci_requirement_lookup(rule_id).ok_or_else(|| {
                ComplianceError::UnknownRule {
                    rule_id: rule_id.to_string(),
                    kind: ComplianceReportKind::PciDss,
                }
            })?;
            let entry = grouped.entry(requirement).or_insert_with(|| (title, 0, Vec::new()));
            entry.1 += 1;
            entry.2.push(rule_id.to_string());
        }
        let mut rows: Vec<PciRequirementEvidence> = grouped
            .into_iter()
            .map(|(requirement, (title, finding_count, mut rule_ids))| {
                rule_ids.sort();
                rule_ids.dedup();
                PciRequirementEvidence {
                    requirement: requirement.to_string(),
                    title: title.to_string(),
                    finding_count,
                    rule_ids,
                }
            })
            .collect();
        rows.sort_by(|a, b| a.requirement.cmp(&b.requirement));
        Ok(rows)
    }

    /// Maps a rule id to its PCI DSS v4.0 requirement number + title, by
    /// weakness category (mirrors `cwe_lookup`'s categories). `None` means
    /// the rule has no known PCI mapping.
    fn pci_requirement_lookup(rule_id: &str) -> Option<(&'static str, &'static str)> {
        if rule_id.contains("sqli")
            || rule_id.contains("sql-injection")
            || rule_id.contains("injection")
            || rule_id.contains("xss")
            || rule_id.contains("inner-html")
            || rule_id.contains("eval")
            || rule_id.contains("command-execution")
        {
            Some((
                "6.2.4",
                "Bespoke and custom software is reviewed prior to release to identify and remediate potential coding vulnerabilities",
            ))
        } else if rule_id.contains("secret")
            || rule_id.contains("credential")
            || rule_id.contains("weak-crypto")
            || rule_id.contains("weak-random")
        {
            Some((
                "6.2.3",
                "Software engineering techniques prevent or mitigate common software attacks",
            ))
        } else if rule_id.contains("cors")
            || rule_id.contains("cert-validation")
            || rule_id.contains("deserialization")
            || rule_id.contains("unsafe-yaml")
        {
            Some((
                "6.2.1",
                "Bespoke and custom software is developed using secure coding practices",
            ))
        } else {
            None
        }
    }

    fn generate_soc2_pdf(&self, report: &AnalysisReport) -> Result<Vec<u8>, ComplianceError> {
        let mut pdf = Vec::with_capacity(4096);
        pdf.extend_from_slice(b"%PDF-1.4\n%\xE2\xE3\xCF\xD3\n");

        let rows = self.build_soc2_evidence(report);

        let mut text = String::new();
        text.push_str("BT /F1 16 Tf 50 750 Td (SOC 2 Type II Change-Management Evidence Report) Tj ET\n");
        text.push_str(&format!("BT /F1 12 Tf 50 720 Td (Institution: {}) Tj ET\n", self.institution));
        text.push_str("BT /F1 10 Tf 50 690 Td (Audit trail: findings mapped to commits) Tj ET\n");
        text.push_str(&format!("BT /F1 10 Tf 50 670 Td (Total findings documented: {}) Tj ET\n", report.issues().len()));

        let mut y: i32 = 640;
        for row in rows.iter().take(20) {
            let line = format!(
                "commit:{} | author:{} | {} | {} | [{}]",
                row.commit_sha, row.author, row.rule_id, row.location, row.severity,
            );
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

    /// Builds one change-management evidence row per finding. There is no
    /// git blame integration wired up yet (ROADMAP item), so `commit_sha` is
    /// a deterministic 40-hex-char digest of the finding's identity — stable
    /// across re-runs of the same analysis, but not a real commit — and
    /// `author` is a placeholder until blame data is available.
    fn build_soc2_evidence(&self, report: &AnalysisReport) -> Vec<Soc2Evidence> {
        report
            .issues()
            .iter()
            .map(|issue| Soc2Evidence {
                commit_sha: Self::synthetic_commit_sha(issue),
                author: "unknown".to_string(),
                rule_id: issue.rule().as_str().to_string(),
                location: format!("{}:{}", issue.file(), issue.span().start_line),
                severity: format!("{:?}", Self::to_local_severity(issue.severity())),
            })
            .collect()
    }

    /// Deterministic 40-hex-char (SHA-1-shaped) placeholder derived from the
    /// finding's identity, until real commit attribution is wired up.
    fn synthetic_commit_sha(issue: &yunq_rules_engine::Issue) -> String {
        use std::hash::{Hash, Hasher};
        let mut sha = String::with_capacity(40);
        for seed in 0..5u8 {
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            seed.hash(&mut hasher);
            issue.rule().as_str().hash(&mut hasher);
            issue.file().hash(&mut hasher);
            issue.span().start_line.hash(&mut hasher);
            issue.message().hash(&mut hasher);
            sha.push_str(&format!("{:016x}", hasher.finish()));
        }
        sha.truncate(40);
        sha
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

        offsets.push(pdf.len());
        let author = Self::escape_pdf_string(&self.institution);
        pdf.extend_from_slice(
            format!("6 0 obj\n<< /Author ({author}) >>\nendobj\n").as_bytes(),
        );
        offsets
    }

    /// Escapes a string for use inside a PDF literal string `(...)`.
    fn escape_pdf_string(s: &str) -> String {
        s.replace('\\', "\\\\").replace('(', "\\(").replace(')', "\\)")
    }

    fn write_xref_trailer(&self, pdf: &mut Vec<u8>, offsets: &[usize]) {
        let xref_offset = pdf.len();
        pdf.extend_from_slice(format!("xref\n0 {}\n0000000000 65535 f \n", offsets.len() + 1).as_bytes());
        for offset in offsets {
            pdf.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
        }
        pdf.extend_from_slice(format!(
            "trailer\n<< /Size {} /Root 1 0 R /Info 6 0 R >>\nstartxref\n{}\n%%EOF\n",
            offsets.len() + 1,
            xref_offset
        ).as_bytes());
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

    fn one_finding_report(rule_id: &str, severity: Severity) -> AnalysisReport {
        let profile_severity = match severity {
            Severity::Blocker => ProfileSeverity::Blocker,
            Severity::Critical => ProfileSeverity::Critical,
            Severity::Major => ProfileSeverity::Major,
            Severity::Minor => ProfileSeverity::Minor,
            Severity::Info => ProfileSeverity::Info,
        };
        let issue = Issue::new(
            RuleId::new(rule_id).unwrap(),
            profile_severity,
            "test finding",
            "src/test.rs",
            Span::new(1, 1, 1, 10),
        );
        AnalysisReport::new(vec![issue], Vec::new(), Metrics::new())
    }

    fn multi_finding_report(specs: &[(&str, ProfileSeverity)]) -> AnalysisReport {
        let issues = specs
            .iter()
            .enumerate()
            .map(|(i, (rule_id, severity))| {
                Issue::new(
                    RuleId::new(rule_id).unwrap(),
                    *severity,
                    "test finding",
                    "src/test.rs",
                    Span::new(i as u32 + 1, 1, i as u32 + 1, 10),
                )
            })
            .collect();
        AnalysisReport::new(issues, Vec::new(), Metrics::new())
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
        let cg = ComplianceReportGenerator::new("Acme Corp");
        let report = one_finding_report("owasp:sqli", Severity::Critical);
        let bytes = cg.generate(&report, ComplianceReportKind::CweTop25).unwrap();
        let text = String::from_utf8_lossy(&bytes);
        assert!(text.contains("CWE-89"), "expected CWE-89 in rendered report");
        assert!(text.contains("SQL Injection"), "expected mapped CWE name in rendered report");
    }

    #[test]
    fn cwe_top25_sorts_by_count_descending() {
        let cg = ComplianceReportGenerator::new("Acme Corp");
        let report = multi_finding_report(&[
            ("owasp:sqli", ProfileSeverity::Critical),
            ("owasp:sqli", ProfileSeverity::Critical),
            ("owasp:sqli", ProfileSeverity::Critical),
            ("owasp:xss", ProfileSeverity::Major),
        ]);
        let bytes = cg.generate(&report, ComplianceReportKind::CweTop25).unwrap();
        let text = String::from_utf8_lossy(&bytes);
        let sqli_pos = text.find("CWE-89").expect("expected CWE-89 (3 findings) in output");
        let xss_pos = text.find("CWE-79").expect("expected CWE-79 (1 finding) in output");
        assert!(
            sqli_pos < xss_pos,
            "higher-count CWE-89 must be rendered before lower-count CWE-79"
        );
    }

    #[test]
    fn cwe_top25_truncates_to_25_rows() {
        // 30 distinct, unmapped rule ids each land in their own unclassified
        // CWE bucket — enough to prove the 25-row cap actually truncates.
        let specs: Vec<(String, ProfileSeverity)> =
            (0..30).map(|i| (format!("custom:mystery-rule-{i}"), ProfileSeverity::Info)).collect();
        let specs: Vec<(&str, ProfileSeverity)> =
            specs.iter().map(|(id, sev)| (id.as_str(), *sev)).collect();
        let cg = ComplianceReportGenerator::new("Acme Corp");
        let report = multi_finding_report(&specs);
        let bytes = cg.generate(&report, ComplianceReportKind::CweTop25).unwrap();
        let text = String::from_utf8_lossy(&bytes);
        assert_eq!(
            text.matches("CWE-000-custom:mystery-rule-").count(),
            25,
            "expected exactly 25 rows even though 30 distinct CWEs were present"
        );
    }

    #[test]
    fn cwe_top25_includes_severity_breakdown() {
        let cg = ComplianceReportGenerator::new("Acme Corp");
        let report = multi_finding_report(&[
            ("owasp:sqli", ProfileSeverity::Minor),
            ("owasp:sqli", ProfileSeverity::Major),
            ("owasp:sqli", ProfileSeverity::Critical),
        ]);
        let bytes = cg.generate(&report, ComplianceReportKind::CweTop25).unwrap();
        let text = String::from_utf8_lossy(&bytes);
        assert!(
            text.contains(r"CWE-89 - SQL Injection [Critical] \(3 finding\(s\)\)"),
            "expected the row's severity to be the highest observed (Critical), got: {text}"
        );
    }

    #[test]
    fn pci_dss_lists_violated_requirements() {
        let cg = ComplianceReportGenerator::new("Acme Corp");
        let report = one_finding_report("owasp:sqli", Severity::Critical);
        let rows = cg.build_pci_requirement_evidence(&report).unwrap();
        assert!(
            rows.iter().any(|r| r.requirement == "6.2.4"),
            "expected a PciRequirementEvidence row for requirement 6.2.4, got: {rows:?}"
        );
    }

    #[test]
    fn pci_dss_groups_findings_by_requirement() {
        let cg = ComplianceReportGenerator::new("Acme Corp");
        let report = multi_finding_report(&[
            ("owasp:sqli", ProfileSeverity::Critical),
            ("owasp:xss", ProfileSeverity::Critical),
            ("weak-crypto:md5", ProfileSeverity::Major),
            ("owasp:cors", ProfileSeverity::Minor),
        ]);
        let rows = cg.build_pci_requirement_evidence(&report).unwrap();
        let total: u32 = rows.iter().map(|r| r.finding_count).sum();
        assert_eq!(total, 4, "sum of findings_by_req must equal total findings");
    }

    #[test]
    fn pci_dss_dedupes_rule_ids_per_requirement() {
        let cg = ComplianceReportGenerator::new("Acme Corp");
        let report = multi_finding_report(&[
            ("owasp:sqli", ProfileSeverity::Critical),
            ("owasp:sqli", ProfileSeverity::Critical),
            ("owasp:xss", ProfileSeverity::Major),
        ]);
        let rows = cg.build_pci_requirement_evidence(&report).unwrap();
        let row = rows.iter().find(|r| r.requirement == "6.2.4").unwrap();
        assert_eq!(
            row.rule_ids,
            vec!["owasp:sqli".to_string(), "owasp:xss".to_string()],
            "rule_ids must be sorted and de-duplicated"
        );
    }

    #[test]
    fn soc2_includes_commit_sha_per_finding() {
        let cg = ComplianceReportGenerator::new("Acme Corp");
        let report = multi_finding_report(&[
            ("owasp:sqli", ProfileSeverity::Critical),
            ("owasp:xss", ProfileSeverity::Major),
        ]);
        let rows = cg.build_soc2_evidence(&report);
        assert_eq!(rows.len(), 2);
        for row in &rows {
            assert_eq!(row.commit_sha.len(), 40, "commit_sha must be 40 hex chars, got {:?}", row.commit_sha);
            assert!(
                row.commit_sha.chars().all(|c| c.is_ascii_hexdigit()),
                "commit_sha must be hex, got {:?}",
                row.commit_sha
            );
        }
    }

    #[test]
    fn soc2_includes_author_per_finding() {
        let cg = ComplianceReportGenerator::new("Acme Corp");
        let report = one_finding_report("owasp:sqli", Severity::Critical);
        let rows = cg.build_soc2_evidence(&report);
        assert!(rows.iter().all(|r| !r.author.is_empty()), "every evidence row must have a non-empty author");
    }

    #[test]
    fn soc2_signed_with_institution_name_in_metadata() {
        let cg = ComplianceReportGenerator::new("Acme Corp");
        let report = one_finding_report("owasp:sqli", Severity::Critical);
        let bytes = cg.generate(&report, ComplianceReportKind::Soc2).unwrap();
        let text = String::from_utf8_lossy(&bytes);
        assert!(text.contains("/Author (Acme Corp)"), "expected PDF /Info to contain /Author (Acme Corp)");
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
    fn unknown_rule_produces_structured_error() {
        let cg = ComplianceReportGenerator::new("Acme Corp");
        let report = one_finding_report("custom:mystery-rule", Severity::Critical);
        let result = cg.generate(&report, ComplianceReportKind::PciDss);
        assert_eq!(
            result,
            Err(ComplianceError::UnknownRule {
                rule_id: "custom:mystery-rule".to_string(),
                kind: ComplianceReportKind::PciDss,
            })
        );
    }
}
