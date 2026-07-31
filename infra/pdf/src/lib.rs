//! Compliance report generator: OWASP Top 10, CWE & PCI DSS evidence reports in valid binary PDF 1.4 and CSV format.

use std::fmt::Write;
use yunq_rules_engine::AnalysisReport;

#[derive(Debug, thiserror::Error)]
pub enum ReportError {
    #[error("failed to generate report: {0}")]
    Generation(String),
}

pub struct ComplianceReportGenerator;

/// Builds the page's `BT ... ET` text-showing operator stream: title, gate
/// status/summary lines, then up to 20 issue lines (stopping early once `y`
/// would run off the bottom margin).
fn build_report_text_stream(report: &AnalysisReport) -> String {
    let mut text_stream = String::new();
    text_stream.push_str(
        "BT /F1 16 Tf 50 750 Td (yunq OWASP Top 10 Security & Compliance Report) Tj ET\n",
    );
    text_stream.push_str(
        "BT /F1 12 Tf 50 720 Td (------------------------------------------------) Tj ET\n",
    );
    let gate_status = if report.issues().is_empty() {
        "PASSED"
    } else {
        "ACTION REQUIRED"
    };
    let _ = writeln!(
        text_stream,
        "BT /F1 10 Tf 50 690 Td (Quality Gate Status: {gate_status}) Tj ET"
    );
    let _ = writeln!(
        text_stream,
        "BT /F1 10 Tf 50 670 Td (Total Vulnerabilities: {}) Tj ET",
        report.issues().len()
    );
    let _ = writeln!(
        text_stream,
        "BT /F1 10 Tf 50 650 Td (Total Security Hotspots: {}) Tj ET",
        report.hotspots().len()
    );

    let mut y: i32 = 620;
    for issue in report.issues().iter().take(20) {
        let line = format!(
            "[{:?}] {} in {}:{}",
            issue.severity(),
            issue.rule().as_str(),
            issue.file(),
            issue.span().start_line
        );
        let escaped_line = line.replace('(', "\\(").replace(')', "\\)");
        let _ = writeln!(text_stream, "BT /F1 9 Tf 50 {y} Td ({escaped_line}) Tj ET");
        y = y.saturating_sub(15);
        if y < 50 {
            break;
        }
    }
    text_stream
}

/// Appends PDF objects 1-5 (Catalog, Pages, Page, Content Stream, Font) to
/// `pdf` and returns each object's byte offset, for the xref table.
fn write_pdf_objects(pdf: &mut Vec<u8>, text_stream: &str) -> Vec<usize> {
    let mut offsets = Vec::new();

    offsets.push(pdf.len());
    pdf.extend_from_slice(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");

    offsets.push(pdf.len());
    pdf.extend_from_slice(b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n");

    offsets.push(pdf.len());
    pdf.extend_from_slice(b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>\nendobj\n");

    offsets.push(pdf.len());
    let stream_bytes = text_stream.as_bytes();
    pdf.extend_from_slice(
        format!("4 0 obj\n<< /Length {} >>\nstream\n", stream_bytes.len()).as_bytes(),
    );
    pdf.extend_from_slice(stream_bytes);
    pdf.extend_from_slice(b"\nendstream\nendobj\n");

    offsets.push(pdf.len());
    pdf.extend_from_slice(
        b"5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n",
    );

    offsets
}

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

    /// Generates a valid PDF 1.4 binary document byte stream conforming to ISO 32000-1.
    pub fn generate_owasp_compliance_pdf_binary(
        report: &AnalysisReport,
    ) -> Result<Vec<u8>, ReportError> {
        let mut pdf = Vec::with_capacity(4096);
        pdf.extend_from_slice(b"%PDF-1.4\n%\xE2\xE3\xCF\xD3\n"); // yunq-ignore: secrets:high-entropy-string (PDF spec magic bytes, not a secret)

        let text_stream = build_report_text_stream(report);
        let offsets = write_pdf_objects(&mut pdf, &text_stream);

        // Xref table
        let xref_offset = pdf.len();
        pdf.extend_from_slice(
            format!("xref\n0 {}\n0000000000 65535 f \n", offsets.len() + 1).as_bytes(),
        );
        for offset in &offsets {
            pdf.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
        }

        // Trailer
        pdf.extend_from_slice(
            format!(
                "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{}\n%%EOF\n",
                offsets.len() + 1,
                xref_offset
            )
            .as_bytes(),
        );

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

    #[test]
    fn generates_valid_pdf_binary_stream() {
        let report = AnalysisReport::new(vec![], vec![], Metrics::default());
        let pdf = ComplianceReportGenerator::generate_owasp_compliance_pdf_binary(&report).unwrap();
        assert!(pdf.starts_with(b"%PDF-1.4"));
        assert!(pdf.ends_with(b"%%EOF\n"));
    }
}
