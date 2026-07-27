//! Coverage-format auto-detection and a single generalized entry point that
//! dispatches to the right per-format parser. Lets callers (e.g. the CLI)
//! accept any of the five supported coverage-report formats through one
//! flag instead of needing one flag per format.

use yunq_rules_engine::CoverageReport;

use crate::cobertura::{self, CoberturaError};
use crate::istanbul::{self, IstanbulError};
use crate::jacoco::{self, JacocoError};
use crate::lcov::{self, LcovError};
use crate::llvm_cov::{self, LlvmCovError};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoverageFormat {
    Lcov,
    Cobertura,
    Jacoco,
    LlvmCov,
    Istanbul,
}

#[derive(Debug, thiserror::Error)]
pub enum CoverageParseError {
    #[error("could not detect the coverage report format from its content")]
    UnknownFormat,
    #[error(transparent)]
    Lcov(#[from] LcovError),
    #[error(transparent)]
    Cobertura(#[from] CoberturaError),
    #[error(transparent)]
    Jacoco(#[from] JacocoError),
    #[error(transparent)]
    LlvmCov(#[from] LlvmCovError),
    #[error(transparent)]
    Istanbul(#[from] IstanbulError),
}

/// Sniffs the coverage report format from its content (no reliance on file
/// extension, since e.g. Cobertura/JaCoCo are both plain XML and llvm-cov/
/// Istanbul are both plain JSON).
pub fn detect_coverage_format(content: &str) -> Option<CoverageFormat> {
    let trimmed = content.trim_start();

    // LCOV is the one plain-text (non-XML/JSON) format.
    if trimmed.starts_with("TN:")
        || trimmed.starts_with("SF:")
        || trimmed.starts_with("DA:")
        || content.contains("\nend_of_record")
    {
        return Some(CoverageFormat::Lcov);
    }

    if trimmed.starts_with('<') {
        // JaCoCo's root element is `<report ...>` (optionally preceded by a
        // `<!DOCTYPE report ...>`); Cobertura's is `<coverage ...>`.
        if trimmed.contains("<report") {
            return Some(CoverageFormat::Jacoco);
        }
        if trimmed.contains("<coverage") {
            return Some(CoverageFormat::Cobertura);
        }
        return None;
    }

    if trimmed.starts_with('{') {
        // llvm-cov export: `{"data":[{"files":[...]}], ...}`.
        if trimmed.contains("\"data\"") && trimmed.contains("\"files\"") {
            return Some(CoverageFormat::LlvmCov);
        }
        // Istanbul's `coverage-final.json`: a map of file path -> entry,
        // each entry carrying a `statementMap`.
        if trimmed.contains("\"statementMap\"") {
            return Some(CoverageFormat::Istanbul);
        }
        return None;
    }

    None
}

/// Parses `content` as the given format, or auto-detects it when `format`
/// is `None`.
pub fn parse_coverage_report(
    content: &str,
    format: Option<CoverageFormat>,
) -> Result<CoverageReport, CoverageParseError> {
    let format = match format {
        Some(format) => format,
        None => detect_coverage_format(content).ok_or(CoverageParseError::UnknownFormat)?,
    };
    Ok(match format {
        CoverageFormat::Lcov => lcov::parse_lcov_report(content)?,
        CoverageFormat::Cobertura => cobertura::parse_cobertura_report(content)?,
        CoverageFormat::Jacoco => jacoco::parse_jacoco_report(content)?,
        CoverageFormat::LlvmCov => llvm_cov::parse_llvm_cov_report(content)?,
        CoverageFormat::Istanbul => istanbul::parse_istanbul_report(content)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_lcov() {
        let content = "TN:\nSF:a.ts\nDA:1,1\nend_of_record\n";
        assert_eq!(detect_coverage_format(content), Some(CoverageFormat::Lcov));
    }

    #[test]
    fn detects_cobertura() {
        let content = r#"<?xml version="1.0"?><coverage line-rate="1.0"></coverage>"#;
        assert_eq!(
            detect_coverage_format(content),
            Some(CoverageFormat::Cobertura)
        );
    }

    #[test]
    fn detects_jacoco() {
        let content = r#"<?xml version="1.0"?><report name="x"></report>"#;
        assert_eq!(
            detect_coverage_format(content),
            Some(CoverageFormat::Jacoco)
        );
    }

    #[test]
    fn detects_llvm_cov() {
        let content = r#"{"data":[{"files":[]}]}"#;
        assert_eq!(
            detect_coverage_format(content),
            Some(CoverageFormat::LlvmCov)
        );
    }

    #[test]
    fn detects_istanbul() {
        let content = r#"{"/a.js":{"path":"/a.js","statementMap":{},"s":{}}}"#;
        assert_eq!(
            detect_coverage_format(content),
            Some(CoverageFormat::Istanbul)
        );
    }

    #[test]
    fn unknown_content_is_undetected() {
        assert_eq!(detect_coverage_format("not a coverage report"), None);
        assert_eq!(detect_coverage_format("{}"), None);
    }

    #[test]
    fn parse_coverage_report_auto_detects_and_dispatches() {
        let content = "SF:a.ts\nDA:1,1\nDA:2,0\nend_of_record\n";
        let report = parse_coverage_report(content, None).unwrap();
        let summary = report.summary().unwrap();
        assert_eq!(summary.covered_lines(), 1);
        assert_eq!(summary.coverable_lines(), 2);
    }

    #[test]
    fn parse_coverage_report_with_explicit_format_skips_detection() {
        let content = "SF:a.ts\nDA:1,1\nend_of_record\n";
        let report = parse_coverage_report(content, Some(CoverageFormat::Lcov)).unwrap();
        assert_eq!(report.summary().unwrap().covered_lines(), 1);
    }

    #[test]
    fn parse_coverage_report_errors_on_undetectable_content() {
        assert!(matches!(
            parse_coverage_report("garbage", None),
            Err(CoverageParseError::UnknownFormat)
        ));
    }
}
