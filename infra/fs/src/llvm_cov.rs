//! llvm-cov JSON export coverage-report parsing (inbound adapter).

use serde::Deserialize;
use yunq_rules_engine::CoverageSummary;

#[derive(Debug, thiserror::Error)]
pub enum LlvmCovError {
    #[error("no coverage data found in llvm-cov JSON input")]
    Empty,
    #[error("malformed llvm-cov JSON: {0}")]
    Malformed(String),
}

#[derive(Deserialize)]
struct LlvmCovExport {
    data: Vec<LlvmCovData>,
}

#[derive(Deserialize)]
struct LlvmCovData {
    files: Vec<LlvmCovFile>,
}

#[derive(Deserialize)]
struct LlvmCovFile {
    summary: LlvmCovSummary,
}

#[derive(Deserialize)]
struct LlvmCovSummary {
    lines: LlvmCovLines,
}

#[derive(Deserialize)]
struct LlvmCovLines {
    count: usize,
    covered: usize,
}

pub fn parse_llvm_cov(content: &str) -> Result<CoverageSummary, LlvmCovError> {
    let export: LlvmCovExport = serde_json::from_str(content)
        .map_err(|e| LlvmCovError::Malformed(e.to_string()))?;

    let mut summary = CoverageSummary::default();
    let mut records = 0usize;

    for data in export.data {
        for file in data.files {
            let covered = file.summary.lines.covered;
            let total = file.summary.lines.count;
            if total > 0 {
                summary.add(covered, total).map_err(|e| LlvmCovError::Malformed(e.to_string()))?;
                records += 1;
            }
        }
    }

    if records == 0 {
        Err(LlvmCovError::Empty)
    } else {
        Ok(summary)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_llvm_cov_json() {
        let json = r#"{
            "data": [
                {
                    "files": [
                        {
                            "filename": "src/lib.rs",
                            "summary": {
                                "lines": {
                                    "count": 10,
                                    "covered": 8
                                }
                            }
                        }
                    ]
                }
            ]
        }"#;
        let summary = parse_llvm_cov(json).unwrap();
        assert_eq!(summary.covered_lines(), 8);
        assert_eq!(summary.coverable_lines(), 10);
    }
}
