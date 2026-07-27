//! llvm-cov JSON export coverage-report parsing (inbound adapter): the
//! output of `llvm-cov export -format=text`. Line/branch aggregates come
//! from each file's `summary.lines`/`summary.branches` (branches are absent
//! from some llvm-cov versions/targets, hence `Option`). Per-file line
//! detail (coverage-on-new-code) comes from `segments`: each is
//! `[line, col, count, hasCount, isRegionEntry, isGapRegion]` per the
//! llvm-cov export schema; a line's hit count is the max `count` over its
//! segments that carry one (`hasCount`), which is enough to tell whether any
//! part of the line executed.

use serde::Deserialize;
use serde_json::Value;
use yunq_rules_engine::{CoverageReport, CoverageSummary, FileCoverage};

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
    filename: Option<String>,
    summary: LlvmCovSummary,
    #[serde(default)]
    segments: Vec<Vec<Value>>,
}

#[derive(Deserialize)]
struct LlvmCovSummary {
    lines: LlvmCovLines,
    branches: Option<LlvmCovLines>,
}

#[derive(Deserialize)]
struct LlvmCovLines {
    count: usize,
    covered: usize,
}

pub fn parse_llvm_cov(content: &str) -> Result<CoverageSummary, LlvmCovError> {
    parse_llvm_cov_report(content)?
        .summary()
        .map_err(|e| LlvmCovError::Malformed(e.to_string()))
}

/// `(line, count)` for one llvm-cov segment
/// (`[line, col, count, hasCount, isRegionEntry, isGapRegion]`), if it
/// carries a count at all (`hasCount`).
fn segment_hit(segment: &[Value]) -> Option<(u32, usize)> {
    let has_count = segment.get(3).and_then(Value::as_bool).unwrap_or(false);
    if !has_count {
        return None;
    }
    let line = segment.first().and_then(Value::as_u64)?;
    let count = segment.get(2).and_then(Value::as_u64)?;
    Some((line as u32, count as usize))
}

fn file_coverage_detail(file: &LlvmCovFile) -> FileCoverage {
    let mut coverage = FileCoverage::new(file.filename.clone().unwrap_or_default());
    for segment in &file.segments {
        if let Some((line, count)) = segment_hit(segment) {
            coverage.record_line(line, count);
        }
    }
    coverage
}

/// Like [`parse_llvm_cov`], but also returns per-file line-hit detail for
/// coverage-on-new-code.
pub fn parse_llvm_cov_report(content: &str) -> Result<CoverageReport, LlvmCovError> {
    let export: LlvmCovExport =
        serde_json::from_str(content).map_err(|e| LlvmCovError::Malformed(e.to_string()))?;

    let mut total_covered_lines = 0usize;
    let mut total_lines = 0usize;
    let mut total_covered_branches = 0usize;
    let mut total_branches = 0usize;
    let mut files = Vec::new();
    let mut records = 0usize;

    for file in export.data.into_iter().flat_map(|data| data.files) {
        let covered = file.summary.lines.covered;
        let total = file.summary.lines.count;
        if total == 0 {
            continue;
        }
        total_covered_lines += covered;
        total_lines += total;
        if let Some(branches) = &file.summary.branches {
            total_covered_branches += branches.covered;
            total_branches += branches.count;
        }
        records += 1;
        files.push(file_coverage_detail(&file));
    }

    if records == 0 {
        Err(LlvmCovError::Empty)
    } else {
        Ok(CoverageReport::new(
            files,
            total_covered_lines,
            total_lines,
            total_covered_branches,
            total_branches,
        ))
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

    #[test]
    fn parses_branch_summary_when_present() {
        let json = r#"{
            "data": [
                {
                    "files": [
                        {
                            "filename": "src/lib.rs",
                            "summary": {
                                "lines": { "count": 10, "covered": 8 },
                                "branches": { "count": 4, "covered": 3 }
                            }
                        }
                    ]
                }
            ]
        }"#;
        let summary = parse_llvm_cov(json).unwrap();
        assert_eq!(summary.covered_branches(), 3);
        assert_eq!(summary.coverable_branches(), 4);
    }

    #[test]
    fn no_branch_data_leaves_branch_percent_none() {
        let json = r#"{"data":[{"files":[{"filename":"a.rs","summary":{"lines":{"count":1,"covered":1}}}]}]}"#;
        let summary = parse_llvm_cov(json).unwrap();
        assert_eq!(summary.percent_branches(), None);
    }

    #[test]
    fn empty_input_is_an_error() {
        assert!(matches!(
            parse_llvm_cov(r#"{"data":[]}"#),
            Err(LlvmCovError::Empty)
        ));
    }

    #[test]
    fn report_exposes_per_file_line_detail_for_new_code() {
        let json = r#"{
            "data": [
                {
                    "files": [
                        {
                            "filename": "src/lib.rs",
                            "summary": { "lines": { "count": 2, "covered": 1 } },
                            "segments": [
                                [1, 1, 5, true, true, false],
                                [2, 1, 0, true, true, false],
                                [3, 1, 0, false, false, false]
                            ]
                        }
                    ]
                }
            ]
        }"#;
        let report = parse_llvm_cov_report(json).unwrap();
        let files = report.files();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].path(), "src/lib.rs");
        assert_eq!(files[0].lines().get(&1), Some(&5));
        assert_eq!(files[0].lines().get(&2), Some(&0));
        // The 3rd segment has hasCount = false, so line 3 is not recorded.
        assert_eq!(files[0].lines().get(&3), None);
    }
}
