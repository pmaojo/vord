//! Istanbul native JSON coverage-report parsing (inbound adapter):
//! `coverage-final.json`, keyed by file path, each entry carrying
//! `statementMap`/`s` (statement locations + hit counts, used here as the
//! line-coverage proxy — Istanbul does not track "lines" directly) and
//! `branchMap`/`b` (branch locations + one hit count per possible path).
//! A statement's line is covered when its hit count (`s[id]`) is > 0; a
//! branch location is covered when its hit count (`b[id][n]`) is > 0.

use std::collections::HashMap;

use serde::Deserialize;
use vord_rules_engine::{CoverageReport, CoverageSummary, FileCoverage};

#[derive(Debug, thiserror::Error)]
pub enum IstanbulError {
    #[error("no file entries found in Istanbul coverage JSON input")]
    Empty,
    #[error("malformed Istanbul JSON: {0}")]
    Malformed(String),
}

#[derive(Deserialize)]
struct IstanbulFile {
    path: Option<String>,
    #[serde(default, rename = "statementMap")]
    statement_map: HashMap<String, StatementLoc>,
    #[serde(default)]
    s: HashMap<String, usize>,
    #[serde(default)]
    b: HashMap<String, Vec<usize>>,
}

#[derive(Deserialize)]
struct StatementLoc {
    start: Loc,
}

#[derive(Deserialize)]
struct Loc {
    line: u32,
}

pub fn parse_istanbul(content: &str) -> Result<CoverageSummary, IstanbulError> {
    parse_istanbul_report(content)?
        .summary()
        .map_err(|e| IstanbulError::Malformed(e.to_string()))
}

/// Like [`parse_istanbul`], but also returns per-file line-hit detail for
/// coverage-on-new-code.
pub fn parse_istanbul_report(content: &str) -> Result<CoverageReport, IstanbulError> {
    let export: HashMap<String, IstanbulFile> =
        serde_json::from_str(content).map_err(|e| IstanbulError::Malformed(e.to_string()))?;

    if export.is_empty() {
        return Err(IstanbulError::Empty);
    }

    let mut files = Vec::new();
    let mut total_covered_lines = 0usize;
    let mut total_lines = 0usize;
    let mut total_covered_branches = 0usize;
    let mut total_branches = 0usize;

    for (key, entry) in export {
        let path = entry.path.unwrap_or(key);
        let mut coverage = FileCoverage::new(path);
        for (id, statement) in &entry.statement_map {
            let hits = entry.s.get(id).copied().unwrap_or(0);
            coverage.record_line(statement.start.line, hits);
        }
        total_covered_lines += coverage.covered_lines();
        total_lines += coverage.coverable_lines();

        for counts in entry.b.values() {
            total_branches += counts.len();
            total_covered_branches += counts.iter().filter(|&&c| c > 0).count();
        }

        files.push(coverage);
    }
    files.sort_by(|a, b| a.path().cmp(b.path()));

    Ok(CoverageReport::new(
        files,
        total_covered_lines,
        total_lines,
        total_covered_branches,
        total_branches,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_statement_hits_as_line_coverage() {
        let json = r#"{
            "/repo/src/a.js": {
                "path": "/repo/src/a.js",
                "statementMap": {
                    "0": {"start": {"line": 1, "column": 0}, "end": {"line": 1, "column": 10}},
                    "1": {"start": {"line": 2, "column": 0}, "end": {"line": 2, "column": 10}}
                },
                "s": {"0": 3, "1": 0},
                "branchMap": {},
                "b": {}
            }
        }"#;
        let summary = parse_istanbul(json).unwrap();
        assert_eq!(summary.covered_lines(), 1);
        assert_eq!(summary.coverable_lines(), 2);
    }

    #[test]
    fn parses_branch_hit_arrays() {
        let json = r#"{
            "/repo/src/a.js": {
                "path": "/repo/src/a.js",
                "statementMap": {
                    "0": {"start": {"line": 1, "column": 0}, "end": {"line": 1, "column": 10}}
                },
                "s": {"0": 1},
                "branchMap": {
                    "0": {"type": "if", "line": 1, "locations": [{}, {}]}
                },
                "b": {"0": [1, 0]}
            }
        }"#;
        let summary = parse_istanbul(json).unwrap();
        assert_eq!(summary.covered_branches(), 1);
        assert_eq!(summary.coverable_branches(), 2);
    }

    #[test]
    fn no_branch_data_leaves_branch_percent_none() {
        let json = r#"{
            "/repo/src/a.js": {
                "path": "/repo/src/a.js",
                "statementMap": {
                    "0": {"start": {"line": 1, "column": 0}, "end": {"line": 1, "column": 10}}
                },
                "s": {"0": 1}
            }
        }"#;
        let summary = parse_istanbul(json).unwrap();
        assert_eq!(summary.percent_branches(), None);
    }

    #[test]
    fn empty_input_is_an_error() {
        assert!(matches!(parse_istanbul("{}"), Err(IstanbulError::Empty)));
    }

    #[test]
    fn malformed_input_is_an_error() {
        assert!(matches!(
            parse_istanbul("not json"),
            Err(IstanbulError::Malformed(_))
        ));
    }

    #[test]
    fn report_exposes_per_file_line_detail_for_new_code() {
        let json = r#"{
            "/repo/src/a.js": {
                "path": "src/a.js",
                "statementMap": {
                    "0": {"start": {"line": 1, "column": 0}, "end": {"line": 1, "column": 10}},
                    "1": {"start": {"line": 5, "column": 0}, "end": {"line": 5, "column": 10}}
                },
                "s": {"0": 2, "1": 0}
            },
            "/repo/src/b.js": {
                "path": "src/b.js",
                "statementMap": {
                    "0": {"start": {"line": 20, "column": 0}, "end": {"line": 20, "column": 10}}
                },
                "s": {"0": 0}
            }
        }"#;
        let report = parse_istanbul_report(json).unwrap();
        let files = report.files();
        assert_eq!(files.len(), 2);
        assert_eq!(files[0].path(), "src/a.js");
        assert_eq!(files[0].lines().get(&1), Some(&2));
        assert_eq!(files[0].lines().get(&5), Some(&0));
        assert_eq!(files[1].path(), "src/b.js");
        assert_eq!(files[1].lines().get(&20), Some(&0));
    }
}
