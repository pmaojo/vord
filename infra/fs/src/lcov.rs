//! LCOV coverage-report parsing (inbound adapter). Line coverage: per
//! record, `LH:`/`LF:` totals are preferred and `DA:<line>,<hits>` entries
//! are the fallback. Branch coverage: `BRH:`/`BRF:` totals are preferred,
//! `BRDA:<line>,<block>,<branch>,<taken>` entries (`taken` is a hit count or
//! `-` for "never reached") are the fallback. `DA` entries are always kept
//! as per-file line detail (for coverage-on-new-code) regardless of which
//! totals win the aggregate.

use std::collections::BTreeMap;

use yunq_rules_engine::{CoverageReport, CoverageSummary, FileCoverage};

#[derive(Debug, thiserror::Error)]
pub enum LcovError {
    #[error("no coverage records found in LCOV input")]
    Empty,
    #[error("malformed LCOV line {line}: {content:?}")]
    Malformed { line: usize, content: String },
    #[error("inconsistent LCOV totals: {0}")]
    Inconsistent(String),
}

pub fn parse_lcov(content: &str) -> Result<CoverageSummary, LcovError> {
    parse_lcov_report(content)?.summary().map_err(|e| LcovError::Inconsistent(e.to_string()))
}

/// Like [`parse_lcov`], but also returns per-file line-hit detail for
/// coverage-on-new-code.
pub fn parse_lcov_report(content: &str) -> Result<CoverageReport, LcovError> {
    let mut files = Vec::new();
    let mut total_covered_lines = 0usize;
    let mut total_coverable_lines = 0usize;
    let mut total_covered_branches = 0usize;
    let mut total_coverable_branches = 0usize;
    let mut records = 0usize;

    // Per-record state.
    let mut source_file: Option<String> = None;
    let mut da_lines: BTreeMap<u32, usize> = BTreeMap::new();
    let mut da_covered = 0usize;
    let mut da_total = 0usize;
    let mut lh: Option<usize> = None;
    let mut lf: Option<usize> = None;
    let mut brda_covered = 0usize;
    let mut brda_total = 0usize;
    let mut brh: Option<usize> = None;
    let mut brf: Option<usize> = None;

    let parse_count = |value: &str, line: usize, content: &str| {
        value
            .trim()
            .parse::<usize>()
            .map_err(|_| LcovError::Malformed { line, content: content.to_string() })
    };

    for (index, raw) in content.lines().enumerate() {
        let line = raw.trim();
        if let Some(rest) = line.strip_prefix("SF:") {
            source_file = Some(rest.trim().to_string());
        } else if let Some(rest) = line.strip_prefix("DA:") {
            let mut parts = rest.splitn(2, ',');
            let (line_no, hits) = (
                parts.next().ok_or_else(|| LcovError::Malformed {
                    line: index + 1,
                    content: raw.to_string(),
                })?,
                parts.next().ok_or_else(|| LcovError::Malformed {
                    line: index + 1,
                    content: raw.to_string(),
                })?,
            );
            let line_no = parse_count(line_no, index + 1, raw)? as u32;
            // Hits may carry a checksum suffix (`,<checksum>`) — already split off.
            let hits = parse_count(hits.split(',').next().unwrap_or(hits), index + 1, raw)?;
            da_lines.insert(line_no, hits);
            da_total += 1;
            if hits > 0 {
                da_covered += 1;
            }
        } else if let Some(rest) = line.strip_prefix("BRDA:") {
            let parts: Vec<&str> = rest.splitn(4, ',').collect();
            let taken = parts.get(3).ok_or_else(|| LcovError::Malformed {
                line: index + 1,
                content: raw.to_string(),
            })?;
            brda_total += 1;
            if taken.trim().parse::<usize>().is_ok_and(|hits| hits > 0) {
                brda_covered += 1;
            }
        } else if let Some(rest) = line.strip_prefix("LH:") {
            lh = Some(parse_count(rest, index + 1, raw)?);
        } else if let Some(rest) = line.strip_prefix("LF:") {
            lf = Some(parse_count(rest, index + 1, raw)?);
        } else if let Some(rest) = line.strip_prefix("BRH:") {
            brh = Some(parse_count(rest, index + 1, raw)?);
        } else if let Some(rest) = line.strip_prefix("BRF:") {
            brf = Some(parse_count(rest, index + 1, raw)?);
        } else if line == "end_of_record" {
            let (line_covered, line_total) = match (lh, lf) {
                (Some(h), Some(f)) => (h, f),
                _ => (da_covered, da_total),
            };
            let (branch_covered, branch_total) = match (brh, brf) {
                (Some(h), Some(f)) => (h, f),
                _ => (brda_covered, brda_total),
            };
            total_covered_lines += line_covered;
            total_coverable_lines += line_total;
            total_covered_branches += branch_covered;
            total_coverable_branches += branch_total;

            let mut file = FileCoverage::new(source_file.clone().unwrap_or_default());
            for (&line_no, &hits) in &da_lines {
                file.record_line(line_no, hits);
            }
            files.push(file);
            records += 1;
            (source_file, da_lines, da_covered, da_total, lh, lf, brda_covered, brda_total, brh, brf) =
                (None, BTreeMap::new(), 0, 0, None, None, 0, 0, None, None);
        }
    }

    if records == 0 {
        Err(LcovError::Empty)
    } else {
        Ok(CoverageReport::new(
            files,
            total_covered_lines,
            total_coverable_lines,
            total_covered_branches,
            total_coverable_branches,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_da_records_and_prefers_lh_lf() {
        let lcov = "\
TN:
SF:src/a.ts
DA:1,5
DA:2,0
DA:3,1
end_of_record
SF:src/b.ts
DA:1,0
LH:7
LF:10
end_of_record
";
        let summary = parse_lcov(lcov).unwrap();
        // a.ts: 2/3 via DA; b.ts: 7/10 via LH/LF (preferred over DA).
        assert_eq!(summary.covered_lines(), 9);
        assert_eq!(summary.coverable_lines(), 13);
        let percent = summary.percent().unwrap();
        assert!((percent - 69.23).abs() < 0.01);
    }

    #[test]
    fn empty_input_is_an_error() {
        assert!(matches!(parse_lcov("TN:\n"), Err(LcovError::Empty)));
    }

    #[test]
    fn malformed_da_is_an_error() {
        let lcov = "SF:a\nDA:notanumber\nend_of_record\n";
        assert!(matches!(parse_lcov(lcov), Err(LcovError::Malformed { .. })));
    }

    #[test]
    fn parses_branch_coverage_from_brda() {
        let lcov = "\
SF:src/a.ts
DA:1,1
BRDA:1,0,0,1
BRDA:1,0,1,0
BRDA:1,0,2,-
end_of_record
";
        let summary = parse_lcov(lcov).unwrap();
        assert_eq!(summary.covered_branches(), 1);
        assert_eq!(summary.coverable_branches(), 3);
        let percent = summary.percent_branches().unwrap();
        assert!((percent - 33.33).abs() < 0.01);
    }

    #[test]
    fn parses_branch_coverage_preferring_brh_brf() {
        let lcov = "\
SF:src/a.ts
DA:1,1
BRDA:1,0,0,1
BRH:5
BRF:8
end_of_record
";
        let summary = parse_lcov(lcov).unwrap();
        assert_eq!(summary.covered_branches(), 5);
        assert_eq!(summary.coverable_branches(), 8);
    }

    #[test]
    fn no_branch_data_leaves_branch_percent_none() {
        let lcov = "SF:src/a.ts\nDA:1,1\nend_of_record\n";
        let summary = parse_lcov(lcov).unwrap();
        assert_eq!(summary.percent_branches(), None);
    }

    #[test]
    fn report_exposes_per_file_line_detail_for_new_code() {
        let lcov = "\
SF:src/a.ts
DA:1,5
DA:2,0
DA:3,1
end_of_record
SF:src/b.ts
DA:10,0
end_of_record
";
        let report = parse_lcov_report(lcov).unwrap();
        let files = report.files();
        assert_eq!(files.len(), 2);
        assert_eq!(files[0].path(), "src/a.ts");
        assert_eq!(files[0].lines().get(&2), Some(&0));
        assert_eq!(files[1].path(), "src/b.ts");
        assert_eq!(files[1].lines().get(&10), Some(&0));
    }
}
