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

fn parse_count(value: &str, line: usize, content: &str) -> Result<usize, LcovError> {
    value.trim().parse::<usize>().map_err(|_| LcovError::Malformed { line, content: content.to_string() })
}

/// State accumulated between `SF:` and `end_of_record` for one file's
/// record — one method per line prefix `parse_lcov_report`'s loop can
/// dispatch to, instead of a long inline `if`/`else if` chain.
#[derive(Default)]
struct RecordAccumulator {
    source_file: Option<String>,
    da_lines: BTreeMap<u32, usize>,
    da_covered: usize,
    da_total: usize,
    lh: Option<usize>,
    lf: Option<usize>,
    brda_covered: usize,
    brda_total: usize,
    brh: Option<usize>,
    brf: Option<usize>,
}

impl RecordAccumulator {
    fn handle_da(&mut self, rest: &str, index: usize, raw: &str) -> Result<(), LcovError> {
        let mut parts = rest.splitn(2, ',');
        let malformed = || LcovError::Malformed { line: index + 1, content: raw.to_string() };
        let (line_no, hits) = (parts.next().ok_or_else(malformed)?, parts.next().ok_or_else(malformed)?);
        let line_no = parse_count(line_no, index + 1, raw)? as u32;
        // Hits may carry a checksum suffix (`,<checksum>`) — already split off.
        let hits = parse_count(hits.split(',').next().unwrap_or(hits), index + 1, raw)?;
        self.da_lines.insert(line_no, hits);
        self.da_total += 1;
        if hits > 0 {
            self.da_covered += 1;
        }
        Ok(())
    }

    fn handle_brda(&mut self, rest: &str, index: usize, raw: &str) -> Result<(), LcovError> {
        let parts: Vec<&str> = rest.splitn(4, ',').collect();
        let taken = parts
            .get(3)
            .ok_or_else(|| LcovError::Malformed { line: index + 1, content: raw.to_string() })?;
        self.brda_total += 1;
        if taken.trim().parse::<usize>().is_ok_and(|hits| hits > 0) {
            self.brda_covered += 1;
        }
        Ok(())
    }

    /// `(covered, total)` lines for this record — the declared `LH`/`LF`
    /// totals when present, else the count derived from `DA:` entries.
    fn line_totals(&self) -> (usize, usize) {
        match (self.lh, self.lf) {
            (Some(h), Some(f)) => (h, f),
            _ => (self.da_covered, self.da_total),
        }
    }

    /// `(covered, total)` branches for this record — the declared
    /// `BRH`/`BRF` totals when present, else the count derived from
    /// `BRDA:` entries.
    fn branch_totals(&self) -> (usize, usize) {
        match (self.brh, self.brf) {
            (Some(h), Some(f)) => (h, f),
            _ => (self.brda_covered, self.brda_total),
        }
    }

    fn into_file(self) -> FileCoverage {
        let mut file = FileCoverage::new(self.source_file.unwrap_or_default());
        for (&line_no, &hits) in &self.da_lines {
            file.record_line(line_no, hits);
        }
        file
    }
}

/// Whole-report state: the finished per-file records and running totals,
/// plus the record currently being accumulated.
#[derive(Default)]
struct ReportAccumulator {
    files: Vec<FileCoverage>,
    total_covered_lines: usize,
    total_coverable_lines: usize,
    total_covered_branches: usize,
    total_coverable_branches: usize,
    records: usize,
    current: RecordAccumulator,
}

impl ReportAccumulator {
    /// Dispatches one trimmed source line by its LCOV prefix.
    fn handle_line(&mut self, line: &str, index: usize, raw: &str) -> Result<(), LcovError> {
        if let Some(rest) = line.strip_prefix("SF:") {
            self.current.source_file = Some(rest.trim().to_string());
        } else if let Some(rest) = line.strip_prefix("DA:") {
            self.current.handle_da(rest, index, raw)?;
        } else if let Some(rest) = line.strip_prefix("BRDA:") {
            self.current.handle_brda(rest, index, raw)?;
        } else if let Some(rest) = line.strip_prefix("LH:") {
            self.current.lh = Some(parse_count(rest, index + 1, raw)?);
        } else if let Some(rest) = line.strip_prefix("LF:") {
            self.current.lf = Some(parse_count(rest, index + 1, raw)?);
        } else if let Some(rest) = line.strip_prefix("BRH:") {
            self.current.brh = Some(parse_count(rest, index + 1, raw)?);
        } else if let Some(rest) = line.strip_prefix("BRF:") {
            self.current.brf = Some(parse_count(rest, index + 1, raw)?);
        } else if line == "end_of_record" {
            self.finish_record();
        }
        Ok(())
    }

    /// Folds the current record's totals into the running totals and
    /// starts a fresh record.
    fn finish_record(&mut self) {
        let (line_covered, line_total) = self.current.line_totals();
        let (branch_covered, branch_total) = self.current.branch_totals();
        self.total_covered_lines += line_covered;
        self.total_coverable_lines += line_total;
        self.total_covered_branches += branch_covered;
        self.total_coverable_branches += branch_total;

        self.files.push(std::mem::take(&mut self.current).into_file());
        self.records += 1;
    }

    fn into_report(self) -> Result<CoverageReport, LcovError> {
        if self.records == 0 {
            Err(LcovError::Empty)
        } else {
            Ok(CoverageReport::new(
                self.files,
                self.total_covered_lines,
                self.total_coverable_lines,
                self.total_covered_branches,
                self.total_coverable_branches,
            ))
        }
    }
}

/// Like [`parse_lcov`], but also returns per-file line-hit detail for
/// coverage-on-new-code.
pub fn parse_lcov_report(content: &str) -> Result<CoverageReport, LcovError> {
    let mut acc = ReportAccumulator::default();
    for (index, raw) in content.lines().enumerate() {
        acc.handle_line(raw.trim(), index, raw)?;
    }
    acc.into_report()
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
