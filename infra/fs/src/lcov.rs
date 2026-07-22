//! LCOV coverage-report parsing (inbound adapter). Only the line-coverage
//! records matter here: per record, `LH:`/`LF:` totals are preferred and
//! `DA:<line>,<hits>` entries are the fallback.

use yunq_rules_engine::CoverageSummary;

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
    let mut summary = CoverageSummary::default();
    let mut records = 0usize;

    // Per-record state.
    let mut da_covered = 0usize;
    let mut da_total = 0usize;
    let mut lh: Option<usize> = None;
    let mut lf: Option<usize> = None;

    let parse_count = |value: &str, line: usize, content: &str| {
        value
            .trim()
            .parse::<usize>()
            .map_err(|_| LcovError::Malformed { line, content: content.to_string() })
    };

    for (index, raw) in content.lines().enumerate() {
        let line = raw.trim();
        if let Some(rest) = line.strip_prefix("DA:") {
            let mut parts = rest.splitn(2, ',');
            let (_, hits) = (
                parts.next().ok_or_else(|| LcovError::Malformed {
                    line: index + 1,
                    content: raw.to_string(),
                })?,
                parts.next().ok_or_else(|| LcovError::Malformed {
                    line: index + 1,
                    content: raw.to_string(),
                })?,
            );
            // Hits may carry a checksum suffix (`,<checksum>`) — already split off.
            let hits = parse_count(hits.split(',').next().unwrap_or(hits), index + 1, raw)?;
            da_total += 1;
            if hits > 0 {
                da_covered += 1;
            }
        } else if let Some(rest) = line.strip_prefix("LH:") {
            lh = Some(parse_count(rest, index + 1, raw)?);
        } else if let Some(rest) = line.strip_prefix("LF:") {
            lf = Some(parse_count(rest, index + 1, raw)?);
        } else if line == "end_of_record" {
            let (covered, total) = match (lh, lf) {
                (Some(h), Some(f)) => (h, f),
                _ => (da_covered, da_total),
            };
            summary.add(covered, total).map_err(|e| LcovError::Inconsistent(e.to_string()))?;
            records += 1;
            (da_covered, da_total, lh, lf) = (0, 0, None, None);
        }
    }

    if records == 0 { Err(LcovError::Empty) } else { Ok(summary) }
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
}
