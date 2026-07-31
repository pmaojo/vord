//! JaCoCo XML coverage-report parsing (inbound adapter). Line coverage uses
//! JaCoCo's aggregate `<counter type="LINE" missed="M" covered="C"/>` tags
//! (summed across every nesting level found, matching this adapter's
//! existing convention); branch coverage does the same with
//! `type="BRANCH"`. JaCoCo has no simple per-line branch hit/miss, but it
//! does emit per-line instruction/branch counts via
//! `<line nr="N" mi=".." ci=".." mb=".." cb=".."/>` (mi/ci = missed/covered
//! instructions, mb/cb = missed/covered branches) inside each
//! `<sourcefile name="...">` — used here for per-file line detail
//! (coverage-on-new-code): a line counts as covered when it has at least one
//! covered instruction (`ci > 0`).

use std::collections::BTreeMap;

use yunq_rules_engine::{CoverageReport, CoverageSummary, FileCoverage};

#[derive(Debug, thiserror::Error)]
pub enum JacocoError {
    #[error("no line counters found in JaCoCo XML input")]
    Empty,
    #[error("malformed JaCoCo line: {0}")]
    Malformed(String),
}

pub fn parse_jacoco(content: &str) -> Result<CoverageSummary, JacocoError> {
    parse_jacoco_report(content)?
        .summary()
        .map_err(|e| JacocoError::Malformed(e.to_string()))
}

fn missed_and_covered(trimmed: &str) -> (usize, usize) {
    let missed = extract_attr(trimmed, "missed")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(0);
    let covered = extract_attr(trimmed, "covered")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(0);
    (missed, covered)
}

/// State accumulated while scanning the XML line-by-line: the finished
/// per-file records, the current `<sourcefile>`'s in-progress line map,
/// the running LINE/BRANCH counter totals, and whether any LINE counter
/// has been seen at all (an empty report is an error).
#[derive(Default)]
struct Accumulator {
    files: Vec<FileCoverage>,
    current_file: Option<String>,
    current_lines: BTreeMap<u32, usize>,
    total_covered_lines: usize,
    total_missed_lines: usize,
    total_covered_branches: usize,
    total_missed_branches: usize,
    found: bool,
}

impl Accumulator {
    fn flush_file(&mut self) {
        if let Some(name) = self.current_file.take() {
            let mut file = FileCoverage::new(name);
            for (&line, &hits) in self.current_lines.iter() {
                file.record_line(line, hits);
            }
            self.files.push(file);
        }
        self.current_lines.clear();
    }

    fn open_sourcefile(&mut self, trimmed: &str) {
        self.flush_file();
        self.current_file = extract_attr(trimmed, "name").map(|s| s.to_string());
    }

    fn line_counter(&mut self, trimmed: &str) {
        let (missed, covered) = missed_and_covered(trimmed);
        self.total_missed_lines += missed;
        self.total_covered_lines += covered;
        self.found = true;
    }

    fn branch_counter(&mut self, trimmed: &str) {
        let (missed, covered) = missed_and_covered(trimmed);
        self.total_missed_branches += missed;
        self.total_covered_branches += covered;
    }

    fn line_detail(&mut self, trimmed: &str) {
        if self.current_file.is_none() {
            return;
        }
        let Some(nr) = extract_attr(trimmed, "nr").and_then(|s| s.parse::<u32>().ok()) else {
            return;
        };
        let ci = extract_attr(trimmed, "ci")
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(0);
        self.current_lines.insert(nr, ci);
    }

    /// Dispatches one trimmed source line by its tag/attribute shape.
    fn handle_line(&mut self, trimmed: &str) {
        if trimmed.contains("<sourcefile ") || trimmed.starts_with("<sourcefile") {
            self.open_sourcefile(trimmed);
        } else if trimmed.starts_with("</sourcefile>") {
            self.flush_file();
        } else if trimmed.contains("type=\"LINE\"") || trimmed.contains("type='LINE'") {
            self.line_counter(trimmed);
        } else if trimmed.contains("type=\"BRANCH\"") || trimmed.contains("type='BRANCH'") {
            self.branch_counter(trimmed);
        } else if trimmed.contains("<line ") || trimmed.starts_with("<line") {
            self.line_detail(trimmed);
        }
    }

    fn into_report(mut self) -> Result<CoverageReport, JacocoError> {
        self.flush_file();
        if !self.found {
            return Err(JacocoError::Empty);
        }
        let total_lines = self.total_covered_lines + self.total_missed_lines;
        let total_branches = self.total_covered_branches + self.total_missed_branches;
        Ok(CoverageReport::new(
            self.files,
            self.total_covered_lines,
            total_lines,
            self.total_covered_branches,
            total_branches,
        ))
    }
}

/// Like [`parse_jacoco`], but also returns per-file line-hit detail for
/// coverage-on-new-code.
pub fn parse_jacoco_report(content: &str) -> Result<CoverageReport, JacocoError> {
    let mut acc = Accumulator::default();
    for raw in content.lines() {
        acc.handle_line(raw.trim());
    }
    acc.into_report()
}

fn extract_attr<'a>(line: &'a str, attr: &str) -> Option<&'a str> {
    let key1 = format!("{attr}=\"");
    if let Some(start_idx) = line.find(&key1) {
        let start = start_idx + key1.len();
        let end = line[start..].find('"')? + start;
        return Some(&line[start..end]);
    }
    let key2 = format!("{attr}='");
    if let Some(start_idx) = line.find(&key2) {
        let start = start_idx + key2.len();
        let end = line[start..].find('\'')? + start;
        return Some(&line[start..end]);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_jacoco_counter_tags() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<report name="yunq">
  <package name="com/example">
    <class name="com/example/Service">
      <counter type="INSTRUCTION" missed="20" covered="80"/>
      <counter type="LINE" missed="5" covered="15"/>
    </class>
  </package>
  <counter type="LINE" missed="10" covered="40"/>
</report>"#;
        let summary = parse_jacoco(xml).unwrap();
        assert_eq!(summary.covered_lines(), 55);
        assert_eq!(summary.coverable_lines(), 70);
    }

    #[test]
    fn parses_branch_counter_tags() {
        let xml = r#"<report name="yunq">
  <package name="com/example">
    <class name="com/example/Service">
      <counter type="LINE" missed="5" covered="15"/>
      <counter type="BRANCH" missed="1" covered="3"/>
    </class>
  </package>
</report>"#;
        let summary = parse_jacoco(xml).unwrap();
        assert_eq!(summary.covered_branches(), 3);
        assert_eq!(summary.coverable_branches(), 4);
    }

    #[test]
    fn no_branch_data_leaves_branch_percent_none() {
        let xml = r#"<report name="yunq">
  <counter type="LINE" missed="0" covered="10"/>
</report>"#;
        let summary = parse_jacoco(xml).unwrap();
        assert_eq!(summary.percent_branches(), None);
    }

    #[test]
    fn empty_input_is_an_error() {
        assert!(matches!(
            parse_jacoco("<report></report>"),
            Err(JacocoError::Empty)
        ));
    }

    #[test]
    fn report_exposes_per_file_line_detail_for_new_code() {
        let xml = r#"<report name="yunq">
  <package name="com/example">
    <sourcefile name="Service.java">
      <line nr="1" mi="0" ci="2" mb="0" cb="0"/>
      <line nr="2" mi="1" ci="0" mb="0" cb="0"/>
    </sourcefile>
    <sourcefile name="Other.java">
      <line nr="10" mi="0" ci="1" mb="1" cb="1"/>
    </sourcefile>
    <counter type="LINE" missed="1" covered="3"/>
  </package>
</report>"#;
        let report = parse_jacoco_report(xml).unwrap();
        let files = report.files();
        assert_eq!(files.len(), 2);
        assert_eq!(files[0].path(), "Service.java");
        assert_eq!(files[0].lines().get(&1), Some(&2));
        assert_eq!(files[0].lines().get(&2), Some(&0));
        assert_eq!(files[1].path(), "Other.java");
        assert_eq!(files[1].lines().get(&10), Some(&1));
    }
}
