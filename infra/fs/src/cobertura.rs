//! Cobertura XML coverage-report parsing (inbound adapter). A lightweight
//! line-oriented scan (no full XML parser) matches the existing convention
//! for this crate's other coverage adapters. Root `lines-covered`/
//! `lines-valid` (and, where present, `branches-covered`/`branches-valid`)
//! attributes are preferred over a recount from `<line>` elements; per-line
//! `<line number="N" hits="H" .../>` entries always feed the per-file detail
//! used for coverage-on-new-code.

use std::collections::BTreeMap;

use yunq_rules_engine::{CoverageReport, CoverageSummary, FileCoverage};

#[derive(Debug, thiserror::Error)]
pub enum CoberturaError {
    #[error("empty or invalid Cobertura XML input")]
    Empty,
    #[error("malformed Cobertura line: {0}")]
    Malformed(String),
}

pub fn parse_cobertura(content: &str) -> Result<CoverageSummary, CoberturaError> {
    parse_cobertura_report(content)?
        .summary()
        .map_err(|e| CoberturaError::Malformed(e.to_string()))
}

/// State accumulated while scanning the XML line-by-line: the finished
/// per-file records, the current `<class>`'s in-progress line map, the
/// recounted totals (used when the root `<coverage>` tag omits its own),
/// and the root totals when present (preferred over the recount).
#[derive(Default)]
struct Accumulator {
    files: Vec<FileCoverage>,
    current_file: Option<String>,
    current_lines: BTreeMap<u32, usize>,
    counted_lines_covered: usize,
    counted_lines_total: usize,
    counted_branches_covered: usize,
    counted_branches_total: usize,
    root_lines: Option<(usize, usize)>,
    root_branches: Option<(usize, usize)>,
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

    fn handle_class_tag(&mut self, trimmed: &str) {
        self.flush_file();
        self.current_file = extract_attr(trimmed, "filename").map(|s| s.to_string());
    }

    fn handle_line_tag(&mut self, trimmed: &str) {
        let (Some(hits_str), Some(num_str)) = (
            extract_attr(trimmed, "hits"),
            extract_attr(trimmed, "number"),
        ) else {
            return;
        };
        let hits: usize = hits_str.parse().unwrap_or(0);
        let number: u32 = num_str.parse().unwrap_or(0);
        self.counted_lines_total += 1;
        if hits > 0 {
            self.counted_lines_covered += 1;
        }
        self.current_lines.insert(number, hits);

        if extract_attr(trimmed, "branch") == Some("true")
            && let Some(coverage) = extract_attr(trimmed, "condition-coverage")
            && let Some((covered, total)) = parse_condition_coverage(coverage)
        {
            self.counted_branches_covered += covered;
            self.counted_branches_total += total;
        }
    }

    fn handle_coverage_tag(&mut self, trimmed: &str) {
        if let (Some(c_str), Some(v_str)) = (
            extract_attr(trimmed, "lines-covered"),
            extract_attr(trimmed, "lines-valid"),
        ) && let (Ok(c), Ok(v)) = (c_str.parse::<usize>(), v_str.parse::<usize>())
        {
            self.root_lines = Some((c, v));
        }
        if let (Some(c_str), Some(v_str)) = (
            extract_attr(trimmed, "branches-covered"),
            extract_attr(trimmed, "branches-valid"),
        ) && let (Ok(c), Ok(v)) = (c_str.parse::<usize>(), v_str.parse::<usize>())
        {
            self.root_branches = Some((c, v));
        }
    }

    /// Dispatches one trimmed source line by its tag.
    fn handle_line(&mut self, trimmed: &str) {
        if trimmed.starts_with("<class ") || trimmed.starts_with("<class>") {
            self.handle_class_tag(trimmed);
        } else if trimmed.contains("<line ") || trimmed.starts_with("<line") {
            self.handle_line_tag(trimmed);
        } else if trimmed.contains("<coverage ") {
            self.handle_coverage_tag(trimmed);
        }
    }

    fn into_report(mut self) -> Result<CoverageReport, CoberturaError> {
        self.flush_file();
        if self.files.is_empty() && self.counted_lines_total == 0 && self.root_lines.is_none() {
            return Err(CoberturaError::Empty);
        }
        let (lines_covered, lines_total) = self
            .root_lines
            .unwrap_or((self.counted_lines_covered, self.counted_lines_total));
        let (branches_covered, branches_total) = self
            .root_branches
            .unwrap_or((self.counted_branches_covered, self.counted_branches_total));
        Ok(CoverageReport::new(
            self.files,
            lines_covered,
            lines_total,
            branches_covered,
            branches_total,
        ))
    }
}

/// Like [`parse_cobertura`], but also returns per-file line-hit detail for
/// coverage-on-new-code.
pub fn parse_cobertura_report(content: &str) -> Result<CoverageReport, CoberturaError> {
    let mut acc = Accumulator::default();
    for raw in content.lines() {
        acc.handle_line(raw.trim());
    }
    acc.into_report()
}

/// Parses Cobertura's `condition-coverage="50% (1/2)"` attribute into
/// `(covered, total)` — the parenthesized fraction, not the percentage.
fn parse_condition_coverage(value: &str) -> Option<(usize, usize)> {
    let start = value.find('(')? + 1;
    let end = value[start..].find(')')? + start;
    let fraction = &value[start..end];
    let (covered, total) = fraction.split_once('/')?;
    Some((covered.trim().parse().ok()?, total.trim().parse().ok()?))
}

fn extract_attr<'a>(line: &'a str, attr: &str) -> Option<&'a str> {
    let key = format!("{attr}=\"");
    let start = line.find(&key)? + key.len();
    let end = line[start..].find('"')? + start;
    Some(&line[start..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cobertura_line_tags() {
        let xml = r#"<?xml version="1.0"?>
<coverage line-rate="0.75">
  <packages>
    <package name="main">
      <classes>
        <class name="App" filename="App.java">
          <lines>
            <line number="1" hits="3"/>
            <line number="2" hits="0"/>
            <line number="3" hits="1"/>
            <line number="4" hits="0"/>
          </lines>
        </class>
      </classes>
    </package>
  </packages>
</coverage>"#;
        let summary = parse_cobertura(xml).unwrap();
        assert_eq!(summary.covered_lines(), 2);
        assert_eq!(summary.coverable_lines(), 4);
    }

    #[test]
    fn prefers_root_lines_covered_and_valid_when_present() {
        let xml = r#"<coverage line-rate="0.5" lines-covered="50" lines-valid="100">
  <packages>
    <package name="main">
      <classes>
        <class name="App" filename="App.java">
          <lines>
            <line number="1" hits="1"/>
          </lines>
        </class>
      </classes>
    </package>
  </packages>
</coverage>"#;
        let summary = parse_cobertura(xml).unwrap();
        assert_eq!(summary.covered_lines(), 50);
        assert_eq!(summary.coverable_lines(), 100);
    }

    #[test]
    fn parses_branch_coverage_from_condition_coverage() {
        let xml = r#"<coverage line-rate="1.0">
  <packages>
    <package name="main">
      <classes>
        <class name="App" filename="App.java">
          <lines>
            <line number="1" hits="1" branch="true" condition-coverage="50% (1/2)"/>
            <line number="2" hits="1" branch="true" condition-coverage="100% (2/2)"/>
            <line number="3" hits="1"/>
          </lines>
        </class>
      </classes>
    </package>
  </packages>
</coverage>"#;
        let summary = parse_cobertura(xml).unwrap();
        assert_eq!(summary.covered_branches(), 3);
        assert_eq!(summary.coverable_branches(), 4);
    }

    #[test]
    fn no_branch_data_leaves_branch_percent_none() {
        let xml = r#"<coverage line-rate="1.0">
  <packages><package name="main"><classes>
    <class name="App" filename="App.java">
      <lines><line number="1" hits="1"/></lines>
    </class>
  </classes></package></packages>
</coverage>"#;
        let summary = parse_cobertura(xml).unwrap();
        assert_eq!(summary.percent_branches(), None);
    }

    #[test]
    fn report_exposes_per_file_line_detail_for_new_code() {
        let xml = r#"<coverage line-rate="1.0">
  <packages><package name="main"><classes>
    <class name="App" filename="src/App.java">
      <lines>
        <line number="1" hits="1"/>
        <line number="2" hits="0"/>
      </lines>
    </class>
    <class name="Other" filename="src/Other.java">
      <lines>
        <line number="5" hits="2"/>
      </lines>
    </class>
  </classes></package></packages>
</coverage>"#;
        let report = parse_cobertura_report(xml).unwrap();
        let files = report.files();
        assert_eq!(files.len(), 2);
        assert_eq!(files[0].path(), "src/App.java");
        assert_eq!(files[0].lines().get(&2), Some(&0));
        assert_eq!(files[1].path(), "src/Other.java");
        assert_eq!(files[1].lines().get(&5), Some(&2));
    }

    #[test]
    fn empty_input_is_an_error() {
        assert!(matches!(
            parse_cobertura("<coverage></coverage>"),
            Err(CoberturaError::Empty)
        ));
    }
}
