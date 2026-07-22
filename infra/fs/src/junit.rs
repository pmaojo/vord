//! JUnit XML test execution report parsing (inbound adapter).

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct TestReportSummary {
    pub total_tests: usize,
    pub passed_tests: usize,
    pub failed_tests: usize,
    pub skipped_tests: usize,
    pub errors: usize,
}

#[derive(Debug, thiserror::Error)]
pub enum JunitError {
    #[error("no testsuite elements found in JUnit XML input")]
    Empty,
    #[error("malformed JUnit XML line: {0}")]
    Malformed(String),
}

pub fn parse_junit(content: &str) -> Result<TestReportSummary, JunitError> {
    let mut summary = TestReportSummary::default();
    let mut found = false;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.contains("<testsuite ") || trimmed.starts_with("<testsuite ") {
            let tests = extract_attr(trimmed, "tests").and_then(|s| s.parse::<usize>().ok()).unwrap_or(0);
            let failures = extract_attr(trimmed, "failures").and_then(|s| s.parse::<usize>().ok()).unwrap_or(0);
            let errors = extract_attr(trimmed, "errors").and_then(|s| s.parse::<usize>().ok()).unwrap_or(0);
            let skipped = extract_attr(trimmed, "skipped").and_then(|s| s.parse::<usize>().ok()).unwrap_or(0);

            if tests > 0 {
                summary.total_tests += tests;
                summary.failed_tests += failures;
                summary.errors += errors;
                summary.skipped_tests += skipped;
                summary.passed_tests += tests.saturating_sub(failures + errors + skipped);
                found = true;
            }
        }
    }

    if !found {
        Err(JunitError::Empty)
    } else {
        Ok(summary)
    }
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
    fn parses_junit_testsuite_summary() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<testsuites>
  <testsuite name="unit-tests" tests="10" failures="2" errors="0" skipped="1">
    <testcase name="test1"/>
  </testsuite>
</testsuites>"#;
        let summary = parse_junit(xml).unwrap();
        assert_eq!(summary.total_tests, 10);
        assert_eq!(summary.passed_tests, 7);
        assert_eq!(summary.failed_tests, 2);
        assert_eq!(summary.skipped_tests, 1);
    }
}
