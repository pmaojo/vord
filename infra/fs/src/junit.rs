//! JUnit XML test execution report parsing (inbound adapter). Handles the
//! de-facto standard format shared by JUnit, pytest, Jest, cargo-nextest,
//! etc.: a root `<testsuites>` wrapping one or more `<testsuite>` elements,
//! or a single root `<testsuite>` with no wrapper — both are common in the
//! wild and handled identically here, since we look for `<testsuite>`
//! elements at any depth rather than requiring a specific wrapper.
//!
//! Per `<testsuite>`, the `tests`/`failures`/`errors`/`skipped`/`time`
//! attributes declared on the tag are authoritative (per the de-facto
//! schema) and are preferred when present; when a suite omits some of them,
//! the gap is filled by counting `<testcase>` children and their
//! `<failure>`/`<error>`/`<skipped>` outcome elements instead.

use quick_xml::Reader;
use quick_xml::events::{BytesEnd, BytesStart, Event};
use yunq_rules_engine::{TestReportSummary, TestSuiteSummary};

#[derive(Debug, thiserror::Error)]
pub enum JunitError {
    #[error("empty or invalid JUnit XML input")]
    Empty,
    #[error("malformed JUnit XML: {0}")]
    Malformed(String),
}

#[derive(Clone, Copy, PartialEq, Eq, Default)]
enum Outcome {
    #[default]
    Passed,
    Failed,
    Errored,
    Skipped,
}

/// Running totals for the `<testsuite>` currently being parsed.
#[derive(Default)]
struct SuiteAccumulator {
    name: Option<String>,
    declared_tests: Option<usize>,
    declared_failures: Option<usize>,
    declared_errors: Option<usize>,
    declared_skipped: Option<usize>,
    declared_time: Option<f64>,
    seen_tests: usize,
    seen_failures: usize,
    seen_errors: usize,
    seen_skipped: usize,
    seen_time: f64,
}

impl SuiteAccumulator {
    fn from_attrs(tag: &BytesStart) -> Result<Self, JunitError> {
        Ok(Self {
            name: attr_value(tag, "name")?,
            declared_tests: attr_usize(tag, "tests")?,
            declared_failures: attr_usize(tag, "failures")?,
            declared_errors: attr_usize(tag, "errors")?,
            declared_skipped: attr_usize(tag, "skipped")?,
            declared_time: attr_f64(tag, "time")?,
            ..Default::default()
        })
    }

    fn finish(self) -> TestSuiteSummary {
        let tests = self.declared_tests.unwrap_or(self.seen_tests);
        let failures = self.declared_failures.unwrap_or(self.seen_failures);
        let errors = self.declared_errors.unwrap_or(self.seen_errors);
        let skipped = self.declared_skipped.unwrap_or(self.seen_skipped);
        let passed = tests.saturating_sub(failures + errors + skipped);
        let time_seconds = self.declared_time.unwrap_or(self.seen_time);
        TestSuiteSummary {
            name: self.name.unwrap_or_default(),
            tests,
            passed,
            failures,
            errors,
            skipped,
            time_seconds,
        }
    }
}

fn fold_suite(summary: &mut TestReportSummary, acc: SuiteAccumulator) {
    let suite = acc.finish();
    summary.total_tests += suite.tests;
    summary.passed_tests += suite.passed;
    summary.failed_tests += suite.failures;
    summary.errors += suite.errors;
    summary.skipped_tests += suite.skipped;
    summary.time_seconds += suite.time_seconds;
    summary.suites.push(suite);
}

/// Cross-event parse state: the running summary, the `<testsuite>`
/// currently being accumulated (if any), and whether we're inside a
/// `<testcase>` and what outcome it's seen so far — split out so
/// `parse_junit`'s event loop can dispatch to one method per event kind
/// instead of three parallel match statements.
#[derive(Default)]
struct ParseState {
    summary: TestReportSummary,
    current: Option<SuiteAccumulator>,
    in_testcase: bool,
    testcase_outcome: Outcome,
}

impl ParseState {
    fn open_testsuite(&mut self, tag: &BytesStart) -> Result<(), JunitError> {
        self.current = Some(SuiteAccumulator::from_attrs(tag)?);
        Ok(())
    }

    /// A self-closed `<testsuite/>` — folds its declared attributes
    /// straight in without becoming the "current" suite, since it has no
    /// `<testcase>` children to accumulate.
    fn self_closed_testsuite(&mut self, tag: &BytesStart) -> Result<(), JunitError> {
        fold_suite(&mut self.summary, SuiteAccumulator::from_attrs(tag)?);
        Ok(())
    }

    fn count_testcase(&mut self, tag: &BytesStart) -> Result<(), JunitError> {
        let time = attr_f64(tag, "time")?.unwrap_or(0.0);
        if let Some(acc) = self.current.as_mut() {
            acc.seen_tests += 1;
            acc.seen_time += time;
        }
        Ok(())
    }

    fn open_testcase(&mut self, tag: &BytesStart) -> Result<(), JunitError> {
        self.in_testcase = true;
        self.testcase_outcome = Outcome::Passed;
        self.count_testcase(tag)
    }

    fn mark_outcome(&mut self, local_name: &[u8]) {
        if !self.in_testcase {
            return;
        }
        match local_name {
            b"failure" => self.testcase_outcome = Outcome::Failed,
            b"error" => self.testcase_outcome = Outcome::Errored,
            b"skipped" => self.testcase_outcome = Outcome::Skipped,
            _ => {}
        }
    }

    fn close_testsuite(&mut self) {
        if let Some(acc) = self.current.take() {
            fold_suite(&mut self.summary, acc);
        }
    }

    fn close_testcase(&mut self) {
        if let Some(acc) = self.current.as_mut() {
            match self.testcase_outcome {
                Outcome::Passed => {}
                Outcome::Failed => acc.seen_failures += 1,
                Outcome::Errored => acc.seen_errors += 1,
                Outcome::Skipped => acc.seen_skipped += 1,
            }
        }
        self.in_testcase = false;
    }

    fn handle_start(&mut self, tag: &BytesStart) -> Result<(), JunitError> {
        match tag.local_name().as_ref() {
            b"testsuite" => self.open_testsuite(tag),
            b"testcase" => self.open_testcase(tag),
            other => {
                self.mark_outcome(other);
                Ok(())
            }
        }
    }

    fn handle_empty(&mut self, tag: &BytesStart) -> Result<(), JunitError> {
        match tag.local_name().as_ref() {
            b"testsuite" => self.self_closed_testsuite(tag),
            // Self-closed testcase: no failure/error/skipped child, so it passed.
            b"testcase" => self.count_testcase(tag),
            other => {
                self.mark_outcome(other);
                Ok(())
            }
        }
    }

    fn handle_end(&mut self, tag: &BytesEnd) {
        match tag.local_name().as_ref() {
            b"testsuite" => self.close_testsuite(),
            b"testcase" => self.close_testcase(),
            _ => {}
        }
    }
}

/// Parses a JUnit XML test report into aggregate totals plus a per-suite
/// breakdown. Accepts both a `<testsuites>` wrapper with multiple children
/// and a single root `<testsuite>`.
pub fn parse_junit(content: &str) -> Result<TestReportSummary, JunitError> {
    if content.trim().is_empty() {
        return Err(JunitError::Empty);
    }

    let mut reader = Reader::from_str(content);
    reader.config_mut().trim_text(true);

    let mut state = ParseState::default();
    let mut buf = Vec::new();
    loop {
        let event = reader
            .read_event_into(&mut buf)
            .map_err(|e| JunitError::Malformed(e.to_string()))?;
        match event {
            Event::Eof => break,
            Event::Start(tag) => state.handle_start(&tag)?,
            Event::Empty(tag) => state.handle_empty(&tag)?,
            Event::End(tag) => state.handle_end(&tag),
            _ => {}
        }
        buf.clear();
    }

    if state.summary.suites.is_empty() {
        Err(JunitError::Empty)
    } else {
        Ok(state.summary)
    }
}

fn attr_value(tag: &BytesStart, key: &str) -> Result<Option<String>, JunitError> {
    for attr in tag.attributes() {
        let attr = attr.map_err(|e| JunitError::Malformed(e.to_string()))?;
        if attr.key.local_name().as_ref() == key.as_bytes() {
            let value = attr
                .unescape_value()
                .map_err(|e| JunitError::Malformed(e.to_string()))?;
            return Ok(Some(value.into_owned()));
        }
    }
    Ok(None)
}

fn attr_usize(tag: &BytesStart, key: &str) -> Result<Option<usize>, JunitError> {
    Ok(attr_value(tag, key)?.and_then(|v| v.trim().parse::<usize>().ok()))
}

fn attr_f64(tag: &BytesStart, key: &str) -> Result<Option<f64>, JunitError> {
    Ok(attr_value(tag, key)?.and_then(|v| v.trim().parse::<f64>().ok()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_single_passing_suite_from_declared_attributes() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<testsuites>
  <testsuite name="unit-tests" tests="3" failures="0" errors="0" skipped="0" time="1.5">
    <testcase name="test1" time="0.5"/>
    <testcase name="test2" time="0.5"/>
    <testcase name="test3" time="0.5"/>
  </testsuite>
</testsuites>"#;
        let summary = parse_junit(xml).unwrap();
        assert_eq!(summary.total_tests, 3);
        assert_eq!(summary.passed_tests, 3);
        assert_eq!(summary.failed_tests, 0);
        assert_eq!(summary.errors, 0);
        assert_eq!(summary.skipped_tests, 0);
        assert!((summary.time_seconds - 1.5).abs() < f64::EPSILON);
        assert_eq!(summary.suites.len(), 1);
    }

    #[test]
    fn parses_failure_error_and_skipped_testcase_children() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<testsuite name="mixed" tests="4" time="2.0">
  <testcase name="passes" time="0.5"/>
  <testcase name="fails" time="0.5">
    <failure message="assertion failed">stack trace</failure>
  </testcase>
  <testcase name="errors" time="0.5">
    <error message="boom">stack trace</error>
  </testcase>
  <testcase name="skipped" time="0.5">
    <skipped message="not implemented"/>
  </testcase>
</testsuite>"#;
        let summary = parse_junit(xml).unwrap();
        assert_eq!(summary.total_tests, 4);
        assert_eq!(summary.passed_tests, 1);
        assert_eq!(summary.failed_tests, 1);
        assert_eq!(summary.errors, 1);
        assert_eq!(summary.skipped_tests, 1);
    }

    #[test]
    fn derives_counts_from_testcases_when_suite_attributes_are_missing() {
        let xml = r#"<testsuite name="derived">
  <testcase name="a"/>
  <testcase name="b"><failure/></testcase>
  <testcase name="c"><skipped/></testcase>
</testsuite>"#;
        let summary = parse_junit(xml).unwrap();
        assert_eq!(summary.total_tests, 3);
        assert_eq!(summary.passed_tests, 1);
        assert_eq!(summary.failed_tests, 1);
        assert_eq!(summary.skipped_tests, 1);
    }

    #[test]
    fn aggregates_multiple_testsuites_and_keeps_the_per_suite_breakdown() {
        let xml = r#"<testsuites>
  <testsuite name="unit" tests="2" failures="1" errors="0" skipped="0" time="1.0"/>
  <testsuite name="integration" tests="5" failures="0" errors="1" skipped="1" time="3.0"/>
</testsuites>"#;
        let summary = parse_junit(xml).unwrap();
        assert_eq!(summary.total_tests, 7);
        assert_eq!(summary.failed_tests, 1);
        assert_eq!(summary.errors, 1);
        assert_eq!(summary.skipped_tests, 1);
        assert_eq!(summary.passed_tests, 4);
        assert!((summary.time_seconds - 4.0).abs() < f64::EPSILON);
        assert_eq!(summary.suites.len(), 2);
        assert_eq!(summary.suites[0].name, "unit");
        assert_eq!(summary.suites[1].name, "integration");
    }

    #[test]
    fn a_single_root_testsuite_without_a_wrapper_is_supported() {
        let xml = r#"<testsuite name="solo" tests="1" failures="0" errors="0" skipped="0" time="0.1">
  <testcase name="solo-test" time="0.1"/>
</testsuite>"#;
        let summary = parse_junit(xml).unwrap();
        assert_eq!(summary.total_tests, 1);
        assert_eq!(summary.passed_tests, 1);
        assert_eq!(summary.suites.len(), 1);
    }

    #[test]
    fn empty_input_is_an_error() {
        assert!(matches!(parse_junit(""), Err(JunitError::Empty)));
        assert!(matches!(parse_junit("   \n  "), Err(JunitError::Empty)));
    }

    #[test]
    fn xml_with_no_testsuite_elements_is_an_error() {
        assert!(matches!(
            parse_junit(r#"<?xml version="1.0"?><report/>"#),
            Err(JunitError::Empty)
        ));
    }

    #[test]
    fn malformed_xml_is_an_error() {
        // Mismatched end tag: quick-xml rejects this as ill-formed.
        let xml = r#"<testsuites><testsuite name="broken" tests="1"></wrongtag></testsuites>"#;
        assert!(matches!(parse_junit(xml), Err(JunitError::Malformed(_))));
    }
}
