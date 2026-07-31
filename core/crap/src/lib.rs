//! CRAP (Change Risk Anti-Patterns) scoring: `CC² × (1 − coverage)³ + CC`,
//! from [crap4clj](https://github.com/unclebob/crap4clj). Both inputs —
//! cyclomatic complexity and per-line coverage — already exist elsewhere in
//! yunq; this crate is only the formula and the join between them, kept as
//! pure `std`-only logic (no tree-sitter, no coverage-ingest dependency) so
//! it is trivially unit-testable and reusable from any composition root.
//!
//! Deliberately a `core/*` crate, not `rulesets/*`: unlike an ordinary
//! `Rule`, CRAP needs coverage data that (in the current pipeline) is only
//! read from disk *after* `AnalyzerService::analyze_files` has already
//! returned — see `bin/cli/src/main.rs`'s `ingest_coverage` running after
//! `scan_with_project_config`. A `Rule::check(file, ast)` call never has
//! coverage in scope no matter how CRAP is implemented, so this is a
//! post-processing join over an `AnalysisReport`'s already-computed
//! `function_complexities()` and `coverage_report()`, mirroring how
//! `core/duplication` is a plain algorithm crate that `AnalyzerService`
//! invokes directly rather than a `Rule` impl.

use std::collections::BTreeMap;

use yunq_ast::Span;

/// Risk bands from crap4clj: 1-5 low risk (not worth reporting), 5-30 a
/// refactor candidate, 30+ complex *and* untested.
pub const REFACTOR_CANDIDATE_THRESHOLD: f64 = 5.0;
pub const HIGH_RISK_THRESHOLD: f64 = 30.0;

/// `CC² × (1 − coverage)³ + CC`. `coverage_percent` is `0.0..=100.0`.
pub fn crap_score(cyclomatic: u32, coverage_percent: f64) -> f64 {
    let cc = cyclomatic as f64;
    let uncovered = (1.0 - coverage_percent / 100.0).clamp(0.0, 1.0);
    cc * cc * uncovered.powi(3) + cc
}

/// One function's coverage percentage, restricted to the lines its `span`
/// covers. `lines` is a file's instrumented-line -> hit-count map (see
/// `yunq_rules_engine::FileCoverage::lines`). Returns `None` when no line in
/// `span` was instrumented at all — absent coverage data must never be
/// scored as 0%-covered, matching the fail-open convention the rest of the
/// codebase uses when a measure has no input.
pub fn coverage_in_span(lines: &BTreeMap<u32, usize>, span: Span) -> Option<f64> {
    let in_span: Vec<usize> = lines
        .range(span.start_line..=span.end_line)
        .map(|(_, &hits)| hits)
        .collect();
    if in_span.is_empty() {
        return None;
    }
    let covered = in_span.iter().filter(|&&hits| hits > 0).count();
    Some(covered as f64 * 100.0 / in_span.len() as f64)
}

/// One function whose CRAP score crossed [`REFACTOR_CANDIDATE_THRESHOLD`].
#[derive(Clone, Debug, PartialEq)]
pub struct CrapFinding {
    pub path: String,
    pub span: Span,
    pub cyclomatic: u32,
    pub coverage_percent: f64,
    pub score: f64,
}

/// Scores one function, returning a finding only when coverage data exists
/// for at least one of its lines and the resulting score is above
/// [`REFACTOR_CANDIDATE_THRESHOLD`].
pub fn score_function(
    path: &str,
    span: Span,
    cyclomatic: u32,
    lines: &BTreeMap<u32, usize>,
) -> Option<CrapFinding> {
    let coverage_percent = coverage_in_span(lines, span)?;
    let score = crap_score(cyclomatic, coverage_percent);
    (score > REFACTOR_CANDIDATE_THRESHOLD).then(|| CrapFinding {
        path: path.to_string(),
        span,
        cyclomatic,
        coverage_percent,
        score,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fully_covered_simple_function_scores_low() {
        // CC=1, 100% covered: 1*1*0 + 1 = 1, below the refactor band.
        assert_eq!(crap_score(1, 100.0), 1.0);
    }

    #[test]
    fn uncovered_complex_function_scores_high() {
        // CC=10, 0% covered: 100*1 + 10 = 110, well past the high-risk band.
        let score = crap_score(10, 0.0);
        assert!(
            score > HIGH_RISK_THRESHOLD,
            "expected > {HIGH_RISK_THRESHOLD}, got {score}"
        );
    }

    #[test]
    fn partial_coverage_lands_between_the_bands() {
        // CC=6, 50% covered: 36*0.125 + 6 = 10.5 - a refactor candidate.
        let score = crap_score(6, 50.0);
        assert!(score > REFACTOR_CANDIDATE_THRESHOLD && score < HIGH_RISK_THRESHOLD);
    }

    #[test]
    fn coverage_in_span_restricts_to_the_functions_own_lines() {
        let mut lines = BTreeMap::new();
        lines.insert(1, 5); // outside the span
        lines.insert(10, 1);
        lines.insert(11, 0);
        lines.insert(20, 3); // outside the span
        let span = Span::new(10, 1, 11, 1);
        assert_eq!(coverage_in_span(&lines, span), Some(50.0));
    }

    #[test]
    fn coverage_in_span_is_none_when_no_line_is_instrumented() {
        let mut lines = BTreeMap::new();
        lines.insert(1, 5);
        let span = Span::new(10, 1, 11, 1);
        assert_eq!(coverage_in_span(&lines, span), None);
    }

    #[test]
    fn score_function_is_silent_without_coverage_data() {
        let lines = BTreeMap::new();
        let span = Span::new(1, 1, 5, 1);
        assert_eq!(score_function("a.rs", span, 20, &lines), None);
    }

    #[test]
    fn score_function_is_silent_below_the_refactor_band() {
        let mut lines = BTreeMap::new();
        lines.insert(1, 5);
        let span = Span::new(1, 1, 1, 10);
        // CC=1, 100% covered -> score 1.0, below threshold.
        assert_eq!(score_function("a.rs", span, 1, &lines), None);
    }

    #[test]
    fn score_function_reports_a_finding_above_the_refactor_band() {
        let mut lines = BTreeMap::new();
        lines.insert(1, 0);
        lines.insert(2, 0);
        let span = Span::new(1, 1, 2, 10);
        let finding = score_function("a.rs", span, 10, &lines).expect("above threshold");
        assert_eq!(finding.coverage_percent, 0.0);
        assert_eq!(finding.cyclomatic, 10);
        assert_eq!(finding.score, crap_score(10, 0.0));
    }
}
