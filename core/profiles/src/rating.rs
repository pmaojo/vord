//! A–E maintainability rating, replicating SonarQube's SQALE model
//! (`DebtRatingGrid` + `MaintainabilityMeasuresVisitor`): the rating is
//! looked up from the *technical debt ratio* — remediation effort as a
//! fraction of what it would cost to write the code from scratch — not from
//! the worst issue severity present. A file with a thousand trivial-effort
//! minor issues can rate worse than one with a single quick-fix blocker.
//!
//! Reliability and Security ratings are a *different* algorithm from
//! Maintainability, not the same grid applied twice: SonarQube's
//! `ReliabilityAndSecurityRatingMeasuresVisitor` looks up each issue's rating
//! via `Rating.RATING_BY_SEVERITY` (`server/sonar-server-common/.../Rating.java`)
//! and folds it into the metric for the issue's own type — bugs into
//! Reliability, vulnerabilities into Security — taking the worst rating
//! present in each bucket (A if the bucket is empty). Code smells (the only
//! type Maintainability cares about) contribute to neither.

use std::collections::HashMap;
use std::fmt;

use crate::{RuleId, Severity};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Rating {
    A,
    B,
    C,
    D,
    E,
}

impl Rating {
    pub fn letter(&self) -> char {
        match self {
            Rating::A => 'A',
            Rating::B => 'B',
            Rating::C => 'C',
            Rating::D => 'D',
            Rating::E => 'E',
        }
    }

    /// Rating from a technical debt ratio using SonarQube's default grid
    /// (`sonar.technicalDebt.ratingGrid` = `0.05,0.1,0.2,0.5`): A ≤ 5%,
    /// B ≤ 10%, C ≤ 20%, D ≤ 50%, otherwise E.
    pub fn from_debt_ratio(ratio: f64) -> Self {
        DebtRatingGrid::default().rating_for_ratio(ratio)
    }

    /// Rating from a single issue's severity, mirroring SonarQube's
    /// `Rating.RATING_BY_SEVERITY`: `BLOCKER -> E`, `CRITICAL -> D`,
    /// `MAJOR -> C`, `MINOR -> B`, `INFO -> A`. This is the Reliability/
    /// Security algorithm — worst severity present, not a cost ratio.
    pub fn from_severity(severity: Severity) -> Self {
        match severity {
            Severity::Blocker => Rating::E,
            Severity::Critical => Rating::D,
            Severity::Major => Rating::C,
            Severity::Minor => Rating::B,
            Severity::Info => Rating::A,
        }
    }
}

impl fmt::Display for Rating {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.letter())
    }
}

/// Minutes to develop one line of code from scratch — SonarQube's
/// `sonar.technicalDebt.developmentCost`, default 30.
pub const DEFAULT_DEV_COST_MINUTES_PER_LINE: f64 = 30.0;

/// Technical debt ratio = remediation effort / development cost, where
/// development cost = lines of code × cost per line. Mirrors
/// `MaintainabilityMeasuresVisitor.computeDensity`.
pub fn debt_ratio(remediation_minutes: f64, lines_of_code: f64, dev_cost_per_line: f64) -> f64 {
    let development_cost = lines_of_code * dev_cost_per_line;
    if development_cost <= 0.0 { 0.0 } else { remediation_minutes / development_cost }
}

/// The four upper bounds separating A/B/C/D/E, mirroring
/// SonarQube's `DebtRatingGrid`: `A = [0, grid[0]]`, `B = (grid[0], grid[1]]`,
/// … `E = (grid[3], +inf)`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct DebtRatingGrid {
    thresholds: [f64; 4],
}

impl Default for DebtRatingGrid {
    fn default() -> Self {
        Self { thresholds: [0.05, 0.1, 0.2, 0.5] }
    }
}

impl DebtRatingGrid {
    pub fn new(thresholds: [f64; 4]) -> Self {
        Self { thresholds }
    }

    pub fn rating_for_ratio(&self, ratio: f64) -> Rating {
        let [a, b, c, d] = self.thresholds;
        if ratio <= a {
            Rating::A
        } else if ratio <= b {
            Rating::B
        } else if ratio <= c {
            Rating::C
        } else if ratio <= d {
            Rating::D
        } else {
            Rating::E
        }
    }
}

/// SonarQube's three issue types — which of the three ratings an issue
/// counts toward. Code smells feed Maintainability (the debt-ratio grid
/// above); bugs and vulnerabilities each get their own worst-severity
/// rating via [`reliability_and_security_ratings`] instead, and never mix
/// with each other or with Maintainability.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum IssueType {
    Bug,
    Vulnerability,
    CodeSmell,
}

/// A project/component's Reliability and Security ratings, computed
/// independently of each other.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReliabilitySecurityRatings {
    pub reliability: Rating,
    pub security: Rating,
}

/// Reliability rating = worst [`Rating::from_severity`] among open `Bug`
/// issues (`A` if there are none); Security rating = the same over
/// `Vulnerability` issues. Mirrors
/// `ReliabilityAndSecurityRatingMeasuresVisitor`: each issue is rated from
/// its own severity and folded into the metric for its own type only —
/// unlike Maintainability, this is never a cost ratio, and a type's rating
/// is untouched by issues of a different type.
pub fn reliability_and_security_ratings(
    issues: impl IntoIterator<Item = (IssueType, Severity)>,
) -> ReliabilitySecurityRatings {
    let mut reliability = Rating::A;
    let mut security = Rating::A;
    for (issue_type, severity) in issues {
        let rating = Rating::from_severity(severity);
        match issue_type {
            IssueType::Bug => reliability = reliability.max(rating),
            IssueType::Vulnerability => security = security.max(rating),
            IssueType::CodeSmell => {}
        }
    }
    ReliabilitySecurityRatings { reliability, security }
}

/// Cumulative remediation effort (minutes), grouped by rule and by
/// component (file) — the drill-down view behind a project-wide debt
/// total: which rule is generating the most debt, and which file would
/// benefit most from cleanup.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RemediationEffortSummary {
    pub by_rule: HashMap<RuleId, u32>,
    pub by_component: HashMap<String, u32>,
}

/// Builds a [`RemediationEffortSummary`] from `(rule, component, minutes)`
/// triples — one per issue — summing minutes within each rule and within
/// each component independently (an issue counts toward both totals).
pub fn aggregate_remediation_effort<'a>(
    issues: impl IntoIterator<Item = (RuleId, &'a str, u32)>,
) -> RemediationEffortSummary {
    let mut summary = RemediationEffortSummary::default();
    for (rule, component, minutes) in issues {
        *summary.by_rule.entry(rule).or_insert(0) += minutes;
        *summary.by_component.entry(component.to_string()).or_insert(0) += minutes;
    }
    summary
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debt_ratio_from_sonarqube_docs_example() {
        // 24,000 minutes of debt over 2,500 LOC at 30 min/line = 32% -> D.
        let ratio = debt_ratio(24_000.0, 2_500.0, DEFAULT_DEV_COST_MINUTES_PER_LINE);
        assert!((ratio - 0.32).abs() < 1e-9);
        assert_eq!(Rating::from_debt_ratio(ratio), Rating::D);
    }

    #[test]
    fn grid_boundaries_are_inclusive_upper_bounds() {
        assert_eq!(Rating::from_debt_ratio(0.0), Rating::A);
        assert_eq!(Rating::from_debt_ratio(0.05), Rating::A);
        assert_eq!(Rating::from_debt_ratio(0.050001), Rating::B);
        assert_eq!(Rating::from_debt_ratio(0.1), Rating::B);
        assert_eq!(Rating::from_debt_ratio(0.2), Rating::C);
        assert_eq!(Rating::from_debt_ratio(0.5), Rating::D);
        assert_eq!(Rating::from_debt_ratio(0.500001), Rating::E);
    }

    #[test]
    fn no_lines_of_code_means_no_debt_ratio() {
        assert_eq!(debt_ratio(100.0, 0.0, DEFAULT_DEV_COST_MINUTES_PER_LINE), 0.0);
    }

    #[test]
    fn ratings_order_from_best_to_worst() {
        assert!(Rating::A < Rating::E);
    }

    #[test]
    fn rating_by_severity_matches_sonarqube_table() {
        // Verified against `Rating.RATING_BY_SEVERITY` in
        // server/sonar-server-common/.../Rating.java.
        assert_eq!(Rating::from_severity(Severity::Blocker), Rating::E);
        assert_eq!(Rating::from_severity(Severity::Critical), Rating::D);
        assert_eq!(Rating::from_severity(Severity::Major), Rating::C);
        assert_eq!(Rating::from_severity(Severity::Minor), Rating::B);
        assert_eq!(Rating::from_severity(Severity::Info), Rating::A);
    }

    #[test]
    fn reliability_and_security_are_independent_and_worst_of_type() {
        let ratings = reliability_and_security_ratings([
            (IssueType::Bug, Severity::Minor),
            (IssueType::Bug, Severity::Critical),
            (IssueType::Vulnerability, Severity::Major),
        ]);
        // Worst bug (Critical -> D) drives Reliability...
        assert_eq!(ratings.reliability, Rating::D);
        // ...independently of the worst vulnerability (Major -> C).
        assert_eq!(ratings.security, Rating::C);
    }

    #[test]
    fn code_smells_and_the_other_type_never_affect_a_rating() {
        // The naive approach a single shared "worst severity across all
        // issues" grid would take: a Blocker code smell (pure
        // maintainability concern) must not touch Reliability or Security
        // at all, and a Blocker bug must not touch Security.
        let ratings = reliability_and_security_ratings([
            (IssueType::CodeSmell, Severity::Blocker),
            (IssueType::Bug, Severity::Blocker),
        ]);
        assert_eq!(ratings.security, Rating::A, "no vulnerability present, security must stay A");
        assert_eq!(ratings.reliability, Rating::E, "the blocker bug must still drive reliability");
    }

    #[test]
    fn no_bugs_or_vulnerabilities_means_both_ratings_are_a() {
        let ratings = reliability_and_security_ratings([(IssueType::CodeSmell, Severity::Blocker); 5]);
        assert_eq!(ratings.reliability, Rating::A);
        assert_eq!(ratings.security, Rating::A);
    }

    #[test]
    fn remediation_effort_aggregates_by_rule_and_by_component_independently() {
        let bug_rule = RuleId::new("bugs:null-deref").unwrap();
        let smell_rule = RuleId::new("smells:cognitive-complexity").unwrap();
        let summary = aggregate_remediation_effort([
            (bug_rule.clone(), "src/a.rs", 20),
            (bug_rule.clone(), "src/b.rs", 20),
            (smell_rule.clone(), "src/a.rs", 30),
        ]);

        assert_eq!(summary.by_rule[&bug_rule], 40);
        assert_eq!(summary.by_rule[&smell_rule], 30);
        assert_eq!(summary.by_component["src/a.rs"], 50);
        assert_eq!(summary.by_component["src/b.rs"], 20);
    }
}
