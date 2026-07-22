//! A–E maintainability rating, replicating SonarQube's SQALE model
//! (`DebtRatingGrid` + `MaintainabilityMeasuresVisitor`): the rating is
//! looked up from the *technical debt ratio* — remediation effort as a
//! fraction of what it would cost to write the code from scratch — not from
//! the worst issue severity present. A file with a thousand trivial-effort
//! minor issues can rate worse than one with a single quick-fix blocker.

use std::fmt;

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
}
