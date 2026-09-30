//! Quality as a vector, not a verdict (Pareto guard for refactor tasks).
//!
//! [`completion`](crate::completion) answers "did the task add findings?".
//! A refactor can pass that and still make the system worse: splitting one
//! module into five adds no finding anywhere, yet raises coupling everywhere
//! the five now import each other. Continuous refactoring is a
//! multi-objective problem — improving one quality routinely degrades
//! another — so a refactor task is judged here on *every* measured dimension
//! at once, before and after, and is done only when no dimension got worse
//! beyond its tolerance (a Pareto-style guard: trade-offs are surfaced, not
//! averaged away).
//!
//! Values are integers on purpose: every dimension is a count or a 0-100
//! score, and integer comparison keeps verdicts exact and `Eq`.

use std::collections::BTreeMap;
use std::fmt;

/// One measured quality dimension.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Dimension {
    /// `AnalysisReport::health_score`, 0-100. Higher is better.
    HealthScore,
    /// Estimated remediation effort, minutes.
    DebtMinutes,
    /// Lines inside a copy-paste clone set.
    DuplicatedLines,
    /// Functions whose cyclomatic complexity exceeds
    /// [`COMPLEX_FUNCTION_THRESHOLD`].
    ComplexFunctions,
    /// The single most complex function's cyclomatic complexity.
    MaxCyclomatic,
    /// File-level import edges — the coupling an over-eager split inflates.
    ImportEdges,
    /// Component-level dependency edges.
    ComponentEdges,
    /// Import cycles.
    ImportCycles,
}

/// Cyclomatic complexity above which a function counts toward
/// [`Dimension::ComplexFunctions`] — McCabe's own "consider splitting" line.
pub const COMPLEX_FUNCTION_THRESHOLD: u32 = 10;

impl Dimension {
    pub const ALL: [Dimension; 8] = [
        Dimension::HealthScore,
        Dimension::DebtMinutes,
        Dimension::DuplicatedLines,
        Dimension::ComplexFunctions,
        Dimension::MaxCyclomatic,
        Dimension::ImportEdges,
        Dimension::ComponentEdges,
        Dimension::ImportCycles,
    ];

    pub fn higher_is_better(self) -> bool {
        matches!(self, Dimension::HealthScore)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Dimension::HealthScore => "health_score",
            Dimension::DebtMinutes => "debt_minutes",
            Dimension::DuplicatedLines => "duplicated_lines",
            Dimension::ComplexFunctions => "complex_functions",
            Dimension::MaxCyclomatic => "max_cyclomatic",
            Dimension::ImportEdges => "import_edges",
            Dimension::ComponentEdges => "component_edges",
            Dimension::ImportCycles => "import_cycles",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|d| d.as_str() == raw)
    }

    /// How much worse `after` is than `before`, in this dimension's own
    /// units; negative when it improved.
    fn worsening(self, before: i64, after: i64) -> i64 {
        if self.higher_is_better() {
            before - after
        } else {
            after - before
        }
    }
}

impl fmt::Display for Dimension {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A snapshot of every measured dimension. A dimension the analyzer could
/// not measure is simply absent, and is never compared.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct QualityVector {
    values: BTreeMap<Dimension, i64>,
}

impl QualityVector {
    pub fn with(mut self, dimension: Dimension, value: i64) -> Self {
        self.values.insert(dimension, value);
        self
    }

    pub fn get(&self, dimension: Dimension) -> Option<i64> {
        self.values.get(&dimension).copied()
    }

    pub fn iter(&self) -> impl Iterator<Item = (Dimension, i64)> + '_ {
        self.values.iter().map(|(d, v)| (*d, *v))
    }
}

/// How much each dimension may worsen before the guard objects. Zero for
/// every dimension by default: a refactor that makes anything measurably
/// worse must say why, and that "why" is a human's call, not the model's.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Tolerances {
    allowed: BTreeMap<Dimension, i64>,
}

impl Tolerances {
    pub fn allow(mut self, dimension: Dimension, worsening: i64) -> Self {
        self.allowed.insert(dimension, worsening.max(0));
        self
    }

    pub fn allowed(&self, dimension: Dimension) -> i64 {
        self.allowed.get(&dimension).copied().unwrap_or(0)
    }
}

/// One dimension's before/after.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DimensionChange {
    pub dimension: Dimension,
    pub before: i64,
    pub after: i64,
}

impl DimensionChange {
    pub fn describe(&self) -> String {
        let direction = if self.dimension.higher_is_better() {
            "higher is better"
        } else {
            "lower is better"
        };
        format!(
            "{}: {} -> {} ({direction})",
            self.dimension, self.before, self.after
        )
    }
}

/// Every dimension measured on both sides, split by direction of change.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct QualityDelta {
    pub improved: Vec<DimensionChange>,
    /// Worse by more than the tolerance allows.
    pub degraded: Vec<DimensionChange>,
    /// Worse, but within tolerance — reported, never objected to.
    pub tolerated: Vec<DimensionChange>,
}

impl QualityDelta {
    pub fn is_pareto_safe(&self) -> bool {
        self.degraded.is_empty()
    }

    /// Weighted sum of per-dimension improvement (positive = better), for
    /// ranking alternatives. Unweighted dimensions count with weight 1.
    pub fn utility(&self, weights: &BTreeMap<Dimension, i64>) -> i64 {
        let weight = |d: Dimension| weights.get(&d).copied().unwrap_or(1);
        let gain =
            |c: &DimensionChange| -c.dimension.worsening(c.before, c.after) * weight(c.dimension);
        self.improved
            .iter()
            .chain(&self.degraded)
            .chain(&self.tolerated)
            .map(gain)
            .sum()
    }
}

/// Compares two snapshots dimension by dimension. Only dimensions present in
/// both are compared — "could not measure" is never read as "unchanged".
pub fn compare(
    before: &QualityVector,
    after: &QualityVector,
    tolerances: &Tolerances,
) -> QualityDelta {
    let mut delta = QualityDelta::default();
    for (dimension, old) in before.iter() {
        let Some(new) = after.get(dimension) else {
            continue;
        };
        let change = DimensionChange {
            dimension,
            before: old,
            after: new,
        };
        let worsening = dimension.worsening(old, new);
        if worsening < 0 {
            delta.improved.push(change);
        } else if worsening > tolerances.allowed(dimension) {
            delta.degraded.push(change);
        } else if worsening > 0 {
            delta.tolerated.push(change);
        }
    }
    delta
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vector(health: i64, edges: i64) -> QualityVector {
        QualityVector::default()
            .with(Dimension::HealthScore, health)
            .with(Dimension::ImportEdges, edges)
    }

    #[test]
    fn an_unchanged_vector_is_pareto_safe_and_empty() {
        let delta = compare(&vector(90, 10), &vector(90, 10), &Tolerances::default());
        assert!(delta.is_pareto_safe());
        assert!(delta.improved.is_empty() && delta.tolerated.is_empty());
    }

    #[test]
    fn a_local_improvement_that_raises_coupling_is_a_trade_off() {
        // The over-partitioning case: health went up, coupling went up more.
        let delta = compare(&vector(90, 10), &vector(92, 14), &Tolerances::default());
        assert!(!delta.is_pareto_safe());
        assert_eq!(delta.improved[0].dimension, Dimension::HealthScore);
        assert_eq!(delta.degraded[0].dimension, Dimension::ImportEdges);
    }

    #[test]
    fn a_falling_health_score_is_a_degradation() {
        let delta = compare(&vector(90, 10), &vector(89, 10), &Tolerances::default());
        assert_eq!(delta.degraded[0].dimension, Dimension::HealthScore);
    }

    #[test]
    fn a_tolerance_downgrades_a_degradation_to_tolerated() {
        let tolerances = Tolerances::default().allow(Dimension::ImportEdges, 5);
        let delta = compare(&vector(90, 10), &vector(92, 14), &tolerances);
        assert!(delta.is_pareto_safe());
        assert_eq!(delta.tolerated[0].dimension, Dimension::ImportEdges);
    }

    #[test]
    fn a_dimension_missing_on_either_side_is_not_compared() {
        let before = QualityVector::default().with(Dimension::ImportCycles, 0);
        let after = QualityVector::default();
        assert_eq!(
            compare(&before, &after, &Tolerances::default()),
            QualityDelta::default()
        );
    }

    #[test]
    fn utility_weighs_gains_against_losses() {
        let delta = compare(&vector(90, 10), &vector(92, 14), &Tolerances::default());
        assert_eq!(delta.utility(&BTreeMap::new()), 2 - 4);
        let weights = BTreeMap::from([(Dimension::HealthScore, 5)]);
        assert_eq!(delta.utility(&weights), 10 - 4);
    }

    #[test]
    fn dimension_names_round_trip() {
        for dimension in Dimension::ALL {
            assert_eq!(Dimension::parse(dimension.as_str()), Some(dimension));
        }
    }
}
