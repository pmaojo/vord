//! What to refactor next, and how much autonomy to grant doing it.
//!
//! Continuous refactoring cannot mean "refactor everything, always": the
//! budget is finite and each change carries risk. This module turns signals
//! vord already has — per-function complexity, CRAP where coverage exists,
//! the import graph — plus one it did not use before, **version-control
//! history**, into a ranked, explained plan:
//!
//! - **Priority** is a hotspot score: `risk × (1 + commits)`, where `risk` is
//!   the function's CRAP score when coverage is known and its cyclomatic
//!   complexity otherwise. Complex code nobody touches is cheap to leave
//!   alone; complex code that changes every week is where debt costs money.
//! - **Autonomy** is decided per candidate from blast radius (how many files
//!   import this one) and test protection (line coverage): well-covered code
//!   few files depend on may be refactored and merged on the analyzer's word;
//!   code many files depend on, or code tests barely exercise, needs a human
//!   before anything lands.
//! - **Hidden temporal coupling** — files that keep changing together with no
//!   import between them — is reported alongside, because it is a latent
//!   constraint a refactor cannot see in the code and should not break.
//!
//! Pure: the caller supplies history, graph and complexity; nothing here
//! reads git or the filesystem.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::quality::COMPLEX_FUNCTION_THRESHOLD;

/// CRAP score from which a function is a candidate regardless of its
/// complexity alone — crap4clj's "complex *and* untested" band.
pub const CRAP_CANDIDATE_THRESHOLD: f64 = 30.0;

/// Dependents from which a change needs a human, whatever its coverage.
pub const ESCALATE_DEPENDENTS: usize = 10;
/// Dependents up to which a well-covered change may land unreviewed.
pub const AUTO_MAX_DEPENDENTS: usize = 2;
/// Coverage (percent) from which a change may land unreviewed.
pub const AUTO_MIN_COVERAGE: f64 = 80.0;
/// Coverage (percent) below which a change needs a human.
pub const ESCALATE_BELOW_COVERAGE: f64 = 30.0;

/// Co-changes from which two unconnected files count as temporally coupled.
pub const MIN_CO_CHANGES: u32 = 3;

/// One function's measured risk.
#[derive(Clone, Debug, PartialEq)]
pub struct FunctionRisk {
    pub path: String,
    pub line: u32,
    pub cyclomatic: u32,
    /// Line coverage of the function's own span, when coverage was supplied.
    pub coverage: Option<f64>,
    /// CRAP score, when coverage was supplied.
    pub crap: Option<f64>,
}

/// One file's history over the analysed window.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct FileHistory {
    /// Commits that touched the file.
    pub commits: u32,
    /// Lines added plus lines deleted.
    pub churn: u64,
}

/// Everything the planner reads.
#[derive(Clone, Debug, Default)]
pub struct PlanInput {
    pub functions: Vec<FunctionRisk>,
    pub history: BTreeMap<String, FileHistory>,
    /// Commits in which each (sorted) pair of files changed together.
    pub co_changes: BTreeMap<(String, String), u32>,
    /// File-level import edges `(from, to)`.
    pub imports: BTreeSet<(String, String)>,
}

/// How far a candidate's refactor may go without a human.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Autonomy {
    /// The analyzer's verdict is enough to land it.
    Auto,
    /// Open a pull request for a human to review.
    Review,
    /// Do not attempt it autonomously; a human should decide first.
    Escalate,
}

impl Autonomy {
    pub fn as_str(self) -> &'static str {
        match self {
            Autonomy::Auto => "auto",
            Autonomy::Review => "review",
            Autonomy::Escalate => "escalate",
        }
    }
}

/// One ranked refactor candidate, with the reasons for its rank and tier.
/// Not `Clone`: wide enough that copies should be deliberate, and callers
/// borrow candidates from the [`Plan`] that owns them.
#[derive(Debug, PartialEq, Serialize)]
pub struct Candidate {
    pub path: String,
    pub line: u32,
    pub cyclomatic: u32,
    pub coverage: Option<f64>,
    pub crap: Option<f64>,
    pub commits: u32,
    pub churn: u64,
    pub dependents: usize,
    pub score: f64,
    pub autonomy: Autonomy,
    pub rationale: String,
}

/// Two files that change together with no import between them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TemporalCoupling {
    pub a: String,
    pub b: String,
    pub co_changes: u32,
}

#[derive(Debug, Default, PartialEq, Serialize)]
pub struct Plan {
    /// Highest score first.
    pub candidates: Vec<Candidate>,
    /// Most co-changes first.
    pub temporal_couplings: Vec<TemporalCoupling>,
}

/// Ranks every function worth refactoring and assigns it an autonomy tier.
pub fn plan(input: &PlanInput) -> Plan {
    Plan {
        candidates: candidates(input),
        temporal_couplings: temporal_couplings(input),
    }
}

fn candidates(input: &PlanInput) -> Vec<Candidate> {
    let mut dependents: BTreeMap<&str, usize> = BTreeMap::new();
    for (_, to) in &input.imports {
        *dependents.entry(to.as_str()).or_insert(0) += 1;
    }
    let mut ranked: Vec<Candidate> = input
        .functions
        .iter()
        .filter(|f| {
            f.cyclomatic > COMPLEX_FUNCTION_THRESHOLD
                || f.crap.is_some_and(|c| c >= CRAP_CANDIDATE_THRESHOLD)
        })
        .map(|f| {
            let history = input.history.get(&f.path).copied().unwrap_or_default();
            candidate(
                f,
                history,
                dependents.get(f.path.as_str()).copied().unwrap_or(0),
            )
        })
        .collect();
    ranked.sort_by(|a, b| {
        b.score
            .total_cmp(&a.score)
            .then_with(|| a.path.cmp(&b.path))
            .then_with(|| a.line.cmp(&b.line))
    });
    ranked
}

fn candidate(f: &FunctionRisk, history: FileHistory, dependents: usize) -> Candidate {
    let risk = f.crap.unwrap_or(f64::from(f.cyclomatic));
    let (autonomy, why) = autonomy(f.coverage, dependents);
    let risk_text = match f.crap {
        Some(crap) => format!("CRAP {crap:.0}"),
        None => format!("cyclomatic {}", f.cyclomatic),
    };
    Candidate {
        path: f.path.clone(),
        line: f.line,
        cyclomatic: f.cyclomatic,
        coverage: f.coverage,
        crap: f.crap,
        commits: history.commits,
        churn: history.churn,
        dependents,
        score: risk * f64::from(1 + history.commits),
        autonomy,
        rationale: format!(
            "{risk_text}, changed in {} commit(s); {why}",
            history.commits
        ),
    }
}

fn temporal_couplings(input: &PlanInput) -> Vec<TemporalCoupling> {
    let imported = |a: &String, b: &String| input.imports.contains(&(a.clone(), b.clone()));
    let mut couplings: Vec<TemporalCoupling> = input
        .co_changes
        .iter()
        .filter(|((a, b), count)| **count >= MIN_CO_CHANGES && !imported(a, b) && !imported(b, a))
        .map(|((a, b), count)| TemporalCoupling {
            a: a.clone(),
            b: b.clone(),
            co_changes: *count,
        })
        .collect();
    couplings.sort_by(|x, y| {
        y.co_changes
            .cmp(&x.co_changes)
            .then_with(|| (&x.a, &x.b).cmp(&(&y.a, &y.b)))
    });
    couplings
}

fn autonomy(coverage: Option<f64>, dependents: usize) -> (Autonomy, String) {
    let coverage_text = match coverage {
        Some(c) => format!("{c:.0}% covered"),
        None => "coverage unknown".to_string(),
    };
    let context = format!("{dependents} dependent file(s), {coverage_text}");
    if dependents >= ESCALATE_DEPENDENTS {
        return (
            Autonomy::Escalate,
            format!("{context}: blast radius too wide to change unreviewed"),
        );
    }
    if coverage.is_some_and(|c| c < ESCALATE_BELOW_COVERAGE) {
        return (
            Autonomy::Escalate,
            format!("{context}: tests barely exercise it, so behaviour cannot be verified"),
        );
    }
    if dependents <= AUTO_MAX_DEPENDENTS && coverage.is_some_and(|c| c >= AUTO_MIN_COVERAGE) {
        return (Autonomy::Auto, format!("{context}: narrow and well tested"));
    }
    (Autonomy::Review, format!("{context}: needs a reviewer"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn function(path: &str, cyclomatic: u32, coverage: Option<f64>) -> FunctionRisk {
        FunctionRisk {
            path: path.to_string(),
            line: 1,
            cyclomatic,
            coverage,
            crap: None,
        }
    }

    fn history(commits: u32) -> FileHistory {
        FileHistory {
            commits,
            churn: u64::from(commits) * 10,
        }
    }

    #[test]
    fn simple_functions_are_not_candidates() {
        let input = PlanInput {
            functions: vec![function("a.rs", 3, None)],
            ..PlanInput::default()
        };
        assert!(plan(&input).candidates.is_empty());
    }

    #[test]
    fn churn_outranks_raw_complexity() {
        let input = PlanInput {
            functions: vec![function("cold.rs", 30, None), function("hot.rs", 12, None)],
            history: BTreeMap::from([("hot.rs".to_string(), history(9))]),
            ..PlanInput::default()
        };
        let plan = plan(&input);
        let ranked: Vec<&str> = plan.candidates.iter().map(|c| c.path.as_str()).collect();
        assert_eq!(ranked, ["hot.rs", "cold.rs"]);
    }

    #[test]
    fn crap_replaces_complexity_as_risk_when_known() {
        let mut risky = function("a.rs", 8, Some(0.0));
        risky.crap = Some(72.0);
        let input = PlanInput {
            functions: vec![risky],
            ..PlanInput::default()
        };
        let plan = plan(&input);
        assert_eq!(plan.candidates[0].score, 72.0);
        assert!(plan.candidates[0].rationale.contains("CRAP 72"));
    }

    #[test]
    fn autonomy_follows_blast_radius_and_coverage() {
        let hub_imports: BTreeSet<(String, String)> = (0..ESCALATE_DEPENDENTS)
            .map(|i| (format!("user{i}.rs"), "hub.rs".to_string()))
            .collect();
        let input = PlanInput {
            functions: vec![
                function("leaf.rs", 15, Some(95.0)),
                function("hub.rs", 15, Some(95.0)),
                function("untested.rs", 15, Some(10.0)),
                function("unknown.rs", 15, None),
            ],
            imports: hub_imports,
            ..PlanInput::default()
        };
        let tiers: BTreeMap<String, Autonomy> = plan(&input)
            .candidates
            .into_iter()
            .map(|c| (c.path, c.autonomy))
            .collect();
        assert_eq!(tiers["leaf.rs"], Autonomy::Auto);
        assert_eq!(tiers["hub.rs"], Autonomy::Escalate);
        assert_eq!(tiers["untested.rs"], Autonomy::Escalate);
        assert_eq!(tiers["unknown.rs"], Autonomy::Review);
    }

    #[test]
    fn co_changing_files_without_an_import_are_temporally_coupled() {
        let pair = |a: &str, b: &str| (a.to_string(), b.to_string());
        let input = PlanInput {
            co_changes: BTreeMap::from([
                (pair("api.rs", "schema.sql"), 5),
                (pair("a.rs", "b.rs"), 7),
                (pair("x.rs", "y.rs"), 1),
            ]),
            imports: BTreeSet::from([pair("b.rs", "a.rs")]),
            ..PlanInput::default()
        };
        assert_eq!(
            plan(&input).temporal_couplings,
            vec![TemporalCoupling {
                a: "api.rs".into(),
                b: "schema.sql".into(),
                co_changes: 5
            }]
        );
    }
}
