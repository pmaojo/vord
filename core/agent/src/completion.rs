//! The analyzer as the definition of done (roadmap A3).
//!
//! `RemediationEngine` already answers this question for a single issue in a
//! single file: the fix is accepted when the target rule stops firing and
//! nothing new appears. This lifts that verdict to task scope, where two
//! things change.
//!
//! First, the comparison has to be **against a baseline**, not against zero.
//! A single-issue fix runs on one file and can demand a clean report; a task
//! runs against a repository that already has findings, and demanding zero
//! would make every task in a real codebase impossible.
//!
//! Second, a finding's identity has to survive an edit. Line numbers move as
//! soon as anything above them changes, so identity here is
//! `(file, rule, message)` — the same rule firing with the same message in
//! the same file is the same finding, wherever it drifted to. Counted as a
//! multiset, so introducing a *second* copy of an existing finding is still
//! a regression rather than a match.
//!
//! No self-assessment turn is involved anywhere in this module. The model's
//! opinion of its own work is not an input.

use std::collections::HashMap;

use vord_ast::{SemanticDrift, SemanticFingerprint};
use vord_profiles::{RuleId, Severity};

use crate::quality::{self, DimensionChange, QualityVector, Tolerances};

/// A finding with the file it was found in. `vord_agent_policy::Finding`
/// deliberately has no path (a policy judges one file at a time and already
/// knows which); a task-scope comparison spans files and needs it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocatedFinding {
    pub file: String,
    pub rule: RuleId,
    pub severity: Severity,
    pub message: String,
    pub line: u32,
}

impl LocatedFinding {
    /// The identity used for before/after comparison — see the module docs
    /// for why the line number is not part of it.
    fn identity(&self) -> (String, String, String) {
        (
            self.file.clone(),
            self.rule.to_string(),
            self.message.clone(),
        )
    }

    pub fn describe(&self) -> String {
        format!(
            "{}:{} {} ({}) — {}",
            self.file, self.line, self.rule, self.severity, self.message
        )
    }
}

/// The analyzer's verdict on whether the task is finished.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Completion {
    /// The target issue (if one was named) is gone and nothing new appeared.
    Done,
    /// The task named a rule to remove and the analyzer still sees it.
    TargetRemains {
        rule: RuleId,
        occurrences: Vec<LocatedFinding>,
    },
    /// Findings that were not in the baseline are present now.
    Regressed { introduced: Vec<LocatedFinding> },
    /// A refactor task changed behaviour-bearing syntax — a constant, an
    /// operator, a new branch — that a pure refactor preserves.
    SemanticDrift { drift: SemanticDrift },
    /// A refactor task made some quality dimension worse than its tolerance
    /// allows, whatever it improved elsewhere.
    TradeOff {
        improved: Vec<DimensionChange>,
        degraded: Vec<DimensionChange>,
    },
}

impl Completion {
    pub fn is_done(&self) -> bool {
        matches!(self, Completion::Done)
    }

    /// The disagreement, written to be fed back to the model as the next
    /// user turn — this text is how "the analyzer is the judge" reaches the
    /// agent, so it names what is wrong rather than merely saying no.
    pub fn describe(&self) -> String {
        match self {
            Completion::Done => "the analyzer agrees the task is complete".to_string(),
            Completion::TargetRemains { rule, occurrences } => {
                let mut out =
                    format!("the analyzer still reports {rule}, so the task is not complete:\n");
                for finding in occurrences {
                    out.push_str(&format!("  - {}\n", finding.describe()));
                }
                out
            }
            Completion::Regressed { introduced } => {
                let mut out = format!(
                    "your changes introduced {} finding(s) that were not there before:\n",
                    introduced.len()
                );
                for finding in introduced {
                    out.push_str(&format!("  - {}\n", finding.describe()));
                }
                out
            }
            Completion::SemanticDrift { drift } => describe_drift(drift),
            Completion::TradeOff { improved, degraded } => describe_trade_off(improved, degraded),
        }
    }
}

fn describe_trade_off(improved: &[DimensionChange], degraded: &[DimensionChange]) -> String {
    let mut out = String::from(
        "this is a refactor task, and your changes made the codebase measurably worse \
         on at least one quality dimension:\n",
    );
    for change in degraded {
        out.push_str(&format!("  - {}\n", change.describe()));
    }
    if !improved.is_empty() {
        out.push_str("It did improve:\n");
        for change in improved {
            out.push_str(&format!("  - {}\n", change.describe()));
        }
    }
    out.push_str(
        "A local improvement that degrades the whole is not done. Find a shape \
         that improves without that cost, or revert the part that caused it.\n",
    );
    out
}

fn describe_drift(drift: &SemanticDrift) -> String {
    let mut out = String::from(
        "this is a refactor task, and your changes altered behaviour-bearing code \
         (a pure refactor moves, renames, extracts and inlines — it does not change \
         constants, operators or add branches):\n",
    );
    for atom in &drift.appeared {
        out.push_str(&format!("  - new: `{atom}`\n"));
    }
    for atom in &drift.vanished {
        out.push_str(&format!("  - gone: `{atom}`\n"));
    }
    for (atom, before, after) in &drift.added_control {
        out.push_str(&format!("  - more `{atom}`: {before} -> {after}\n"));
    }
    out.push_str(
        "Restore the original behaviour; a behaviour change belongs in a separate task.\n",
    );
    out
}

/// What the analyzer saw at one moment: the findings, plus — when a
/// [`RefactorGuard`] asked for them — the quality vector and the semantic
/// fingerprint of the scope. `None` means "not measured", never "zero".
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Snapshot {
    pub findings: Vec<LocatedFinding>,
    pub quality: Option<QualityVector>,
    pub semantics: Option<SemanticFingerprint>,
}

impl Snapshot {
    pub fn findings_only(findings: Vec<LocatedFinding>) -> Self {
        Self {
            findings,
            ..Self::default()
        }
    }
}

/// The extra bar a refactor task must clear on top of [`judge`]: behaviour
/// preserved and no quality dimension degraded past its tolerance.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RefactorGuard {
    pub tolerances: Tolerances,
    /// Reject semantic drift (see `vord_ast::SemanticFingerprint`).
    pub preserve_behaviour: bool,
}

/// The refactor guard needed a measurement the analyzer did not supply.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("the refactor guard needs {0}, which the analyzer did not produce")]
pub struct MissingMeasurement(&'static str);

/// [`judge`] plus the refactor guard. `Err` when the guard needed a
/// measurement the analyzer did not supply — "we could not check" must not
/// read as done.
pub fn judge_refactor(
    baseline: &Snapshot,
    current: &Snapshot,
    target: Option<&RuleId>,
    guard: &RefactorGuard,
) -> Result<Completion, MissingMeasurement> {
    let verdict = judge(&baseline.findings, &current.findings, target);
    if !verdict.is_done() {
        return Ok(verdict);
    }
    if guard.preserve_behaviour {
        let (Some(before), Some(after)) = (&baseline.semantics, &current.semantics) else {
            return Err(MissingMeasurement("a semantic fingerprint"));
        };
        let drift = before.drift(after);
        if !drift.is_empty() {
            return Ok(Completion::SemanticDrift { drift });
        }
    }
    let (Some(before), Some(after)) = (&baseline.quality, &current.quality) else {
        return Err(MissingMeasurement("a quality vector"));
    };
    let delta = quality::compare(before, after, &guard.tolerances);
    if delta.is_pareto_safe() {
        Ok(Completion::Done)
    } else {
        Ok(Completion::TradeOff {
            improved: delta.improved,
            degraded: delta.degraded,
        })
    }
}

fn counts(findings: &[LocatedFinding]) -> HashMap<(String, String, String), usize> {
    let mut counted = HashMap::new();
    for finding in findings {
        *counted.entry(finding.identity()).or_insert(0) += 1;
    }
    counted
}

/// Everything in `current` that the baseline did not already contain, as a
/// multiset difference.
fn introduced(baseline: &[LocatedFinding], current: &[LocatedFinding]) -> Vec<LocatedFinding> {
    let mut remaining = counts(baseline);
    let mut new = Vec::new();
    for finding in current {
        match remaining.get_mut(&finding.identity()) {
            Some(count) if *count > 0 => *count -= 1,
            _ => new.push(finding.clone()),
        }
    }
    new
}

/// Judges the task complete.
///
/// `target` is the rule the task set out to remove, when the task named one
/// (`vord agent run --fix <rule>`); a free-form task passes `None` and is
/// then judged on regressions alone. Regressions are checked *after* the
/// target, because an agent that removed the target by introducing something
/// worse should be told about the thing it introduced, and an agent that
/// never removed the target should be told that first.
pub fn judge(
    baseline: &[LocatedFinding],
    current: &[LocatedFinding],
    target: Option<&RuleId>,
) -> Completion {
    if let Some(rule) = target {
        let occurrences: Vec<LocatedFinding> = current
            .iter()
            .filter(|finding| finding.rule == *rule)
            .cloned()
            .collect();
        if !occurrences.is_empty() {
            return Completion::TargetRemains {
                rule: rule.clone(),
                occurrences,
            };
        }
    }

    let new = introduced(baseline, current);
    if new.is_empty() {
        Completion::Done
    } else {
        Completion::Regressed { introduced: new }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(raw: &str) -> RuleId {
        RuleId::new(raw).expect("valid rule id")
    }

    fn finding(file: &str, rule_id: &str, message: &str, line: u32) -> LocatedFinding {
        LocatedFinding {
            file: file.to_string(),
            rule: rule(rule_id),
            severity: Severity::Major,
            message: message.to_string(),
            line,
        }
    }

    #[test]
    fn an_unchanged_report_is_done() {
        let baseline = vec![finding("a.rs", "smells:long-method", "too long", 10)];
        assert_eq!(judge(&baseline, &baseline, None), Completion::Done);
    }

    #[test]
    fn removing_the_target_rule_is_done() {
        let baseline = vec![finding("a.rs", "owasp:xss", "unescaped", 3)];
        let target = rule("owasp:xss");
        assert_eq!(judge(&baseline, &[], Some(&target)), Completion::Done);
    }

    #[test]
    fn a_surviving_target_rule_is_not_done_and_names_where_it_survived() {
        let baseline = vec![finding("a.rs", "owasp:xss", "unescaped", 3)];
        let target = rule("owasp:xss");
        let verdict = judge(&baseline, &baseline, Some(&target));
        let Completion::TargetRemains { occurrences, .. } = &verdict else {
            panic!("expected the target to remain, got {verdict:?}");
        };
        assert_eq!(occurrences.len(), 1);
        assert!(verdict.describe().contains("a.rs:3"));
        assert!(!verdict.is_done());
    }

    #[test]
    fn a_pre_existing_finding_elsewhere_does_not_block_completion() {
        // The task was about `owasp:xss`; the long method was already there
        // and is not this task's problem.
        let baseline = vec![
            finding("a.rs", "owasp:xss", "unescaped", 3),
            finding("b.rs", "smells:long-method", "too long", 40),
        ];
        let current = vec![finding("b.rs", "smells:long-method", "too long", 40)];
        let target = rule("owasp:xss");
        assert_eq!(judge(&baseline, &current, Some(&target)), Completion::Done);
    }

    #[test]
    fn a_finding_that_only_moved_lines_is_not_a_regression() {
        let baseline = vec![finding("a.rs", "smells:long-method", "too long", 10)];
        let current = vec![finding("a.rs", "smells:long-method", "too long", 88)];
        assert_eq!(judge(&baseline, &current, None), Completion::Done);
    }

    #[test]
    fn a_new_finding_is_a_regression_that_names_itself() {
        let baseline = vec![];
        let current = vec![finding("a.rs", "owasp:eval-usage", "eval", 4)];
        let verdict = judge(&baseline, &current, None);
        let Completion::Regressed { introduced } = &verdict else {
            panic!("expected a regression, got {verdict:?}");
        };
        assert_eq!(introduced.len(), 1);
        assert!(verdict.describe().contains("owasp:eval-usage"));
    }

    #[test]
    fn a_second_copy_of_an_existing_finding_is_a_regression() {
        let baseline = vec![finding("a.rs", "smells:long-method", "too long", 10)];
        let current = vec![
            finding("a.rs", "smells:long-method", "too long", 10),
            finding("a.rs", "smells:long-method", "too long", 60),
        ];
        let Completion::Regressed { introduced } = judge(&baseline, &current, None) else {
            panic!("duplicating a finding must not read as unchanged");
        };
        assert_eq!(introduced.len(), 1);
    }

    #[test]
    fn the_same_rule_in_a_different_file_is_a_regression() {
        let baseline = vec![finding("a.rs", "owasp:xss", "unescaped", 3)];
        let current = vec![finding("b.rs", "owasp:xss", "unescaped", 3)];
        assert!(matches!(
            judge(&baseline, &current, None),
            Completion::Regressed { .. }
        ));
    }

    #[test]
    fn the_surviving_target_outranks_a_regression_in_the_report() {
        let baseline = vec![finding("a.rs", "owasp:xss", "unescaped", 3)];
        let current = vec![
            finding("a.rs", "owasp:xss", "unescaped", 3),
            finding("a.rs", "owasp:eval-usage", "eval", 9),
        ];
        let target = rule("owasp:xss");
        assert!(matches!(
            judge(&baseline, &current, Some(&target)),
            Completion::TargetRemains { .. }
        ));
    }

    #[test]
    fn a_done_verdict_says_so_in_words() {
        assert!(Completion::Done.describe().contains("agrees"));
        assert!(Completion::Done.is_done());
    }

    fn literal_tree(literal: &str) -> vord_ast::SemanticFingerprint {
        let span = vord_ast::Span::new(1, 1, 1, 1);
        let leaf = vord_ast::AstNode::new(vord_ast::NodeKind::StringLiteral, span, literal, vec![]);
        vord_ast::SemanticFingerprint::of(&leaf)
    }

    fn measured(literal: &str, health: i64) -> Snapshot {
        Snapshot {
            findings: Vec::new(),
            quality: Some(
                QualityVector::default().with(crate::quality::Dimension::HealthScore, health),
            ),
            semantics: Some(literal_tree(literal)),
        }
    }

    fn strict() -> RefactorGuard {
        RefactorGuard {
            preserve_behaviour: true,
            ..RefactorGuard::default()
        }
    }

    #[test]
    fn a_behaviour_preserving_refactor_that_holds_quality_is_done() {
        let verdict = judge_refactor(
            &measured("\"a\"", 90),
            &measured("\"a\"", 91),
            None,
            &strict(),
        );
        assert_eq!(verdict, Ok(Completion::Done));
    }

    #[test]
    fn semantic_drift_is_reported_before_any_trade_off() {
        let verdict = judge_refactor(
            &measured("\"a\"", 90),
            &measured("\"b\"", 80),
            None,
            &strict(),
        )
        .expect("measured on both sides");
        let Completion::SemanticDrift { drift } = &verdict else {
            panic!("expected drift, got {verdict:?}");
        };
        assert_eq!(drift.appeared, vec!["lit:\"b\"".to_string()]);
        assert!(verdict.describe().contains("behaviour"));
    }

    #[test]
    fn a_degraded_dimension_is_a_trade_off() {
        let verdict = judge_refactor(&measured("x", 90), &measured("x", 85), None, &strict())
            .expect("measured on both sides");
        assert!(
            matches!(verdict, Completion::TradeOff { .. }),
            "{verdict:?}"
        );
        assert!(verdict.describe().contains("health_score: 90 -> 85"));
    }

    #[test]
    fn a_finding_regression_is_still_reported_first() {
        let mut current = measured("x", 90);
        current
            .findings
            .push(finding("a.rs", "owasp:xss", "unescaped", 1));
        let verdict = judge_refactor(&measured("x", 90), &current, None, &strict());
        assert!(matches!(verdict, Ok(Completion::Regressed { .. })));
    }

    #[test]
    fn a_missing_fingerprint_is_an_error_not_a_pass() {
        let mut current = measured("x", 90);
        current.semantics = None;
        assert!(judge_refactor(&measured("x", 90), &current, None, &strict()).is_err());
    }
}
