//! Compares two quality profiles' *effective* (inheritance-resolved) rule
//! activations — the "Compare profiles" operation from issue #22: which
//! rules are active in one but not the other, and where a shared rule's
//! severity differs. Pure and DB-free; the two profiles are already
//! in-memory `QualityProfile` values, wherever they came from.

use std::collections::HashMap;

use crate::{QualityProfile, RuleId, Severity};

/// A rule active in both profiles but at a different severity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SeverityDifference {
    pub rule: RuleId,
    pub severity_in_a: Severity,
    pub severity_in_b: Severity,
}

/// The result of comparing profile `a` against profile `b`. Every list is
/// sorted by rule id for deterministic output — callers rendering a diff
/// (or asserting on one in a test) shouldn't have to re-sort a hash map's
/// arbitrary iteration order themselves.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ProfileDiff {
    /// Active in `a`, inactive in `b`.
    pub only_in_a: Vec<(RuleId, Severity)>,
    /// Active in `b`, inactive in `a`.
    pub only_in_b: Vec<(RuleId, Severity)>,
    /// Active in both, at different severities.
    pub severity_differs: Vec<SeverityDifference>,
}

impl ProfileDiff {
    /// True when the two profiles are activation-equivalent (same rules,
    /// same severities) — inheritance structure and profile name aside.
    pub fn is_empty(&self) -> bool {
        self.only_in_a.is_empty() && self.only_in_b.is_empty() && self.severity_differs.is_empty()
    }
}

fn sorted(mut entries: Vec<(RuleId, Severity)>) -> Vec<(RuleId, Severity)> {
    entries.sort_by(|(a, _), (b, _)| a.as_str().cmp(b.as_str()));
    entries
}

/// Compares `a` and `b`'s effective activations (each profile's own rules
/// plus whatever it inherits, exactly what an analyzer run would use).
pub fn compare(a: &QualityProfile, b: &QualityProfile) -> ProfileDiff {
    let effective_a: HashMap<RuleId, Severity> = a.effective_activations();
    let effective_b: HashMap<RuleId, Severity> = b.effective_activations();

    let only_in_a = sorted(
        effective_a
            .iter()
            .filter(|(rule, _)| !effective_b.contains_key(*rule))
            .map(|(rule, severity)| (rule.clone(), *severity))
            .collect(),
    );
    let only_in_b = sorted(
        effective_b
            .iter()
            .filter(|(rule, _)| !effective_a.contains_key(*rule))
            .map(|(rule, severity)| (rule.clone(), *severity))
            .collect(),
    );
    let mut severity_differs: Vec<SeverityDifference> = effective_a
        .iter()
        .filter_map(|(rule, severity_a)| {
            let severity_b = effective_b.get(rule)?;
            (severity_a != severity_b).then(|| SeverityDifference {
                rule: rule.clone(),
                severity_in_a: *severity_a,
                severity_in_b: *severity_b,
            })
        })
        .collect();
    severity_differs.sort_by(|x, y| x.rule.as_str().cmp(y.rule.as_str()));

    ProfileDiff { only_in_a, only_in_b, severity_differs }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RuleId as Rid;

    fn rule(raw: &str) -> RuleId {
        Rid::new(raw).unwrap()
    }

    #[test]
    fn identical_profiles_diff_to_empty() {
        let mut a = QualityProfile::new("a");
        a.activate(rule("owasp:eval-usage"), Severity::Critical);
        let mut b = QualityProfile::new("b");
        b.activate(rule("owasp:eval-usage"), Severity::Critical);

        let diff = compare(&a, &b);
        assert!(diff.is_empty());
    }

    #[test]
    fn detects_rules_only_active_on_one_side() {
        let mut a = QualityProfile::new("a");
        a.activate(rule("owasp:eval-usage"), Severity::Critical);
        a.activate(rule("smells:todo-comment"), Severity::Info);
        let mut b = QualityProfile::new("b");
        b.activate(rule("owasp:eval-usage"), Severity::Critical);
        b.activate(rule("rust:mem-forget"), Severity::Major);

        let diff = compare(&a, &b);
        assert_eq!(diff.only_in_a, vec![(rule("smells:todo-comment"), Severity::Info)]);
        assert_eq!(diff.only_in_b, vec![(rule("rust:mem-forget"), Severity::Major)]);
        assert!(diff.severity_differs.is_empty());
    }

    #[test]
    fn detects_severity_differences_on_shared_rules() {
        let mut a = QualityProfile::new("a");
        a.activate(rule("owasp:eval-usage"), Severity::Critical);
        let mut b = QualityProfile::new("b");
        b.activate(rule("owasp:eval-usage"), Severity::Blocker);

        let diff = compare(&a, &b);
        assert_eq!(
            diff.severity_differs,
            vec![SeverityDifference {
                rule: rule("owasp:eval-usage"),
                severity_in_a: Severity::Critical,
                severity_in_b: Severity::Blocker,
            }]
        );
    }

    #[test]
    fn compares_effective_activations_including_inherited_rules() {
        let mut parent = QualityProfile::new("parent");
        parent.activate(rule("owasp:eval-usage"), Severity::Critical);
        let child = QualityProfile::new("child").with_parent(parent);

        let mut other = QualityProfile::new("other");
        other.activate(rule("owasp:eval-usage"), Severity::Critical);

        // `child` has no *own* activations, but inherits the same rule at
        // the same severity as `other` — the diff must see through that.
        assert!(compare(&child, &other).is_empty());
    }
}
