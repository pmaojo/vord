//! Profile "Copy": duplicate a profile's activations under a new name —
//! issue #22's copy operation. Pure core logic; the Postgres adapter is a
//! thin wrapper that reads the source, calls this, and persists the result
//! (see `infra/postgres/src/profile.rs::copy_quality_profile`).

use crate::QualityProfile;

/// Duplicates `source`'s *effective* rule activations (its own plus
/// whatever it inherits through its parent chain) into a brand-new,
/// standalone profile named `new_name` — no parent link, so later edits to
/// `source` (or any of its ancestors) never retroactively change the copy.
/// This matches the "Copy" semantics quality tools use: a snapshot, not a
/// subscription (that's what `with_parent` inheritance is for).
pub fn copy_profile(source: &QualityProfile, new_name: impl Into<String>) -> QualityProfile {
    QualityProfile::from_activations(new_name, source.effective_activations())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{RuleId, Severity};

    #[test]
    fn copy_has_new_name_and_same_effective_activations() {
        let rule = RuleId::new("owasp:eval-usage").unwrap();
        let mut source = QualityProfile::new("original");
        source.activate(rule.clone(), Severity::Critical);

        let copy = copy_profile(&source, "duplicate");

        assert_eq!(copy.name(), "duplicate");
        assert_eq!(copy.severity_of(&rule), Some(Severity::Critical));
    }

    #[test]
    fn copy_flattens_inherited_activations_and_drops_the_parent_link() {
        let base_rule = RuleId::new("owasp:eval-usage").unwrap();
        let mut parent = QualityProfile::new("parent");
        parent.activate(base_rule.clone(), Severity::Critical);
        let child = QualityProfile::new("child").with_parent(parent);

        let copy = copy_profile(&child, "child-copy");

        // The inherited rule became an *own* activation on the copy...
        assert_eq!(copy.own_activations().count(), 1);
        assert_eq!(copy.severity_of(&base_rule), Some(Severity::Critical));
        // ...and the copy has no parent of its own.
        assert!(copy.parent().is_none());
    }

    #[test]
    fn editing_the_source_after_copying_does_not_affect_the_copy() {
        let rule = RuleId::new("owasp:eval-usage").unwrap();
        let mut source = QualityProfile::new("original");
        source.activate(rule.clone(), Severity::Major);

        let copy = copy_profile(&source, "duplicate");
        source.activate(rule.clone(), Severity::Blocker);

        assert_eq!(copy.severity_of(&rule), Some(Severity::Major));
        assert_eq!(source.severity_of(&rule), Some(Severity::Blocker));
    }
}
