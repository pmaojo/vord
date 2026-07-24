//! Profile backup/restore — issue #22's "export to a portable format and
//! reimport it, including on a different yunq instance" operation.
//!
//! [`ProfileBackup`] is the portable snapshot: name, own (non-inherited)
//! activations, and the parent's name if any. It's deliberately serde-free,
//! like the rest of this crate (see the module docs on
//! `infra/postgres::gate`'s `NewCodeDefinition` encoding for the same
//! split) — turning it into JSON for upload/download is an edge concern
//! that belongs to `bin/server`, not the pure domain type.
//!
//! Restoring is a pure decision function: given the backup, whatever
//! same-named profile (if any) already exists on the target instance, the
//! resolved parent (if any — the adapter looks it up by name on *this*
//! instance, since a cross-instance parent may not exist there), and a
//! collision policy, decide whether to proceed and build the resulting
//! `QualityProfile`. The adapter does the I/O (read the existing profile
//! and the parent, then persist the result); this function only decides.

use crate::{QualityProfile, RuleId, Severity};

/// Portable snapshot of a profile, ready to serialize (JSON, at the edge)
/// or hand straight to [`restore`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProfileBackup {
    pub name: String,
    /// The parent profile's name, if this profile inherits from one.
    /// Restoring on an instance that doesn't have a same-named profile
    /// leaves the restored profile parentless rather than failing — see
    /// [`restore`].
    pub parent_name: Option<String>,
    /// This profile's own activations (not its inherited ones — same
    /// convention as `QualityProfile::own_activations`), sorted by rule id
    /// for a deterministic, diff-friendly serialization.
    pub activations: Vec<(RuleId, Severity)>,
}

/// Snapshots `profile` into its portable backup form.
pub fn backup(profile: &QualityProfile) -> ProfileBackup {
    let mut activations: Vec<(RuleId, Severity)> =
        profile.own_activations().map(|(rule, severity)| (rule.clone(), severity)).collect();
    activations.sort_by(|(a, _), (b, _)| a.as_str().cmp(b.as_str()));
    ProfileBackup {
        name: profile.name().to_string(),
        parent_name: profile.parent().map(|parent| parent.name().to_string()),
        activations,
    }
}

/// What to do when restoring a backup whose name collides with a profile
/// that already exists on the target instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RestorePolicy {
    /// Refuse the restore — the safe default. The caller must rename the
    /// backup or explicitly opt into `Overwrite`.
    Reject,
    /// Replace the existing profile's activations with the backup's.
    Overwrite,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RestoreError {
    #[error(
        "a profile named {0:?} already exists on this instance; restore with force/overwrite to replace it"
    )]
    NameCollision(String),
}

/// Rebuilds a `QualityProfile` from `backup`.
///
/// - `existing`: the caller's lookup of a same-named profile already on
///   this instance, or `None` if the name is free. Ignored under
///   `RestorePolicy::Overwrite`; causes `RestoreError::NameCollision` under
///   `RestorePolicy::Reject`.
/// - `parent`: the caller's resolution of `backup.parent_name` on *this*
///   instance (`None` if the backup has no parent, or if it does but this
///   instance has nothing by that name) — restoring across instances that
///   don't share the parent profile still succeeds, just without the
///   inherited rules, rather than failing the whole restore.
pub fn restore(
    backup: &ProfileBackup,
    existing: Option<&QualityProfile>,
    parent: Option<QualityProfile>,
    policy: RestorePolicy,
) -> Result<QualityProfile, RestoreError> {
    if existing.is_some() && policy == RestorePolicy::Reject {
        return Err(RestoreError::NameCollision(backup.name.clone()));
    }
    let mut restored =
        QualityProfile::from_activations(backup.name.clone(), backup.activations.clone());
    if let Some(parent) = parent {
        restored = restored.with_parent(parent);
    }
    Ok(restored)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(raw: &str) -> RuleId {
        RuleId::new(raw).unwrap()
    }

    #[test]
    fn backup_only_captures_own_activations_and_parent_name() {
        let mut parent = QualityProfile::new("company-way");
        parent.activate(rule("owasp:eval-usage"), Severity::Critical);
        let mut child = QualityProfile::new("team-way").with_parent(parent);
        child.activate(rule("smells:todo-comment"), Severity::Info);

        let snapshot = backup(&child);

        assert_eq!(snapshot.name, "team-way");
        assert_eq!(snapshot.parent_name, Some("company-way".to_string()));
        assert_eq!(snapshot.activations, vec![(rule("smells:todo-comment"), Severity::Info)]);
    }

    #[test]
    fn restore_roundtrips_a_backup_with_no_collision() {
        let mut original = QualityProfile::new("team-way");
        original.activate(rule("owasp:eval-usage"), Severity::Critical);
        let snapshot = backup(&original);

        let restored = restore(&snapshot, None, None, RestorePolicy::Reject).unwrap();

        assert_eq!(restored.name(), "team-way");
        assert_eq!(restored.severity_of(&rule("owasp:eval-usage")), Some(Severity::Critical));
    }

    #[test]
    fn restore_rejects_a_name_collision_by_default() {
        let mut original = QualityProfile::new("team-way");
        original.activate(rule("owasp:eval-usage"), Severity::Critical);
        let snapshot = backup(&original);

        let existing = QualityProfile::new("team-way");
        let err = restore(&snapshot, Some(&existing), None, RestorePolicy::Reject).unwrap_err();

        assert_eq!(err, RestoreError::NameCollision("team-way".to_string()));
    }

    #[test]
    fn restore_overwrites_when_forced() {
        let mut original = QualityProfile::new("team-way");
        original.activate(rule("owasp:eval-usage"), Severity::Blocker);
        let snapshot = backup(&original);

        let existing = QualityProfile::new("team-way");
        let restored = restore(&snapshot, Some(&existing), None, RestorePolicy::Overwrite).unwrap();

        assert_eq!(restored.severity_of(&rule("owasp:eval-usage")), Some(Severity::Blocker));
    }

    #[test]
    fn restore_reattaches_a_parent_resolved_on_the_target_instance() {
        let mut parent = QualityProfile::new("company-way");
        parent.activate(rule("owasp:eval-usage"), Severity::Critical);
        let mut child = QualityProfile::new("team-way").with_parent(parent.clone());
        child.activate(rule("smells:todo-comment"), Severity::Info);
        let snapshot = backup(&child);

        let restored = restore(&snapshot, None, Some(parent), RestorePolicy::Reject).unwrap();

        // Own activation present, and the inherited one resolves through
        // the reattached parent.
        assert_eq!(restored.severity_of(&rule("smells:todo-comment")), Some(Severity::Info));
        assert_eq!(restored.severity_of(&rule("owasp:eval-usage")), Some(Severity::Critical));
    }

    #[test]
    fn restore_succeeds_parentless_when_the_parent_is_missing_on_this_instance() {
        let snapshot = ProfileBackup {
            name: "team-way".to_string(),
            parent_name: Some("company-way".to_string()),
            activations: vec![(rule("smells:todo-comment"), Severity::Info)],
        };

        // The adapter looked for "company-way" on this instance, didn't
        // find it, and passes `None` — restore still succeeds.
        let restored = restore(&snapshot, None, None, RestorePolicy::Reject).unwrap();

        assert!(restored.parent().is_none());
        assert_eq!(restored.severity_of(&rule("smells:todo-comment")), Some(Severity::Info));
    }
}
