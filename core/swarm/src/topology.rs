//! Topologies: an ordered pipeline of roles `vord swarm` drives automatically
//! (roadmap B4). B1–B3 gave a role everything it needs to run in isolation —
//! its own worktree, its own scoped policy, its own handoff channel — but
//! nothing decided *which roles, in what order*. This module is that
//! decision, and only that decision: given what `[swarm]` declared (a named
//! preset or an explicit role sequence) and which roles actually exist under
//! `[[swarm.role]]`, it resolves one validated, ordered role list. Creating
//! worktrees, running the agent and moving handoffs along that order is I/O
//! and lives in `bin/cli::swarm`, same split as [`crate::worktree`] and
//! [`crate::handoff`].

/// swarm-forge's smallest team shape: a coder and a reviewer.
pub const TWO_PACK: &[&str] = &["coder", "reviewer"];

/// swarm-forge's full team shape: architect designs, coder implements,
/// cleaner removes what the first pass left behind, QA has the last word.
pub const FOUR_PACK: &[&str] = &["architect", "coder", "cleaner", "qa"];

/// The Issue Triage Factory's team shape (roadmap C —
/// `docs/design/issue-triage-factory.md`): reproducer writes the failing
/// regression test, diagnostician maps it to a root cause, fixer drives
/// `core/remediation`'s verify-before-suggest loop against it. Names match
/// `vord_triage::TriageLabel::active_role` exactly — `core/triage` can't
/// depend on this crate to enforce that at compile time (it stays
/// dependency-free by design), so a test on each side pins the string.
pub const TRIAGE_PACK: &[&str] = &["reproducer", "diagnostician", "fixer"];

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TopologyError {
    /// Neither a named preset nor an explicit pipeline was configured.
    Unconfigured,
    /// `topology = "..."` named something that isn't `two-pack`/`four-pack`.
    UnknownPreset(String),
    /// `pipeline = []` — an empty sequence drives nothing.
    Empty,
    /// A role name in the resolved order has no matching `[[swarm.role]]`.
    UnknownRole(String),
    /// The same role named twice in one pipeline — a role cannot be two
    /// positions in the same run.
    DuplicateRole(String),
}

impl std::fmt::Display for TopologyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unconfigured => write!(
                f,
                "no topology configured — set [swarm] topology = \"two-pack\"/\"four-pack\"/\"triage-pack\" or pipeline = [...]"
            ),
            Self::UnknownPreset(name) => {
                write!(
                    f,
                    "unknown topology preset {name:?} — expected \"two-pack\", \"four-pack\" or \"triage-pack\""
                )
            }
            Self::Empty => write!(f, "pipeline is empty — a topology needs at least one role"),
            Self::UnknownRole(role) => {
                write!(
                    f,
                    "topology names role {role:?}, which has no [[swarm.role]] entry"
                )
            }
            Self::DuplicateRole(role) => {
                write!(f, "role {role:?} appears twice in the same topology")
            }
        }
    }
}

impl std::error::Error for TopologyError {}

fn preset_order(name: &str) -> Result<Vec<String>, TopologyError> {
    match name {
        "two-pack" => Ok(TWO_PACK.iter().map(|s| s.to_string()).collect()),
        "four-pack" => Ok(FOUR_PACK.iter().map(|s| s.to_string()).collect()),
        "triage-pack" => Ok(TRIAGE_PACK.iter().map(|s| s.to_string()).collect()),
        other => Err(TopologyError::UnknownPreset(other.to_string())),
    }
}

/// Resolves `[swarm]`'s `pipeline` (an explicit role-name sequence, if
/// present) or `topology` (a named preset, otherwise) into a validated,
/// ordered list of role names. An explicit `pipeline` always wins over a
/// named `topology` — the same "the specific setting outranks the general
/// one" convention `run_config` already uses for `vord agent`'s budget.
pub fn resolve_topology(
    preset: Option<&str>,
    pipeline: Option<&[String]>,
    configured_roles: &[String],
) -> Result<Vec<String>, TopologyError> {
    let order = match pipeline {
        Some(explicit) if !explicit.is_empty() => explicit.to_vec(),
        Some(_) => return Err(TopologyError::Empty),
        None => match preset {
            Some(name) => preset_order(name)?,
            None => return Err(TopologyError::Unconfigured),
        },
    };

    let mut seen = std::collections::HashSet::new();
    for role in &order {
        if !configured_roles.iter().any(|r| r == role) {
            return Err(TopologyError::UnknownRole(role.clone()));
        }
        if !seen.insert(role.as_str()) {
            return Err(TopologyError::DuplicateRole(role.clone()));
        }
    }
    Ok(order)
}

/// The role immediately after `current` in `order`, or `None` at the last
/// step — the boundary a pipeline runner uses to decide whether to send a
/// handoff at all.
pub fn next_role<'a>(order: &'a [String], current: &str) -> Option<&'a str> {
    let position = order.iter().position(|r| r == current)?;
    order.get(position + 1).map(String::as_str)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roles(names: &[&str]) -> Vec<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn the_two_pack_preset_resolves_to_coder_then_reviewer() {
        let order =
            resolve_topology(Some("two-pack"), None, &roles(&["coder", "reviewer"])).unwrap();
        assert_eq!(order, vec!["coder", "reviewer"]);
    }

    #[test]
    fn the_four_pack_preset_resolves_in_architect_coder_cleaner_qa_order() {
        let order = resolve_topology(
            Some("four-pack"),
            None,
            &roles(&["architect", "coder", "cleaner", "qa"]),
        )
        .unwrap();
        assert_eq!(order, vec!["architect", "coder", "cleaner", "qa"]);
    }

    #[test]
    fn the_triage_pack_preset_resolves_in_reproducer_diagnostician_fixer_order() {
        let order = resolve_topology(
            Some("triage-pack"),
            None,
            &roles(&["reproducer", "diagnostician", "fixer"]),
        )
        .unwrap();
        assert_eq!(order, vec!["reproducer", "diagnostician", "fixer"]);
    }

    #[test]
    fn the_triage_pack_role_names_match_vord_triage_active_role_exactly() {
        // core/triage can't depend on this crate to check this at compile
        // time (it stays dependency-free by design — see its module doc),
        // so this is the other half of that pin: TriageLabel::active_role
        // returns "reproducer"/"diagnostician"/"fixer" for its three worker
        // stages, and TRIAGE_PACK must name the same three roles in the
        // same order a pipeline runs them.
        assert_eq!(TRIAGE_PACK, &["reproducer", "diagnostician", "fixer"]);
    }

    #[test]
    fn an_unknown_preset_name_is_rejected() {
        let err = resolve_topology(Some("three-pack"), None, &roles(&["coder"])).unwrap_err();
        assert_eq!(err, TopologyError::UnknownPreset("three-pack".to_string()));
    }

    #[test]
    fn a_preset_naming_a_role_that_was_never_configured_is_rejected() {
        let err = resolve_topology(Some("two-pack"), None, &roles(&["coder"])).unwrap_err();
        assert_eq!(err, TopologyError::UnknownRole("reviewer".to_string()));
    }

    #[test]
    fn an_explicit_pipeline_outranks_a_named_preset() {
        let pipeline = roles(&["qa", "coder"]);
        let order =
            resolve_topology(Some("two-pack"), Some(&pipeline), &roles(&["qa", "coder"])).unwrap();
        assert_eq!(order, vec!["qa", "coder"]);
    }

    #[test]
    fn an_explicit_empty_pipeline_is_rejected_rather_than_falling_back_to_the_preset() {
        let empty: Vec<String> = Vec::new();
        let err = resolve_topology(
            Some("two-pack"),
            Some(&empty),
            &roles(&["coder", "reviewer"]),
        )
        .unwrap_err();
        assert_eq!(err, TopologyError::Empty);
    }

    #[test]
    fn a_role_named_twice_in_one_pipeline_is_rejected() {
        let pipeline = roles(&["coder", "coder"]);
        let err = resolve_topology(None, Some(&pipeline), &roles(&["coder"])).unwrap_err();
        assert_eq!(err, TopologyError::DuplicateRole("coder".to_string()));
    }

    #[test]
    fn nothing_configured_is_reported_rather_than_silently_resolving_to_nothing() {
        let err = resolve_topology(None, None, &roles(&["coder"])).unwrap_err();
        assert_eq!(err, TopologyError::Unconfigured);
    }

    #[test]
    fn next_role_walks_the_pipeline_and_stops_after_the_last_one() {
        let order = roles(&["architect", "coder", "qa"]);
        assert_eq!(next_role(&order, "architect"), Some("coder"));
        assert_eq!(next_role(&order, "coder"), Some("qa"));
        assert_eq!(next_role(&order, "qa"), None);
    }
}
