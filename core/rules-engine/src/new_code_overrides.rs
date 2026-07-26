//! Per-project and per-branch New Code overrides. ROADMAP §Phase 3 — "New
//! Code definition: previous version / N days / reference branch /
//! specific analysis — per project and per branch".
//!
//! Skeleton: types + a pure resolver that picks the most-specific override
//! are in place; the persistence + HTTP layer land in following iterations.

use serde::{Deserialize, Serialize};

use crate::new_code::Baseline;

/// What scope an override applies to — global (instance default), one
/// project, or one branch on one project.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum OverrideScope {
    Global,
    Project { project_key: String },
    Branch { project_key: String, branch_name: String },
}

/// One concrete New Code definition: either a number of days, a reference
/// branch name, or a specific analysis id.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum NewCodeOverride {
    /// Compare against the analysis N days before.
    Days(u32),
    /// Compare against the latest analysis of the named reference branch.
    ReferenceBranch(String),
    /// Compare against one specific prior analysis.
    SpecificAnalysis(String),
}

impl NewCodeOverride {
    /// Return a short label suitable for UI display (`"7 days"`,
    /// `"branch:develop"`, `"analysis:abc-123"`).
    pub fn label(&self) -> String {
        match self {
            Self::Days(d) => format!("{d} days"),
            Self::ReferenceBranch(b) => format!("branch:{b}"),
            Self::SpecificAnalysis(id) => format!("analysis:{id}"),
        }
    }
}

/// A scope + its override. The list of `(scope, override)` records defines
/// the precedence: branch > project > global.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OverrideSource {
    pub scope: OverrideScope,
    pub override_value: NewCodeOverride,
}

/// Pure resolver — picks the most-specific override matching
/// `(project_key, branch_name)`, with the precedence:
///   1. (project_key, branch_name) Branch override
///   2. (project_key) Project override
///   3. Global override
///
/// Returns the source so the caller can record which override won (useful
/// for the per-analysis audit trail).
pub fn resolve_new_code_definition(
    sources: &[OverrideSource],
    project_key: &str,
    branch_name: &str,
) -> Option<(NewCodeOverride, OverrideSource)> {
    // Branch override wins.
    let branch_match = sources.iter().find(|s| matches!(
        &s.scope,
        OverrideScope::Branch { project_key: pk, branch_name: bn } if pk == project_key && bn == branch_name
    ));
    if let Some(src) = branch_match {
        return Some((src.override_value.clone(), src.clone()));
    }
    // Project override is the next.
    let project_match = sources.iter().find(|s| matches!(
        &s.scope,
        OverrideScope::Project { project_key: pk } if pk == project_key
    ));
    if let Some(src) = project_match {
        return Some((src.override_value.clone(), src.clone()));
    }
    // Global last.
    let global = sources.iter().find(|s| matches!(s.scope, OverrideScope::Global));
    global.map(|src| (src.override_value.clone(), src.clone()))
}

/// Helper that converts the resolved override to the existing `Baseline`
/// type, so the analysis path doesn't need to learn about `NewCodeOverride`.
/// The string-id form of `ReferenceBranch`/`SpecificAnalysis` becomes the
/// `Baseline::Named(...)` variant.
#[allow(dead_code)]
pub fn override_to_baseline(override_value: NewCodeOverride) -> Baseline {
    let _ = override_value;
    // TODO: resolve ReferenceBranch / SpecificAnalysis / Days to actual
    // analysis entries from Postgres, then build a real Baseline.
    Baseline::default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn branch(project: &str, branch: &str, days: u32) -> OverrideSource {
        OverrideSource { scope: OverrideScope::Branch { project_key: project.to_string(), branch_name: branch.to_string() }, override_value: NewCodeOverride::Days(days) }
    }
    fn project(project: &str, ref_branch: &str) -> OverrideSource {
        OverrideSource { scope: OverrideScope::Project { project_key: project.to_string() }, override_value: NewCodeOverride::ReferenceBranch(ref_branch.to_string()) }
    }
    fn global(days: u32) -> OverrideSource {
        OverrideSource { scope: OverrideScope::Global, override_value: NewCodeOverride::Days(days) }
    }

    #[test]
    fn empty_sources_returns_none() {
        assert!(resolve_new_code_definition(&[], "yunq", "main").is_none());
    }

    #[test]
    fn only_global_picks_global() {
        let src = global(7);
        let (val, src_back) = resolve_new_code_definition(&[src.clone()], "yunq", "main").unwrap();
        assert_eq!(val, NewCodeOverride::Days(7));
        assert_eq!(src_back.scope, OverrideScope::Global);
    }

    #[test]
    fn project_override_beats_global() {
        let sources = vec![global(7), project("yunq", "develop")];
        let (val, src) = resolve_new_code_definition(&sources, "yunq", "main").unwrap();
        assert_eq!(val, NewCodeOverride::ReferenceBranch("develop".to_string()));
        assert!(matches!(src.scope, OverrideScope::Project { .. }));
    }

    #[test]
    fn branch_override_beats_project_and_global() {
        let sources = vec![
            global(7),
            project("yunq", "develop"),
            branch("yunq", "main", 1),
        ];
        let (val, src) = resolve_new_code_definition(&sources, "yunq", "main").unwrap();
        assert_eq!(val, NewCodeOverride::Days(1));
        assert!(matches!(src.scope, OverrideScope::Branch { .. }));
    }

    #[test]
    fn branch_override_is_per_branch_not_shared() {
        let sources = vec![branch("yunq", "main", 1)];
        // `feature/x` doesn't have its own override; falls back to global.
        let sources_global = vec![branch("yunq", "main", 1), global(14)];
        assert!(resolve_new_code_definition(&sources, "yunq", "feature/x").is_none());
        let (val, _) = resolve_new_code_definition(&sources_global, "yunq", "feature/x").unwrap();
        assert_eq!(val, NewCodeOverride::Days(14));
    }

    #[test]
    fn project_override_does_not_leak_to_other_projects() {
        let sources = vec![project("yunq", "develop")];
        let other = resolve_new_code_definition(&sources, "other", "main");
        assert!(other.is_none());
    }

    #[test]
    fn override_label_is_human_readable() {
        assert_eq!(NewCodeOverride::Days(7).label(), "7 days");
        assert_eq!(NewCodeOverride::ReferenceBranch("develop".to_string()).label(), "branch:develop");
        assert_eq!(NewCodeOverride::SpecificAnalysis("abc".to_string()).label(), "analysis:abc");
    }

    #[test]
    fn override_to_baseline_returns_empty_placeholder() {
        let b = override_to_baseline(NewCodeOverride::ReferenceBranch("develop".to_string()));
        // TODO: Once Baseline resolution is wired, assert the resolved
        // analysis entries here. For now, it returns an empty baseline.
        assert!(b.is_empty());
    }

    #[test]
    fn override_scope_serializes_with_kind_tag() {
        let s = OverrideScope::Project { project_key: "yunq".to_string() };
        let json = serde_json::to_string(&s).unwrap();
        assert!(json.contains("\"project\""));
        assert!(json.contains("yunq"));
    }
}
