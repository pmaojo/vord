//! Per-project and per-branch New Code overrides. ROADMAP §Phase 3 — "New
//! Code definition: previous version / N days / reference branch /
//! specific analysis — per project and per branch".
//!
//! Two layers: a pure resolver (`resolve_new_code_definition`) that picks
//! the most-specific override for a `(project, branch)` out of whatever
//! `OverrideSource`s are configured, and `resolve_baseline`, which turns
//! the winning override into a real `Baseline` via the `AnalysisHistoryReader`
//! port — storing/administering `OverrideSource`s themselves (the HTTP layer)
//! is a separate, not-yet-built piece.

use serde::{Deserialize, Serialize};

use crate::new_code::Baseline;
use crate::ports::{AnalysisHistoryReader, StorageError};

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

/// Resolves `override_value` to a real `Baseline` by looking up the analysis
/// it refers to through `reader` (whichever `AnalysisHistoryReader` the
/// composition root wired up — Postgres in production) and rebuilding that
/// analysis' issue fingerprints:
///   - `ReferenceBranch(b)` → the latest analysis on branch `b`.
///   - `Days(n)` → the analysis closest to (at or before) `n` days ago on
///     `branch_name`.
///   - `SpecificAnalysis(id)` → the analysis `id` parses to.
///
/// Falls back to an empty `Baseline` (nothing pre-existing — every issue
/// counts as new code) when the override points at an analysis that doesn't
/// exist: a reference branch that hasn't been scanned yet, a `Days` window
/// before the project's first scan, or a malformed/unknown `SpecificAnalysis`
/// id. That mirrors how a project's very first analysis has no prior
/// baseline either — it is not an error condition.
pub async fn resolve_baseline<R: AnalysisHistoryReader>(
    reader: &R,
    project_key: &str,
    branch_name: &str,
    override_value: &NewCodeOverride,
) -> Result<Baseline, StorageError> {
    let analysis_id = match override_value {
        NewCodeOverride::ReferenceBranch(branch) => {
            reader.latest_analysis_id_on_branch(project_key, branch).await?
        }
        NewCodeOverride::Days(days) => {
            reader.analysis_id_days_ago(project_key, branch_name, *days).await?
        }
        NewCodeOverride::SpecificAnalysis(id) => id.parse::<i64>().ok(),
    };
    match analysis_id {
        Some(id) => reader.baseline_for_analysis(id).await,
        None => Ok(Baseline::default()),
    }
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
        let (val, src_back) = resolve_new_code_definition(std::slice::from_ref(&src), "yunq", "main").unwrap();
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

    /// In-memory stand-in for the Postgres-backed `AnalysisHistoryReader` —
    /// exercises `resolve_baseline`'s branching without a database.
    #[derive(Default)]
    struct FakeAnalysisHistory {
        /// `(project_key, branch)` -> latest analysis id.
        latest: std::collections::HashMap<(String, String), i64>,
        /// `(project_key, branch, days_ago)` -> analysis id.
        days_ago: std::collections::HashMap<(String, String, u32), i64>,
        /// analysis id -> the baseline it produced.
        baselines: std::collections::HashMap<i64, Baseline>,
    }

    impl AnalysisHistoryReader for FakeAnalysisHistory {
        async fn latest_analysis_id_on_branch(
            &self,
            project_key: &str,
            branch: &str,
        ) -> Result<Option<i64>, StorageError> {
            Ok(self.latest.get(&(project_key.to_string(), branch.to_string())).copied())
        }

        async fn analysis_id_days_ago(
            &self,
            project_key: &str,
            branch: &str,
            days_ago: u32,
        ) -> Result<Option<i64>, StorageError> {
            Ok(self
                .days_ago
                .get(&(project_key.to_string(), branch.to_string(), days_ago))
                .copied())
        }

        async fn baseline_for_analysis(&self, analysis_id: i64) -> Result<Baseline, StorageError> {
            self.baselines
                .get(&analysis_id)
                .cloned()
                .ok_or_else(|| StorageError(format!("no such analysis {analysis_id}")))
        }
    }

    fn baseline_with_fingerprint(fp: u64) -> Baseline {
        Baseline::from_fingerprints([fp])
    }

    #[test]
    fn resolve_baseline_follows_reference_branch_to_its_latest_analysis() {
        let mut history = FakeAnalysisHistory::default();
        history.latest.insert(("yunq".to_string(), "develop".to_string()), 42);
        history.baselines.insert(42, baseline_with_fingerprint(7));

        let resolved = futures::executor::block_on(resolve_baseline(
            &history,
            "yunq",
            "main",
            &NewCodeOverride::ReferenceBranch("develop".to_string()),
        ))
        .unwrap();
        assert_eq!(resolved.fingerprints().collect::<Vec<_>>(), vec![7]);
    }

    #[test]
    fn resolve_baseline_looks_up_days_ago_on_the_requested_branch() {
        let mut history = FakeAnalysisHistory::default();
        history.days_ago.insert(("yunq".to_string(), "main".to_string(), 7), 9);
        history.baselines.insert(9, baseline_with_fingerprint(99));

        let resolved = futures::executor::block_on(resolve_baseline(
            &history,
            "yunq",
            "main",
            &NewCodeOverride::Days(7),
        ))
        .unwrap();
        assert_eq!(resolved.fingerprints().collect::<Vec<_>>(), vec![99]);
    }

    #[test]
    fn resolve_baseline_parses_specific_analysis_id() {
        let mut history = FakeAnalysisHistory::default();
        history.baselines.insert(123, baseline_with_fingerprint(1));

        let resolved = futures::executor::block_on(resolve_baseline(
            &history,
            "yunq",
            "main",
            &NewCodeOverride::SpecificAnalysis("123".to_string()),
        ))
        .unwrap();
        assert_eq!(resolved.fingerprints().collect::<Vec<_>>(), vec![1]);
    }

    #[test]
    fn resolve_baseline_falls_back_to_empty_when_reference_branch_never_analyzed() {
        let history = FakeAnalysisHistory::default();
        let resolved = futures::executor::block_on(resolve_baseline(
            &history,
            "yunq",
            "main",
            &NewCodeOverride::ReferenceBranch("never-scanned".to_string()),
        ))
        .unwrap();
        assert!(resolved.is_empty());
    }

    #[test]
    fn resolve_baseline_falls_back_to_empty_for_a_malformed_specific_analysis_id() {
        let history = FakeAnalysisHistory::default();
        let resolved = futures::executor::block_on(resolve_baseline(
            &history,
            "yunq",
            "main",
            &NewCodeOverride::SpecificAnalysis("not-a-number".to_string()),
        ))
        .unwrap();
        assert!(resolved.is_empty());
    }

    #[test]
    fn override_scope_serializes_with_kind_tag() {
        let s = OverrideScope::Project { project_key: "yunq".to_string() };
        let json = serde_json::to_string(&s).unwrap();
        assert!(json.contains("\"project\""));
        assert!(json.contains("yunq"));
    }
}
