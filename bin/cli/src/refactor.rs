//! `vord refactor` — continuous refactoring, one bounded batch at a time.
//!
//! `plan` ranks what is worth refactoring (`vord_agent::plan`) from the
//! repository's own complexity, coverage, import graph and git history.
//! `run` takes the top candidates the plan allows to be attempted
//! autonomously and drives one `vord agent run --refactor` per candidate:
//! each must keep behaviour, keep every quality dimension within tolerance
//! and add no finding, or it is not done. A scheduled CI job running
//! `vord refactor run` and opening a pull request with whatever landed is
//! the whole loop (see `ci-templates/`).

use std::collections::BTreeSet;
use std::path::Path;

use vord_agent::plan::{self, Autonomy, Candidate, FunctionRisk, Plan, PlanInput};
use vord_agent::runtime::Analyzer;
use vord_agent::{QualityDelta, RunOutcome, Tolerances};
use vord_infra_fs::VordConfig;

use crate::agent::{self, AgentArgs, RepoAnalyzer};
use crate::history;

/// What `vord refactor plan` was asked for.
pub struct PlanArgs {
    /// Only candidates under this repository-relative path (`.` for all).
    pub scope: String,
    /// Days of git history to mine.
    pub since_days: u32,
    /// An LCOV report, to rank by CRAP and to tier autonomy by coverage.
    pub lcov: Option<std::path::PathBuf>,
}

/// Builds the plan for the repository at `root` (its git top level).
pub async fn build_plan(root: &Path, args: &PlanArgs) -> anyhow::Result<Plan> {
    let config = VordConfig::load_from_dir(root);
    let mut report = RepoAnalyzer::new(root, config.as_ref())
        .report(".")
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    if let Some(path) = &args.lcov {
        let raw = tokio::fs::read_to_string(path)
            .await
            .map_err(|e| anyhow::anyhow!("cannot read {}: {e}", path.display()))?;
        report.set_coverage_report(vord_infra_fs::parse_lcov_report(&raw)?);
    }
    let history = history::read_history(root, args.since_days)?;
    let graph = vord_infra_fs::build_dependency_graph(root)?;

    let input = PlanInput {
        functions: function_risks(&report),
        history: history.files,
        // Lockfiles, manifests and docs co-change with everything by
        // nature; coupling between them is bookkeeping, not design.
        co_changes: history
            .co_changes
            .into_iter()
            .filter(|((a, b), _)| is_source(a) && is_source(b))
            .collect(),
        imports: graph
            .graph
            .edges()
            .iter()
            .map(|edge| (edge.from.clone(), edge.to.clone()))
            .collect::<BTreeSet<_>>(),
    };
    let mut plan = plan::plan(&input);
    if args.scope != "." {
        let prefix = args.scope.trim_end_matches('/');
        plan.candidates.retain(|c| c.path.starts_with(prefix));
    }
    Ok(plan)
}

fn is_source(path: &str) -> bool {
    Path::new(path)
        .extension()
        .and_then(|e| e.to_str())
        .and_then(vord_ast::LanguageIdentifier::from_extension)
        .is_some()
}

fn function_risks(report: &vord_rules_engine::AnalysisReport) -> Vec<FunctionRisk> {
    let coverage = report.coverage_report();
    report
        .function_complexities()
        .iter()
        .map(|f| {
            let covered = coverage
                .and_then(|c| c.files().iter().find(|file| file.path() == f.path))
                .and_then(|file| vord_crap::coverage_in_span(file.lines(), f.span));
            FunctionRisk {
                path: f.path.clone(),
                line: f.span.start_line,
                cyclomatic: f.cyclomatic,
                coverage: covered,
                crap: covered.map(|c| vord_crap::crap_score(f.cyclomatic, c)),
            }
        })
        .collect()
}

/// Human-readable plan: one line per candidate, then any hidden coupling.
pub fn render_text(plan: &Plan, limit: usize) -> String {
    let mut out = String::new();
    if plan.candidates.is_empty() {
        out.push_str("No refactor candidates: nothing exceeds the complexity or CRAP threshold.\n");
    }
    for (rank, c) in plan.candidates.iter().take(limit).enumerate() {
        out.push_str(&format!(
            "{:>2}. [{}] {}:{}  score {:.0}\n      {}\n",
            rank + 1,
            c.autonomy.as_str(),
            c.path,
            c.line,
            c.score,
            c.rationale
        ));
    }
    if !plan.temporal_couplings.is_empty() {
        out.push_str("\nHidden temporal coupling (change together, no import between them):\n");
        for t in plan.temporal_couplings.iter().take(limit) {
            out.push_str(&format!(
                "  {} <-> {}  ({} commits)\n",
                t.a, t.b, t.co_changes
            ));
        }
    }
    out
}

/// The task one refactor run is given.
pub fn task_for(candidate: &Candidate) -> String {
    format!(
        "Refactor the function starting at {}:{} to reduce its complexity \
         (cyclomatic {}) without changing its behaviour. Move, rename, extract \
         and inline only: do not change constants, operators or add branches. \
         Keep the change small and local; do not split it across new modules \
         unless coupling stays the same. Why this function: {}.",
        candidate.path, candidate.line, candidate.cyclomatic, candidate.rationale
    )
}

/// One attempted candidate, how its run ended, and — when both snapshots
/// could be taken — what it did to every quality dimension.
pub struct Attempt<'a> {
    pub candidate: &'a Candidate,
    pub outcome: RunOutcome,
    pub delta: Option<QualityDelta>,
}

/// Runs `vord agent run --refactor` on up to `limit` candidates whose tier is
/// at most `max_autonomy` — `Escalate` candidates are never attempted, since
/// escalation means "a human decides first". Stops early when a run fails
/// (vord or the model broke), because the next attempt would fail the same
/// way and spend budget doing it.
pub async fn run<'p>(
    root: &Path,
    plan: &'p Plan,
    limit: usize,
    max_autonomy: Autonomy,
    model: Option<String>,
) -> anyhow::Result<Vec<Attempt<'p>>> {
    let ceiling = max_autonomy.min(Autonomy::Review);
    let analyzer = RepoAnalyzer::new(root, VordConfig::load_from_dir(root).as_ref());
    let mut attempts = Vec::new();
    for candidate in plan
        .candidates
        .iter()
        .filter(|c| c.autonomy <= ceiling)
        .take(limit)
    {
        let before = measure(&analyzer).await;
        let outcome = agent::run(root, refactor_args(candidate, model.clone())).await?;
        let delta = before
            .zip(measure(&analyzer).await)
            .map(|(b, a)| vord_agent::quality::compare(&b, &a, &Tolerances::default()));
        let failed = matches!(outcome, RunOutcome::Failed { .. });
        attempts.push(Attempt {
            candidate,
            outcome,
            delta,
        });
        if failed {
            break;
        }
    }
    Ok(attempts)
}

fn refactor_args(candidate: &Candidate, model: Option<String>) -> AgentArgs {
    AgentArgs {
        task: task_for(candidate),
        scope: ".".to_string(),
        rule: None,
        max_turns: None,
        max_tokens: None,
        model,
        refactor: true,
    }
}

/// The scope's quality vector, for the report. `None` when it cannot be
/// measured — the report then says nothing about quality rather than
/// something wrong.
async fn measure(analyzer: &RepoAnalyzer) -> Option<vord_agent::QualityVector> {
    analyzer.snapshot(".").await.ok().and_then(|s| s.quality)
}

/// The pull-request body for a batch: for each attempt, why it was chosen,
/// what it changed in every measured dimension, and what the reviewer is
/// actually being asked to judge — intent and trade-offs, not line-by-line
/// correctness the analyzer already checked.
pub fn render_report(attempts: &[Attempt]) -> String {
    let landed: Vec<&Attempt> = attempts
        .iter()
        .filter(|a| matches!(a.outcome, RunOutcome::Completed { .. }))
        .collect();
    let mut out = format!(
        "## Continuous refactoring\n\n{} of {} attempted refactor(s) landed. Each one was \
         accepted only because the analyzer agreed: no new finding, no behaviour-bearing \
         syntax changed (constants, operators, branches) and no quality dimension worse \
         than its tolerance.\n",
        landed.len(),
        attempts.len()
    );
    for attempt in attempts {
        out.push_str(&render_attempt(attempt));
    }
    out.push_str(
        "\n**What to review:** whether each extraction or rename reads better and matches \
         the codebase's conventions. Behaviour preservation and regressions were checked \
         mechanically; taste was not.\n",
    );
    out
}

fn render_attempt(attempt: &Attempt) -> String {
    let mut out = String::new();
    let c = &attempt.candidate;
    out.push_str(&format!(
        "\n### `{}:{}` ({})\n\n**Why:** {}.\n\n**Outcome:** {}\n",
        c.path,
        c.line,
        c.autonomy.as_str(),
        c.rationale,
        attempt.outcome.describe().trim()
    ));
    if let Some(delta) = &attempt.delta {
        let lines: Vec<String> = delta
            .improved
            .iter()
            .map(|d| format!("- improved {}", d.describe()))
            .chain(
                delta
                    .tolerated
                    .iter()
                    .map(|d| format!("- tolerated {}", d.describe())),
            )
            .chain(
                delta
                    .degraded
                    .iter()
                    .map(|d| format!("- **degraded** {}", d.describe())),
            )
            .collect();
        if lines.is_empty() {
            out.push_str("\n**Quality:** every measured dimension unchanged.\n");
        } else {
            out.push_str(&format!("\n**Quality:**\n{}\n", lines.join("\n")));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(autonomy: Autonomy) -> Candidate {
        Candidate {
            path: "src/a.rs".into(),
            line: 7,
            cyclomatic: 14,
            coverage: Some(90.0),
            crap: None,
            commits: 4,
            churn: 40,
            dependents: 1,
            score: 70.0,
            autonomy,
            rationale: "cyclomatic 14, changed in 4 commit(s)".into(),
        }
    }

    #[test]
    fn only_source_files_count_toward_temporal_coupling() {
        assert!(is_source("src/api.rs"));
        assert!(is_source("web/app.tsx"));
        assert!(!is_source("Cargo.lock"));
        assert!(!is_source("README.md"));
    }

    #[test]
    fn the_task_names_the_function_and_forbids_behaviour_change() {
        let task = task_for(&candidate(Autonomy::Auto));
        assert!(task.contains("src/a.rs:7"));
        assert!(task.contains("without changing its behaviour"));
    }

    #[test]
    fn the_text_plan_shows_tier_location_and_reason() {
        let plan = Plan {
            candidates: vec![candidate(Autonomy::Review)],
            temporal_couplings: vec![],
        };
        let text = render_text(&plan, 10);
        assert!(text.contains("[review] src/a.rs:7"), "{text}");
        assert!(text.contains("changed in 4 commit(s)"), "{text}");
    }

    #[test]
    fn the_report_explains_each_attempt_and_its_quality_delta() {
        use vord_agent::{Dimension, QualityVector};
        let before = QualityVector::default().with(Dimension::MaxCyclomatic, 14);
        let after = QualityVector::default().with(Dimension::MaxCyclomatic, 6);
        let chosen = candidate(Autonomy::Auto);
        let attempts = vec![Attempt {
            candidate: &chosen,
            outcome: RunOutcome::Completed {
                turns: 3,
                summary: None,
            },
            delta: Some(vord_agent::quality::compare(
                &before,
                &after,
                &Tolerances::default(),
            )),
        }];
        let report = render_report(&attempts);
        assert!(report.contains("1 of 1 attempted"), "{report}");
        assert!(report.contains("`src/a.rs:7` (auto)"), "{report}");
        assert!(
            report.contains("improved max_cyclomatic: 14 -> 6"),
            "{report}"
        );
    }

    #[tokio::test]
    async fn escalated_candidates_are_never_attempted() {
        let plan = Plan {
            candidates: vec![candidate(Autonomy::Escalate)],
            temporal_couplings: vec![],
        };
        let attempts = run(Path::new("."), &plan, 5, Autonomy::Escalate, None)
            .await
            .unwrap();
        assert!(attempts.is_empty());
    }
}
