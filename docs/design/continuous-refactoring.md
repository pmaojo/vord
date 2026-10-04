# Continuous refactoring

Design notes for `vord refactor` and `vord agent run --refactor`, and how
they answer the open problems laid out in *Continuous Autonomous
Refactoring: A Research Roadmap for AI-Driven Code Quality Maintenance*
(arXiv:2609.01236).

## The problem

The paper asks how agents could *continuously* maintain code quality against
an explicit, evolving definition of "good", instead of refactoring now and
then. It groups the obstacles into five dimensions — multi-objective
optimisation, defining and evaluating quality, multi-timescale signals,
multi-agent architecture, trust — plus pipeline integration and cost.

vord already had the prerequisite most agents lack: a deterministic judge
separate from the writer. Before this change that judge only asked "did the
task add findings?", which is the wrong bar for a refactor: an edit can add
no finding and still raise coupling across the system, or flip a comparison.

## What was built

| Piece | Where | Paper problem it addresses |
|---|---|---|
| Quality vector + Pareto guard (`TradeOff` verdict) | `core/agent/src/quality.rs`, `completion::judge_refactor` | Multi-objective optimisation: detect a local improvement that degrades a global property (RQ1, RQ2) |
| Semantic fingerprint (`SemanticDrift` verdict) | `core/ast/src/semantic.rs` | Behaviour preservation before any non-functional improvement |
| `[agent.refactor]` tolerances, reviewer-owned policy vs. team-owned weights | `infra/fs/src/config.rs`, `bin/cli/src/agent.rs` | Formalising context-dependent quality preferences (RQ4, RQ6) |
| `QualityDelta::utility` (weighted gain) | `core/agent/src/quality.rs` | Utility-based comparison of alternatives |
| Git churn and co-change mining | `bin/cli/src/history.rs` | Temporal signals beyond a static snapshot (RQ7, RQ9) |
| Hidden temporal coupling report | `core/agent/src/plan.rs` | Latent constraints not visible in the code |
| Hotspot planner (`risk × (1 + commits)`) | `core/agent/src/plan.rs`, `vord refactor plan` | Organising the search for refactoring actions (RQ3); cost-aware prioritisation (RQ17) |
| Autonomy tiers `auto`/`review`/`escalate` | `core/agent/src/plan.rs` | Boundaries of autonomy by task risk (trust, RQ13) |
| PR report with rationale and per-dimension delta | `bin/cli/src/refactor.rs` (`render_report`) | Informative hand-off: rationale, benefit, side effects (RQ14) |
| Per-role `model` and `refactor` in `[[swarm.role]]` | `infra/fs/src/config.rs`, `bin/cli/src/swarm.rs` | Matching models to sub-tasks (RQ10) |
| Nightly plan → run → PR workflow | `ci-templates/github-actions-refactor.yml` | Position in the delivery pipeline (RQ15) |

### Quality vector

Eight integer dimensions, measured on the scope before the run and at every
completion claim: `health_score` (higher is better), `debt_minutes`,
`duplicated_lines`, `complex_functions` (cyclomatic > 10), `max_cyclomatic`,
`import_edges`, `component_edges`, `import_cycles`. A dimension missing on
either side is not compared — "not measured" is never "unchanged" — and a
refactor-guarded run whose analyzer cannot measure at all fails (exit 1).

Any dimension worse than its tolerance makes the verdict `TradeOff`, listing
what degraded and what improved. Trade-offs are surfaced, not averaged away:
the weighted `utility` exists to rank alternatives, never to excuse a
degradation.

### Semantic fingerprint

A multiset of atoms: literals (`lit:`), operators recovered from the gap
between operands (`op:`), and control-flow shapes (`ctl:if`, `loop`,
`branch`, `catch`, `throw`). Identifiers and `return` are excluded so
renames and extractions pass. Over the whole scope, merged, so moving code
between files passes.

Drift is asymmetric on purpose: an atom that appears or vanishes is drift; a
literal or operator whose count merely changes is not (deduplication lowers
counts, inlining raises them); a control-flow count that rises is drift (a
new branch is new behaviour).

Known limits: it is syntactic. `a > b` → `b < a` reads as drift, and
swapping two existing constants does not. It errs toward reporting. The
existing GumTree implementation (`core/ast/src/gumtree.rs`) was considered
and not used: its matching requires identical text, so it can never emit an
`Update` and reports any leaf change as delete + insert of every ancestor.

### Planner

A function is a candidate when cyclomatic > 10 or CRAP ≥ 30. Score is
`risk × (1 + commits)`, `risk` being CRAP when coverage is known, cyclomatic
otherwise. Autonomy: `escalate` at ≥ 10 dependent files or < 30% coverage;
`auto` at ≤ 2 dependents and ≥ 80% coverage; `review` otherwise, including
whenever coverage is unknown. Commits touching more than 30 files are
counted as churn but not as co-change, so a sweep does not bury real
coupling. Co-change pairs are restricted to source files.

## What is left

- **Learning from hand-offs** (paper §E, RQ16): aggregate `.vord-audit.jsonl`
  approvals/denials and PR acceptance/revert per rule and tier, so autonomy
  is earned (a tier rises after N accepted refactors without revert).
- **Empirical model taxonomy** (RQ10): record terminal state, turns and
  tokens per model and task kind, and surface it as `vord agent stats`.
- **Parallel refactorers with conflict resolution** (RQ11): a
  `refactor-pack` topology that runs candidates in separate worktrees and
  intersects their `dependents` before integrating.
- **Explicit intent annotations**: a `[[intent]]` table for code kept on
  purpose (compatibility shims, deliberate duplication), respected by the
  planner and the guard.
- **Richer dependents for Rust**: `mod` structure is not an import edge
  today, so Rust files often report 0 dependents.
