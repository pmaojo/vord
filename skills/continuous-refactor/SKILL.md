---
name: continuous-refactor
description: "Pick what to refactor from complexity, coverage and git history, then refactor it under vord's refactor guard (no new findings, no behaviour change, no quality dimension degraded). Use when asked to reduce technical debt, clean up hotspots, or keep code quality from decaying between features."
---

# Continuous refactoring with vord

Refactoring is a multi-objective problem: an edit that simplifies one
function can raise coupling across the system, and an "equivalent" rewrite
can flip a comparison. vord treats a refactor as done only when a
deterministic analyzer agrees on three things at once, never on the model's
own say-so.

## 1. Decide what to refactor

```sh
vord refactor plan                      # top 10, text
vord refactor plan --lcov lcov.info     # rank by CRAP, tier by coverage
vord refactor plan --scope core/ --since-days 90 --format json
```

Each candidate has:

- a **score** — risk × (1 + commits in the window), where risk is the CRAP
  score when coverage is known and cyclomatic complexity otherwise.
  Complex code nobody touches is cheap to leave; complex code that changes
  every week is where debt costs money;
- an **autonomy tier** —
  `auto` (≤2 dependent files and ≥80% covered: the analyzer's word is
  enough), `review` (a human reviews the PR), `escalate` (≥10 dependents or
  <30% covered: ask a human before attempting it at all);
- a **rationale** you can quote to the reviewer.

The plan also lists **hidden temporal coupling**: source files that keep
changing together with no import between them. Treat each pair as a latent
constraint — if you refactor one side, check the other.

Work from the top. Never attempt an `escalate` candidate without the user's
explicit go-ahead; say why it is escalated instead.

## 2. Refactor one candidate under the guard

```sh
vord agent run --refactor --task "Refactor src/billing.rs:120 to reduce its complexity without changing behaviour"
vord refactor run --limit 3 --max-autonomy review --report vord-refactor.md
```

`--refactor` adds two checks to the usual "no new finding" verdict:

1. **Behaviour preserved.** vord fingerprints every file in scope as a
   multiset of literals, operators and control-flow constructs. A new or
   vanished constant or operator, or an extra `if`/loop/`throw`, is
   *semantic drift* and the task is not done. Renames, extractions, moves
   between files and inlining pass; removing duplicated code passes.
2. **No quality dimension degraded** past `[agent.refactor]`'s tolerance:
   `health_score`, `debt_minutes`, `duplicated_lines`, `complex_functions`,
   `max_cyclomatic`, `import_edges`, `component_edges`, `import_cycles`. A
   local improvement that makes the whole worse is reported as a *trade-off*
   and sent back.

If you are driving the edits yourself (not through `vord agent`), apply the
same discipline by hand: move, rename, extract, inline — do not change
constants, operators or add branches; run the tests; then re-run
`vord refactor plan` and `vord scan .` and compare.

## 3. Hand off

`vord refactor run --report` writes a PR body with, per attempt: why it was
chosen, the outcome, and the before/after of every quality dimension. Put
that in the PR. The reviewer's job is then intent and taste — whether the
new shape reads better — not re-checking what the analyzer already proved.

## Configuration

```toml
# vord.toml
[agent.refactor]
preserve_behaviour = true        # default
[agent.refactor.tolerances]
import_edges = 2                 # may worsen by up to 2; everything else by 0

[[swarm.role]]
name = "refactorer"
model = "qwen2.5-coder:32b"      # per-role model
refactor = true                  # this role's runs use the refactor guard
```

Unknown tolerance keys are rejected, so a typo never silently tolerates
nothing.

## Running it continuously

`ci-templates/github-actions-refactor.yml` runs plan → run → pull request
nightly. Nothing merges automatically.

## Limits worth knowing

- The fingerprint is syntactic: `a > b` rewritten as `b < a` reads as drift,
  and swapping two existing constants does not. It errs toward reporting.
- `dependents` counts file-level import edges; for Rust, intra-crate `mod`
  structure is not an import edge, so Rust files often show 0.
- The tests are still the behaviour contract: the guard complements them,
  it does not replace running them.
