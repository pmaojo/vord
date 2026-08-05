# Issue Triage Factory (roadmap C)

Inspiration: Cloudflare/Astro's `triagebot-action` (built on the `Flue`
agent framework) drove Astro's open-issue count from 200+ toward zero by
running every new issue through reproduce → diagnose → verify → fix, with
a separate subagent per stage and a GitHub-label state machine holding it
together.

The pipeline shape is worth taking. The verification philosophy is not:
Flue's "verify it's a real bug" stage is another LLM call. vord's whole
premise (`core/agent/src/prompt.rs`:
`the_system_prompt_states_that_the_model_does_not_decide_completion`) is
that a model never gets to be its own judge. This design keeps the
four-stage shape and replaces every judgement point with something
already deterministic in this codebase: a re-scan, a test run, or
`core/agent-policy`.

## Stages → gate, not vibes

| Stage | Astro/Flue | vord |
|---|---|---|
| Reproduce | subagent writes a repro, "looks right" | subagent writes a failing regression test in a sandbox; stage only advances if it *fails* (deterministic exit code) |
| Diagnose | subagent explains root cause | subagent's diagnosis is cross-checked against `vord scan` findings on the touched file — if a rule already flags the span, the diagnosis is grounded in a real `Issue`; if not, that's tracked, not assumed |
| Verify | subagent asserts "yes, real bug" | no separate verify stage — "real bug" *is* "reproduce produced a red test" from stage 1 |
| Fix | subagent patches, PR opens | reuses `RemediationEngine` (`core/remediation/src/lib.rs`) verbatim: `RemediationVerdict::Accepted` requires the regression test to go green *and* the re-scan to introduce no new/regressed findings |

Net effect: three roles instead of four (Reproducer, Diagnostician,
Fixer), because "verify" collapses into a re-run of stage 1's test plus
the remediation engine's existing verify-before-suggest loop — nothing
new to build there, just a new caller.

## Status

- **Built**: `core/triage` — [`TriageLabel`], [`TriageEvent`]/[`FixVerdict`],
  `next_triage_state`, and `repro_event_from_exit_code`. The actual shape
  landed slightly differently from the sketch below:
  `next_triage_state(current: TriageLabel, event: TriageEvent)` (one active
  label, not a slice — an issue is only ever in one stage at a time)
  returning `Result<TriageLabel, InvalidTransition>`. 19 unit tests; `vord
  scan core/triage` is clean (100/100, 0 issues).
- **Built**: `core/swarm`'s `TRIAGE_PACK` preset
  (`core/swarm/src/topology.rs`), resolvable via `topology = "triage-pack"`
  the same way `two-pack`/`four-pack` are. A test on each crate pins the
  role-name string agreement between `TriageLabel::active_role` and
  `TRIAGE_PACK` without either crate depending on the other.
- **Resolved without new code**: the sandbox open question below. Reproduce
  doesn't need a new port — `vord_agent::runtime::Workspace::run`
  (`infra/fs::RepoWorkspace`) already sandboxes an arbitrary command with a
  wall-clock timeout and reports `CommandOutput { exit_code, stdout,
  stderr }`, the same primitive `vord agent`'s own `run` tool uses.
  `repro_event_from_exit_code` is the pure sliver that turns that result
  into a `TriageEvent` (`Some(0)` → no repro, anything else including a
  signal-killed `None` → a real repro).
- **Built**: `infra/github::IssueTriageGateway` (`infra/github/src/issue_triage.rs`)
  — a GitHub-only type, deliberately not folded into the multi-provider
  `AlmGateway`/`GitHubStatusReporter`. Reads/writes the `triage:*` label
  (`current_label`, `set_label` — removes the stale label, adds the new
  one, no-ops if already correct) and posts issue comments
  (`post_comment`). 29 tests in the crate, all passing; `vord scan
  infra/github` is clean (98/100 — the 2 remaining MAJOR findings are
  pre-existing on `GitHubStatusReporter`, unrelated to this addition).
- **Built**: `bin/cli::triage::advance` (`bin/cli/src/triage.rs`) — the
  composition root, mirroring `bin/cli::swarm`'s split of a pure decision
  (`next_action_for`, unit-tested with no I/O) from the I/O it drives.
  All four `NextAction`s are wired:
  - **`Start`** (a wait state — `New`/`Reproduced`/`Diagnosed`/
    `GateRejected`): advances the label, no verification needed.
  - **`RunRepro`** (`Reproducing`): runs a caller-supplied
    `--repro-command` via `RepoWorkspace::run` in the `reproducer` role's
    worktree (creating it if needed), classifies the exit code, advances.
    Needs no LLM at all.
  - **`RunDiagnose`** (`Diagnosing`): runs `crate::agent::run_with_policy`
    in the `diagnostician`'s worktree with the issue's title/body as
    context (`IssueTriageGateway::issue_summary`, also built this pass).
    Always advances to `Diagnosed` on completion —
    `grounded_in_finding` is computed by re-scanning the worktree with
    `crate::scan` and checking for any `vord` finding at all, an
    approximation flagged as informational-only in the code, not a gate
    (`core/triage` never lets it change the transition — see the open
    question below for the real version of this signal).
  - **`RunFix`** (`Fixing`): runs `crate::agent::run_with_policy` in the
    `fixer`'s worktree, then re-runs `--repro-command` and requires it to
    now exit `0`. `fix_verdict` is the pure decision between "the
    agent's own session completed" (its analyzer-as-done gate already
    refuses regressions) and "the regression test now passes" — accepted
    only if both hold.

  `vord triage advance --issue <n> [--repro-command "..."]` is live on the
  `vord` binary. 18 tests: pure branching and `fix_verdict` (no I/O),
  plus integration tests against a real temp git repo, a real `sh -c`
  subprocess and a mock GitHub server for every path that doesn't need a
  live LLM call. `crate::agent::run_with_policy` always sources a real
  provider from the environment with no seam to inject a fake one, so
  `run_diagnose_stage`/`run_fix_stage`'s actual agent turn is exercised by
  the pure helpers they delegate to plus manual review, not an automated
  end-to-end test — an honest limit stated in the module's own docs, not
  hidden.

`vord scan` on both crates after this: `infra/github` 98/100 (the 2
remaining MAJOR findings pre-existing on `GitHubStatusReporter`), `bin/cli`
96/100 (pre-existing findings on other files; `triage.rs` itself has none
— it tripped `rust:disallow-panic-macros` on an `unreachable!()` and
`smells:duplicate-code` on its first pass, both fixed before landing).

## What's actually left

Two things, both scoped and non-blocking:

- **The regression-scanning half of Fix's "verify" step.** The design
  table above described Fix as needing both a green test *and* a clean
  re-scan; what's built gets the first for free from
  `run_with_policy`'s own analyzer-as-done gate (it won't report
  `Completed` if the diff regressed), so a *separate* explicit re-scan in
  `run_fix_stage` was redundant, not skipped.
- **Opening the PR.** `FixReady` today means "the fixer's worktree branch
  has a working fix, verified" — nothing pushes the branch or opens a
  pull request yet. That's ordinary ALM-adapter work (`git push` +
  `AlmGateway`-style PR creation), not a new judgement primitive, and was
  out of scope for this pass.

## Where it lives

No new judgement primitive is needed — `RemediationEngine`,
`AgentPolicy`, and `core/swarm`'s topology/worktree/handoff machinery
already model "isolated role does work, hands off a durable artifact,
gate decides if it lands." This is a new *front door* onto that
machinery (a GitHub issue instead of a lint finding), not a new kind of
gate.

- **`core/triage`** (built, pure — same shape as `core/swarm`): the label
  state machine itself.
  ```rust
  enum TriageLabel {
      New, Reproducing, Reproduced, NeedsInfo,
      Diagnosing, Diagnosed,
      Fixing, FixReady, GateRejected,
  }

  fn next_triage_state(current: TriageLabel, event: TriageEvent) -> Result<TriageLabel, InvalidTransition>;
  ```
  Pure function of current label + event in, next label out — no
  fetches, no clock, no process spawning, matching every other `core/`
  crate in this workspace. `TriageEvent` carries the test's exit status
  and, where relevant, a `FixVerdict` (this crate's own two-variant
  stand-in for `RemediationVerdict`, kept dependency-free of
  `core/remediation` the same way `core/agent-policy::Finding` stays
  independent of `vord_rules_engine::Issue`); it never carries an LLM's
  self-report of success.

- **`core/swarm`**: a third topology, `TRIAGE_PACK = [Reproducer,
  Diagnostician, Fixer]`, alongside the existing `TWO_PACK`/`FOUR_PACK`
  (`core/swarm/src/topology.rs`). Same worktree-per-role isolation
  (`core/swarm/src/worktree.rs`), same durable handoff queue
  (`core/swarm/src/handoff.rs`) — the Reproducer hands off a repro
  script + failure output, the Diagnostician hands off a diagnosis (plus
  the `Issue` it's grounded in, if any), the Fixer hands off a
  `FixProposal` straight into `RemediationEngine`.

- **`core/agent-policy`**: unchanged, applied as-is. A triage-driven
  autonomous fix is still an agent write; protected paths and blocking
  rules apply exactly as they do to `vord agent` today.

- **`infra/github`** (built): `issue_triage.rs` alongside the existing
  `pr_feedback.rs` — its own `IssueTriageGateway` type rather than more
  methods on `AlmGateway` (`core/rules-engine/src/alm_gateway.rs`), which
  today only knows `decorate_pr`/`upsert_check_run` and stays that way;
  issue triage is GitHub-only, not a fifth thing GitLab/Bitbucket/Azure
  need stub methods for.

- **`bin/cli`** (built, all four stages): `vord triage advance --issue <n>
  [--repro-command "..."]`, meant to be invoked from a GitHub Action on a
  `triage:*` label change or on a schedule, the same composition-root
  pattern `bin/cli/src/swarm.rs` already uses to drive `core/swarm`'s pure
  topology against real worktrees — `run_role_task` in `triage.rs` calls
  `crate::agent::run_with_policy` exactly the way `topology_run` does per
  role in a pipeline, reused here to drive one role at a time under the
  label state machine's control instead of a fixed sequence. One step per
  call by design — re-invoked for the next step, same as the label state
  machine it wraps.

## Honest limit

vord's rules engine is static analysis; it doesn't run code. "Reproduce"
therefore still needs either a human-supplied `--repro-command` or (not
built) a model in a sandbox to write one — that part of Flue's approach
isn't replaceable by a vord rule. What changes is everything downstream of
that first red test: no stage after it is allowed to advance the state
machine on an LLM's say-so. Diagnose and Fix do call a live agent — that's
unavoidable, diagnosis and code changes are exactly what a model is for —
but neither stage's *transition* trusts the model's own account of what it
did: Diagnose's transition doesn't depend on the model at all, and Fix's
depends only on the regression command's exit code plus the same
regression-freedom guarantee `run_with_policy` already enforces before
reporting any session `Completed`.

## Open questions

- Does "diagnosed but no matching rule fired" become a new-rule-request
  signal (`core/rules-engine` gets a candidate pattern), or does it just
  route to `NeedsInfo` / a human? Leaning toward the former long-term —
  it's a free source of rule candidates — but it's out of scope for a
  first cut.
