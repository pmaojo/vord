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
  and `next_triage_state`. The actual shape landed slightly differently
  from the sketch below: `next_triage_state(current: TriageLabel, event:
  TriageEvent)` (one active label, not a slice — an issue is only ever in
  one stage at a time) returning `Result<TriageLabel, InvalidTransition>`.
  15 unit tests; `vord scan core/triage` is clean (100/100, 0 issues).
- **Not built yet**: the `TRIAGE_PACK` swarm topology, the `infra/github`
  issue-side I/O, the `bin/cli` entry point, and the
  `core/remediation::Sandbox` test-runner extension the "honest limit"
  section below flags as still undecided. Each depends on that sandbox
  decision before it can be wired up for real, so this first slice stops
  at the pure state machine.

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

- **`infra/github`**: new `issue_triage.rs` alongside the existing
  `pr_feedback.rs`, generalizing the comment-posting patterns already in
  `lib.rs` (`post_issue_review_comment`'s update-or-create logic) from PR
  review comments to issue comments, and adding label read/write. This
  is the one genuinely new I/O surface — `AlmGateway`
  (`core/rules-engine/src/alm_gateway.rs`) today only knows `decorate_pr`
  and `upsert_check_run`; it has no issue-side methods at all.

- **`bin/cli`**: `vord triage run --issue <n>`, invoked from a GitHub
  Action on the `issues.opened` and `issue_comment` webhooks, the same
  composition-root pattern `bin/cli/src/swarm.rs` already uses to drive
  `core/swarm`'s pure topology against real worktrees.

## Honest limit

vord's rules engine is static analysis; it doesn't run code. "Reproduce"
therefore still needs a model in a sandbox to write and run a regression
test — that part of Flue's approach isn't replaceable by a vord rule.
What changes is everything downstream of that first red test: no stage
after it is allowed to advance the state machine on an LLM's say-so.

## Open questions

- Does "diagnosed but no matching rule fired" become a new-rule-request
  signal (`core/rules-engine` gets a candidate pattern), or does it just
  route to `NeedsInfo` / a human? Leaning toward the former long-term —
  it's a free source of rule candidates — but it's out of scope for a
  first cut.
- Sandbox choice for running arbitrary project test suites (as opposed
  to `vord scan`, which is language-aware but doesn't execute anything)
  isn't decided. `core/remediation::Sandbox` is currently scoped to
  applying/reading file edits, not running a project's test runner —
  that trait likely needs a `run_tests` method, or a sibling port.
