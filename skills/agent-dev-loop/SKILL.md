---
name: agent-dev-loop
description: "The end-to-end loop for working in a repository governed by vord with okf-mcp as durable memory: recover context, agree a spec before code, write the executable contract, work RED→GREEN under the guardrail, and close each task with evidence rather than assertion. Use at the START of any session in such a repository, before reading code or planning work."
---

# Agent Development Loop — vord + okf-mcp

This is the loop, in order. Each phase names the thing that must exist
before the next one starts.

## Phase 0 — Preflight (never skip)

A guardrail wired to a missing binary is **silent**: the hook fires, the
command does not resolve, and the write lands unjudged with no error
surfaced to you. Verify before trusting it:

```sh
vord --version                 # binary resolves?
ls .claude/settings.json       # hooks wired?
ls vord-policy.toml            # policy present?
```

If the hooks are wired but the binary is missing, say so before writing
anything. You are not being governed, whatever the config implies.

If no policy exists yet, `vord hook install` writes it **into the
repository** — versioned and reviewed in the same pull request as the code
it governs, not into one developer's profile.

## Phase 1 — Recover context before writing any

Search durable memory first. Something has probably already been decided.

- `memory_search` — a project node? a prior spec? an existing ontology?
- `memory_search` with `type: ontology` **before inventing relation names**.
  Reusing `depends_on` beats inventing `requires` and fragmenting the same
  fact across synonymous edges.
- `spec_status` on any spec you find — it reports which tasks are actually
  startable now versus still waiting on dependencies.

A spec's rejected alternatives are load-bearing. Read them and do not
re-propose what was already ruled out.

## Phase 2 — Spec before code

Architectural forks go to the human, not to your own judgment. Record the
outcome with `spec_propose` (Requirements + Design), and **write down the
alternatives you rejected and why** — that is what stops the next agent
re-litigating them in three weeks.

The human approves the plan. Not the diff.

## Phase 3 — The executable contract

Write the Gherkin scenarios before the logic, tagged `@covers(<glob>)` at
the path they will govern.

The tag alone is not evidence. A block needs a real When/Then pair (and an
Examples row if it is a Scenario Outline), and the glob must be narrower
than `**`. If `[[gherkin_required]]` is enabled for a path, no write lands
there without one.

**You may not enable that gate yourself.** The policy file is a protected
path — an agent that can edit its own referee is not governed by one. Ask.

## Phase 4 — Decompose into a dependency graph

`spec_tasks` with `depends_on`. Then `spec_status` answers the only
question that matters when work resumes mid-stream: *what can I start right
now.*

Move one task to `status-in_progress` with `memory_patch`. One.

## Phase 5 — RED → GREEN → REFACTOR, under the guardrail

- **RED**: an assertion failure, not a compile error. A compile error proves
  the module is missing, not that the behavior is absent. Stub the function,
  assert the real value, watch it fail on the value.
- **GREEN**: the minimum that passes.
- **REFACTOR**: under green, assertions frozen. Changing an assertion is a
  behavior change and belongs back in the spec.

The guardrail judges each write as it lands. Three distinct outcomes, and
they are not interchangeable:

- **`blocking_rules`** — denied, whatever the severity, no override. Not
  approvable, not escalatable.
- **`escalate_rules`** — denied pending human review. `vord hook approve
  <token>` authorizes exactly one retry of that identical write. Never a
  standing exemption.
- **`protected_path`** — denied with no finding required.

A path an agent has already touched is judged against a stricter threshold
next time, tracked automatically. A denial is information: fix the finding,
do not look for a way around it, and never edit the policy to make it pass.

If the circuit breaker or loop alarm trips, stop. Those reset by a human
(`vord hook reset-circuit-breaker`, `vord hook reset-loop-guard`), and the
trip means the problem is your approach, not this one write.

## Phase 6 — Gauntlet

Run the repository's own suite, then `vord scan` on what you touched. Check
**new issues since previous analysis**, not the absolute count — a
pre-existing finding is not yours to fix inside this task, and widening the
diff to chase it is its own defect.

`[[test_required]]` is checked at session end, not per write: no single
write can attest a suite result. The session does not end because you
believe you are done.

## Phase 7 — Evidence, not assertion

A task does not reach `status-done` by being declared finished.
`memory_patch` **rejects** that transition unless the task body already
carries an `## Evidencia` section with commands actually run and their real
output.

Paste the real RED failure, the real GREEN result, the real scan verdict.
If something did not work, or a config line turned out to be a no-op, or a
gate did not fire where you expected — write that down too, under its own
heading. An honest limitation is evidence; a silent omission is not.

## Phase 8 — Consolidate

`memory_consolidate` closes the session as a durable summary: what was
touched, what was decided, linked into the graph. **You** write it — the
server validates structure and renders deterministically, it does not
synthesize anything with a model of its own.

The next session starts at Phase 1 and finds the ground already mapped.

## What not to do

- Do not write code before the spec is agreed and the scenarios exist.
- Do not mark a task done from memory of having run something. Re-run it and
  paste the output.
- Do not edit `vord-policy.toml`, `vord.toml`, CI workflows, or Terraform.
  All protected, by design.
- Do not disable, skip, or `#[allow]` your way past a finding. That is
  reported as gate-gaming.
- Do not claim a mechanism works because the configuration says it should.
  Run it.
