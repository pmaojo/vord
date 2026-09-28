---
name: feature-breakdown
description: "Turn a feature request into a dependency-ordered set of tasks scoped to vord's crate boundaries (core/, parsers/, rulesets/, integrations/). Use before starting any change that touches more than one crate, and before spec_tasks in the agent-dev-loop, to decide the right unit of work."
---

# Feature Breakdown for a Multi-Crate Workspace

`spec_tasks` (see `skills/agent-dev-loop/SKILL.md`) records the task
graph once you know what the tasks are. This skill is for the step
before that: turning "add support for language X" or "add a new
taint-source rule" into tasks that respect this workspace's actual
boundaries, so each task is reviewable and testable on its own.

## Find the seams first

Before splitting work, identify which of these the feature actually
touches — most features touch 2-3, rarely all of them:

- **`parsers/`** — a new `tree-sitter-*` crate, or a grammar version
  bump. Self-contained; can land and be tested before anything consumes it.
- **`core/ast`, `core/cfg`, `core/symbols`** — language-agnostic
  representations. Changes here ripple into every rule that reads them;
  isolate and land first, behind existing tests, before touching rules.
- **`core/rules-engine`, `rulesets/`** — a new rule is additive by
  default (new file, new test fixtures) unless it changes how existing
  rules match.
- **`core/taint`, `core/flow-graph`, `core/flow-risk`** — analysis
  passes with wide blast radius; a change here needs its own task even
  if the triggering feature is "just" a new rule that happens to need a
  new taint source.
- **`core/agent-policy`, `core/agent`** — the guardrail's own decision
  logic. Changes here affect every downstream user pinned to this
  Action; treat as a task on its own with explicit backward-compat
  notes for the escalation/blocking contract.
- **`integrations/`, `npm/`, `packaging/`** — distribution surface.
  Only needed if the feature changes the CLI surface, MCP tool schema,
  or a packaged artifact's contents.

## One task per reviewable unit, in dependency order

1. Parser/grammar change (if any) — lands and tests alone.
2. Core representation change (if any) — lands against existing
   consumers' tests, not yet the new feature's.
3. Rule/analysis logic — the actual behavior, with its own fixtures.
4. Integration/CLI/MCP surface — wiring the new behavior up to callers.
5. Docs/packaging — `docs/`, `README.md`, changelogs.

A task that spans steps 2 and 3 is usually a sign the core change
wasn't actually separable — split it, or write the core change to keep
the old behavior byte-identical until step 3 flips it on.

## Sizing check

If a task can't be described as "one crate, one behavior, one set of
tests," it's too big — split along the seams above rather than by time
estimate. `spec_tasks`' `depends_on` should mirror this list directly:
parser → core → rules → integration → docs.
