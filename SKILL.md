# vord AI Agent & Swarm Skill Instructions

`vord` is an ultra-fast, multi-language static analysis engine and spec-driven agent swarm coordinator written in Rust.

---

## 🏆 The Perfect AI Agent Flow with `vord`

```
  1. Kickoff / Init ──► 2. Worktree Isolation ──► 3. Fast AST Edit-Scan Loop ──► 4. Policy Gate Verification ──► 5. Handoff & Merge
   (vord kickoff)          (vord swarm)             (vord scan <30ms)               (blocking_rules = 0)         (git merge)
```

### Phase 1: Onboarding & Repository Kickoff
1. **Initialize Project / Feature**:
   - Run `vord kickoff react-bulletproof` (or `rust-clean`, `python-clean`, `typescript-clean`, `fullstack-hexagonal`) to generate a clean, modular structure.
   - Or run `vord init` to generate a project-tailored `vord.toml`.
2. **Turn the plan into Gherkin BDD scenarios before writing code**:
   - Kickoff also writes `features/*.feature` — a Gherkin scaffold with one
     placeholder `Scenario:` and a `TODO(agent)` banner. It is not a real
     spec yet.
   - Before touching implementation code, replace the placeholder with real
     `Scenario:` blocks derived from the task's known plan/requirements —
     one scenario per behavior the plan actually commits to (happy path,
     each stated edge case, each acceptance criterion the human gave you).
     Delete the `TODO(agent)` banner once the file reflects the real plan.
   - Treat these scenarios as the acceptance contract for the work: come
     back to `features/*.feature` when a requirement changes, and use it as
     the checklist when deciding the task is done.

---

### Phase 2: Topology Resolution & Worktree Isolation
2. **Query Swarm Topology**:
   - Run `vord swarm roles` to resolve active roles (`architect` -> `coder` -> `cleaner` -> `qa`), worktree paths (`.vord/worktrees/<role>`), protected paths, and blocking rules.

---

### Phase 3: Autonomous Edit-Scan-Fix Loop (< 30ms)
3. **Execute Code Changes inside Worktree**:
   - Edit files inside `.vord/worktrees/<role>`.
4. **Instant AST Verification**:
   - Run `vord scan` inside the worktree.
   - `vord` runs its own AST rules (custom React Doctor/OWASP/AI guardrails,
     architecture, complexity, duplication, ...) plus lightweight syntax
     checks named after Oxlint/Ruff/Clippy (`typescript:oxlint-analyzer`,
     `python:ruff-analyzer`, `rust:clippy-analyzer`) — those three only
     catch parse errors, not each tool's full rule catalog. For the real
     Oxlint/Ruff/Clippy/ESLint/gosec/bandit/semgrep/CodeQL rule sets, run
     the tool itself and merge its SARIF output: `vord scan --sarif
     ruff.sarif --sarif oxlint.sarif` (see README's "Importing another
     analyzer's findings" section). All of this still finishes in < 30ms —
     the SARIF merge is a fast local ingest, not a re-run of the tool.
5. **Self-Correction & Automated Fixes**:
   - Run `vord scan --fix` to apply automated fixes.
   - If manual fixes are needed, inspect `vord`'s `file:line:col` findings and fix immediately.

---

### Phase 4: Policy Gate Verification & Durable Handoff
6. **Verify Policy Scope**:
   - Ensure zero modifications to `protected_paths` and zero `blocking_rules` errors.
7. **Send Handoff to Next Role**:
   ```bash
   vord swarm handoff-send --from architect --to coder --summary "Architectural boundaries established"
   vord swarm handoff-deliver
   ```

---

### Phase 5: Pipeline Completion & Git Merge
8. **Final QA Verification**:
   - Run `vord scan` across the workspace. Verify health score (e.g., 98/100).
9. **Merge Worktree Branch to Main**:
   - Merge `vord/swarm/<role>` into `main` and clean up temporary worktrees:
     ```bash
     git merge vord/swarm/coder
     vord swarm worktree-remove --role coder
     ```

---

## 🧬 Full-Coverage Linting: Oxlint/Ruff/Clippy's Real Rule Catalogs

`vord scan` alone only catches parse errors for `typescript:oxlint-analyzer`/
`python:ruff-analyzer`/`rust:clippy-analyzer` — not each tool's actual rules
(see Phase 3 above). For real coverage, run each tool yourself with SARIF
output and merge it into the same scan. Every command below is verified to
work as written — not just documented, actually run end-to-end:

```bash
# JS/TS — oxlint's own rule engine (native `-f sarif`, oxlint >= 1.x)
oxlint -f sarif src > oxlint.sarif

# Python — ruff's own rule engine (native `--output-format sarif`)
ruff check --output-format sarif . > ruff.sarif

# Rust — clippy's own rule engine (needs a one-time
# `cargo install --locked clippy-sarif`; clippy itself has no native SARIF output)
cargo clippy --message-format=json -q 2>/dev/null | clippy-sarif > clippy.sarif

# Merge whichever of the above apply to this repo — a JS/TS+Python monorepo
# skips --sarif clippy.sarif, etc. Imported findings become ordinary issues:
# they count toward blocker_issues/critical_issues, show up in --format
# json's issues[], and can fail --enforce-gate, same as vord's own rules.
vord scan . --sarif oxlint.sarif --sarif ruff.sarif --sarif clippy.sarif --enforce-gate
```

`--format json`'s stdout carries only the JSON payload (the "📥 Imported..."
status line goes to stderr) — safe to pipe straight into `jq`/a parser
without stripping anything first.

---

## 🧪 High-Assurance / Evidence-First Tasks

For work the human explicitly wants proven rather than reviewed line by
line — "reliable", "TDD", "prove it works" — or that touches money, auth,
data loss, concurrency, or a public API, use the `old-coder` skill
(`skills/old-coder/SKILL.md`): a SPEC → RED → GREEN → REFACTOR → GAUNTLET →
EVIDENCE loop where the human approves a test plan up front and reads a
numbers-only evidence report afterward instead of the diff. Its GAUNTLET
step can use `vord scan --enforce-gate` as one of its static-analysis
layers — see that skill's own "Using this with vord" section. For routine
changes, write good tests directly instead of invoking the loop.

---

## ✅ Finishing a Task: Version Bump Convention

Once a change is actually done — implemented, tested, and you have
concrete evidence it introduces **no regression and no false-positive
risk** (existing tests still pass, clippy is clean, and any new detection
logic has its own tests proving it doesn't fire on innocent code) — bump
the patch version as part of closing out the task. Do **not** bump on
partial work, on a change you haven't run the test suite against, or on
anything that changes existing detection behavior in a way you haven't
verified against real code.

```bash
cargo test --workspace                              # must be green
cargo clippy --workspace --all-targets -- -D warnings  # must be clean
scripts/bump-version.sh <next-patch-version>         # never edit the version by hand
git add -A && git commit -m "..."
```

`scripts/bump-version.sh` is the only correct way to move the version — it
rewrites all ~65 internal crate pins, `Cargo.lock`, `vord.toml` and
`.claude-plugin/plugin.json` together (see `RELEASING.md`); hand-editing
`[workspace.package]` alone leaves those out of sync. This is a version
bump only — tagging and publishing a release (`git tag vX.Y.Z`) is a
separate, deliberate step a human takes per `RELEASING.md`, not something
to do automatically here.

If you're unsure whether your change qualifies as "no regression risk" —
e.g. it changes what an *existing* rule flags, rather than adding something
new and additive — don't bump; leave that decision to the human reviewing
the PR.

---

## ⚡ CLI Quick Reference

```bash
# 🚀 1. Kickoff Starter Templates
vord kickoff react-bulletproof --path ./my-app
vord kickoff rust-clean --path ./my-rust-crate
vord kickoff python-clean --path ./my-python-app
vord kickoff typescript-clean --path ./my-ts-app

# 🔍 2. Static Analysis & Rules
vord scan                         # Scan workspace using vord.toml profile
vord scan --fix                   # Apply automated rule fixes
vord scan --coverage report.lcov  # Also enables flow-coverage auto-detection (flow:untested-sequence)

# Register a multi-function sequence static call-graph inference can't see
# (cross-file, cross-language, dispatched via router/queue/cron): once
# registered, `vord scan` reports flow:registered-gap if any step is
# confirmed untested (0% coverage) or has drifted (renamed/moved).
vord flow add --name checkout-happy-path \
  --step src/checkout.ts:startCheckout \
  --step src/payment.ts:chargeCard

# Declare a custom hexagonal/DDD layer name in vord.toml so a non-standard
# directory (e.g. `checkout/`) is recognized as domain code without renaming it:
#   [[architecture.layer]]
#   name = "checkout-domain"
#   is_a = "domain"        # domain | application | port | adapter | infrastructure
#   patterns = ["src/checkout/**"]

# 🐝 3. Swarm & Multi-Worktree Orchestration (LLM or Offline Spec-Driven)
vord swarm roles                  # View resolved role topologies and policy scopes
vord swarm tui                    # Interactive Ratatui dashboard for roles & handoffs
vord swarm worktree-create --role coder  # Create isolated git worktree for role
vord swarm handoff-send --from architect --to coder --summary "Task..."
vord swarm handoff-deliver        # Deliver queued outbox handoffs into inboxes
vord swarm handoff-inbox --role coder    # Read role inbox
vord swarm handoff-ack --role coder --id <id> # Acknowledge handoff
vord swarm run --task "Ship feature"     # Drive full pipeline (with Assistant prompt fallbacks)

# 🩺 4. Issue Triage Factory (roadmap C) — reproduce -> diagnose -> fix a
# GitHub issue, one step at a time, gated by exit codes and re-scans
# instead of a model's self-assessment. Reads/writes the issue's
# `triage:*` label; needs GITHUB_TOKEN + GITHUB_REPOSITORY set (same as
# any other `vord` GitHub integration).
vord triage advance --issue 42                                 # advance a wait state (New/Reproduced/Diagnosed/GateRejected)
vord triage advance --issue 42 --repro-command "npm test -- -t bug"  # advance triage:reproducing or triage:fixing
```

Every stage is wired: Reproduce runs `--repro-command` and needs no LLM;
Diagnose and Fix each run one live `vord agent` turn
(`diagnostician`/`fixer` roles) and are verified without trusting the
model's own account — Diagnose's transition doesn't depend on the agent's
output at all, and Fix is only accepted if the agent's own regression-free
completion *and* a re-run of `--repro-command` both hold. Needs
`[[swarm.role]]` entries named `reproducer`, `diagnostician` and `fixer`
in `vord.toml` (and `topology = "triage-pack"` if you also want `vord
swarm` to see it as a topology) so each role has a worktree to run in.
Opening a PR from a verified fix isn't built yet — see
`docs/design/issue-triage-factory.md`.

---

## 🤖 How an AI Agent Drives `vord swarm` Flows When LLM Provider is Not Configured

When `vord agent` (the internal LLM runner inside `vord`) is not configured with an API key or local model provider, **you (the interactive AI Coding Assistant) step in as the model runner for each role in the swarm topology**.

### Step-by-Step AI Agent Execution Protocol:

1. **Query Topology & Role Contracts**:
   - Run `vord swarm roles` to resolve active roles (`architect` -> `coder` -> `cleaner` -> `qa`), worktree paths, protected paths, and blocking rules.

2. **Trigger Pipeline Run**:
   - Run `vord swarm run --task "<user_task>"`.
   - `vord swarm` will attempt to launch the first role. Upon encountering no LLM provider, it emits the **`SWARM ASSISTANT HANDOFF PROMPT`**:
     ```text
     vord swarm: LLM provider unavailable for role [architect]
     >>> SWARM ASSISTANT HANDOFF PROMPT (role: architect) <<<
     Worktree: /path/to/project/.vord/worktrees/architect
     Task: <task_description>
     Policy Scope: blocking_rules=["react:feature-directory-isolation"], protected_paths=["infra/"]
     >>> END PROMPT <<<
     ```

3. **Execute Role Task inside Target Worktree**:
   - Navigate your file edits to the target worktree path (`.vord/worktrees/<role>`).
   - **Obey Scoped Policy**:
     - Do NOT edit files under `protected_paths`.
     - Run `vord scan` inside the worktree and fix all violations matching `blocking_rules`.

4. **Send & Deliver Handoff to Next Role**:
   - Once the role's work is complete, queue a handoff for the next role in the topology:
     ```bash
     vord swarm handoff-send --from architect --to coder --summary "Architectural boundaries established and verified"
     vord swarm handoff-deliver
     ```

5. **Drive Recipient Role Inbox**:
   - Read the incoming handoff for the recipient role:
     ```bash
     vord swarm handoff-inbox --role coder
     ```
   - Perform the next role's task in its worktree (`.vord/worktrees/coder`).
   - Acknowledge receipt once complete:
     ```bash
     vord swarm handoff-ack --role coder --id <handoff_id>
     ```

6. **Monitor & Inspect via TUI**:
   - Launch `vord swarm tui` at any time to inspect active worktree branches, pending handoffs, and policy scope metrics in a terminal interface.

---

## 🐝 `vord swarm` Architecture Reference

```
       ┌────────────────┐
       │   vord.toml    │ (Defines topology & role policies)
       └───────┬────────┘
               │
   ┌───────────▼───────────┐
   │  vord swarm topology  │ (architect -> coder -> cleaner -> qa)
   └───────────┬───────────┘
               │
 ┌─────────────┼─────────────┬─────────────┐
 │ Worktree 1  │ Worktree 2  │ Worktree 3  │ ... (.vord/worktrees/<role>)
 │  architect  │    coder    │   cleaner   │
 └──────┬──────┴──────┬──────┴──────┬──────┘
        │             │             │
        ▼             ▼             ▼
 ┌─────────────────────────────────────────┐
 │       Durable Handoff Inbox/Outbox      │ (.vord/handoffs/)
 └────────────────────┬────────────────────┘
                      │
                      ▼
 ┌─────────────────────────────────────────┐
 │   Swarm Assistant Prompt Fallback / TUI │ (vord swarm tui)
 └─────────────────────────────────────────┘
```
