# yunq Roadmap

> The forward-looking plan. Historical session-by-session narrative — and the
> design rationale behind everything already built — lives in
> [DEVLOG.md](DEVLOG.md), which this file replaced on 2026-07-29.

## Mission

yunq began as an analyzer: *"what is wrong with this code?"*. It then became a
guardrail: *"may this write land?"*. The next step is the one this roadmap is
organised around — **yunq writes the code too, and is the only agent runtime
that cannot approve its own work.**

Every coding agent on the market grades its own homework. The model proposes
an edit, the model decides the edit is good, and the verification is a second
prompt to the same weights. yunq is the one project where the judge already
exists as a separate, deterministic, 133-rule artifact that predates the
writer. Making yunq write code is not a pivot away from analysis — it is the
only way to close the loop that analysis was always pointing at.

**The thesis, stated as a constraint:** in `yunq agent`, no edit reaches disk
without passing the same `core/agent-policy` evaluation that gates a
third-party agent today, and no task is reported complete without the
analyzer agreeing. The referee becomes a player without ever stopping being
the referee.

## Where we actually are (2026-07-29)

Verified against the tree, not remembered:

| Area | State |
|---|---|
| Workspace | Hexagonal, enforced by Cargo: `bin → {infra, parsers, rulesets} → core` |
| Languages | 24 tree-sitter grammars (`parsers/`, plus `treesitter-adapter` + `treesitter-tokens`) |
| Rules | 133 `Rule`/`CrossFileRule` impls across 14 ruleset crates |
| Tests | ~1156 test functions in-workspace |
| Analysis core | `rules-engine`, `ast`, `profiles`, `taint` (intra + cross-file), `duplication`, `symbols`, `import-graph` |
| Agent guardrail | `core/agent-policy` (1039 LOC): blocking/advisory rules, protected paths, provenance, Gherkin evidence, circuit breaker, loop guard, single-use escalation tokens, audit log |
| Guardrail host | `yunq hook {claude-code, check, install, approve, audit, reset-*}` — ~7ms p50 per write |
| Remediation | `core/remediation`: `RemediationEngine` over `LlmProvider` + `Sandbox` ports, generate → sandbox → re-scan → verdict |
| LLM adapters | `infra/llm`: Anthropic Messages API + OpenAI-compatible (Groq/DeepSeek/Ollama/vLLM/LiteLLM) |
| CLI | `scan`, `fix`, `hook`, `init`, `wizard` |
| Coverage ingest | LCOV, Cobertura, JaCoCo, llvm-cov, Istanbul — with per-line hit detail (`FileLineCoverage`) |
| ALM adapters | GitHub, GitLab, Bitbucket, Azure DevOps |
| CI | `.github/workflows/ci.yml` — tests, clippy, benchmark regression gate (10% throughput drop fails), mutation gate |
| Performance | **~67.6k LOC/s** measured floor on a throttled runner; target ≥100k. The "~398k LOC/s" figure that circulated earlier is retracted — no harness ever produced it |
| Hosted layer | `yunq-cloud`, private repo (API server, worker, Postgres, frontend) — out of scope here |

**The honest gap:** yunq can judge an edit in 7ms and cannot make one. `yunq
fix` proposes a single-issue patch and stops. There is no session, no tool
loop, no task decomposition, no multi-file change, no orchestration. That gap
is workstream A.

---

## A. `yunq agent` — the native agent runtime

**Decision: build natively on the existing ports. Do not fork ZeroClaw.**

ZeroClaw ([zeroclaw-labs/zeroclaw](https://github.com/zeroclaw-labs/zeroclaw))
is the closest prior art — Rust, 3–5MB, ~10ms startup, tool allowlists,
workspace isolation, dual MIT/Apache-2.0 so a fork is legally free. It is
still the wrong base. It is a *personal-assistant* runtime whose surface area
is 30+ delivery channels (Discord, Telegram, Matrix, email, voice); the part
that matters to a coding agent is its provider abstraction and tool
allowlist, and yunq already has both (`infra/llm`, `core/agent-policy`).
Forking would buy a session loop and pay for it with a permanent rebase tax
against an upstream steering somewhere else entirely. Read it for its
workspace-isolation and pairing design; write our own runtime.

New crate `bin/agent` (composition root) plus whatever pure logic it needs in
`core/agent` — the split follows the existing rule: the loop's decision logic
is pure and unit-testable, the I/O is the binary's problem.

- **A1 — Session + tool loop.** The missing primitive. A conversation with an
  `LlmProvider`, a tool registry, and a turn loop that terminates. Tools ship
  as a closed, declared set (`read`, `write`, `edit`, `search`, `run`,
  `scan`), never an open shell passthrough. `Sandbox` (already a port) is how
  `run` executes.
- **A2 — Policy as the referee, in-process.** `yunq hook` pays ~7ms of
  process startup per write because a third-party host has no other way in.
  Our own agent has no such excuse: `AgentPolicy::evaluate` runs in-process,
  on the proposed content, before the write syscall. Same policy file, same
  causes, same circuit breaker, same audit log — a `yunq-policy.toml` written
  for Claude Code governs `yunq agent` unchanged. This is the feature. An
  agent that shares an enforcement engine with the CI gate cannot drift from
  it.
- **A3 — Analyzer as the definition of done.** A task is complete when the
  embedded `AnalyzerService` says the intended issue is gone and no new
  issue appeared — the `RemediationEngine` verdict logic, lifted from
  single-issue scope to task scope. No self-assessment turn, ever.
- **A4 — Cost and termination.** The circuit breaker (3 consecutive denials
  per rule) and loop guard already exist for hook callers and become the
  agent's own stopping conditions. Add a token/turn budget with an explicit
  exhaustion verdict. A runtime that can burn an unbounded budget against the
  same wall is not shippable.
- **A5 — TUI.** Last, deliberately. A headless `yunq agent run --task` that
  is scriptable and CI-usable is worth more than a chat interface, and it is
  what the swarm in workstream B drives.

**Non-goal:** yunq agent is not a general assistant. No chat channels, no
plugins, no MCP client. It edits repositories under a policy.

## B. `yunq swarm` — multi-agent orchestration

Adapted from Uncle Bob's
[swarm-forge](https://github.com/unclebob/swarm-forge). Take the protocol,
not the implementation: swarm-forge coordinates through tmux sessions and a
shared `scripts/` directory on each agent's PATH, which is a shell-level
solution to a problem yunq can solve in-process and in-binary.

What transfers:

- **Worktree-per-agent isolation.** One `git worktree` per agent, so
  concurrent agents never contend on the index. Direct fit with the existing
  `Sandbox` port, whose git-worktree adapter already exists for remediation.
- **Durable, validated handoffs.** Files under `.yunq/handoffs/`
  (`outbox`/`inbox`/`sent`/`failed`), not direct messaging — a crashed agent
  loses nothing and a malformed handoff lands in `failed` instead of
  corrupting a peer's context. yunq validates handoffs against a schema; the
  denial DTO from `hook check --format json` is the natural payload for
  "agent B, here is exactly why your edit was refused".
- **Role constitutions.** Layered prompts per role (coder, architect,
  cleaner, QA), composed over a shared base.

What yunq adds that swarm-forge deliberately does not have: swarm-forge
enforces discipline "through workflow structure rather than access controls".
yunq has the access controls. **Roles get policy scopes** — the cleaner may
not touch `.github/workflows/**`, the coder may not edit the ruleset that
judges it, QA gets read + `scan` and no write at all. `protected_path` already
expresses this; the swarm just needs per-role policy resolution.

- **B1** Worktree lifecycle + role config (`yunq.toml` `[swarm]` table).
- **B2** Handoff protocol: schema, durable queue, validation, replay.
- **B3** Per-role policy scoping in `core/agent-policy`.
- **B4** Topologies (two-pack / four-pack), driven by headless `yunq agent`.

## C. CRAP — risk as complexity × untestedness

From [crap4clj](https://github.com/unclebob/crap4clj) (and its `crap4java` /
`crap4go` siblings). Formula:

```
CRAP(f) = CC(f)² × (1 − coverage(f))³ + CC(f)
```

Bands: 1–5 low risk, 5–30 refactor candidate, 30+ complex *and* untested —
the code that is most expensive to change and least safe to change.

This is the cheapest high-value item on the roadmap because **both inputs
already exist and have never been multiplied**. Cyclomatic complexity is in
`rulesets/code-smells/src/complexity.rs`; per-line coverage arrives through
five ingest formats and is already exposed as `FileLineCoverage` (1-based
line → hit count). Per-function coverage is the intersection of a function's
`Span` with that map — no new ingest, no new parser, no new port.

- **C1** `rulesets/crap`: a `Rule` computing per-function CC, reading
  per-function coverage from the analysis context, emitting
  `crap:high-risk-function` with the score and both inputs in the message.
- **C2** `crap` as a gate-condition metric (worst score, and count above
  threshold), so a quality gate can fail on risk rather than on raw coverage —
  a coverage number alone says nothing about *where* the untested code is.
- **C3** Sort `yunq scan` output by CRAP when coverage is present. The ranked
  refactor list is the actual deliverable; the rule is just how it is
  computed.

**Design note:** a function with no coverage data must not be scored as
0%-covered — that would make every repository without a coverage report look
catastrophic. Absent data means the rule stays silent, matching the existing
fail-open posture everywhere else in the codebase.

## D. Architecture fitness — components, the main sequence, and a viewer

From [dependency-checker](https://github.com/unclebob/dependency-checker) and
[arch-view](https://github.com/unclebob/arch-view). This is the most
ideologically aligned item on the list: yunq's README already claims *"the
directory structure is the architecture"*, and yunq currently proves that
claim with Cargo and one rule (`architecture:dependency-cycle`). Everything
else is convention.

`core/import-graph` already builds the edge set and detects cycles. What is
missing is the layer above it: components, declared boundaries, and metrics.

- **D1 — Components from topology.** Derive a component per source subtree
  (dependency-checker derives from the second namespace segment; yunq's
  equivalent is the workspace member / directory tier). No new config to
  state what is already on disk.
- **D2 — Declared boundaries.** `[architecture]` in `yunq.toml`:
  `allowed_dependencies` (anything unlisted is a violation) and
  `forbidden_dependencies` (explicitly blocked edges), plus per-edge
  exceptions. A violation is an ordinary `Issue`, so it flows into gates,
  SARIF, PR decoration and the agent policy with zero new plumbing — an agent
  that adds a `core → infra` import gets denied *at write time*, which is the
  whole point.
- **D3 — Instability / Abstractness and the main sequence.** Per component:
  I = Ce/(Ca+Ce), A = abstract types / total types, D = |A+I−1|. Classify
  into the zone of pain (concrete + stable) and the zone of uselessness
  (abstract + unstable). yunq is a Martin-shaped architecture; it should be
  able to measure itself with Martin's own metrics and publish the number.
- **D4 — `yunq arch`.** Layered interactive view: components as boxes ranked
  by topological layer, cycles in red, drill-down, hover for the specific
  import paths. arch-view exports EDN for headless use; yunq exports JSON,
  and renders as a self-contained HTML file rather than a desktop window —
  it must work over SSH and attach to a PR comment.

## E. Mutation testing, widened

The CI mutation gate exists and works — it caught a real regression in
`yunq-agent-policy` (`Evaluation::is_empty` and `AgentPolicy::enabled` had
only true-case assertions, so the "replace body with `true`" mutant survived
both). It is scoped to exactly one crate.

Coverage says a line ran. Mutation says a test would have *noticed*. With A
and B shipping code written by yunq's own agent, that distinction stops being
academic: the agent optimises for whatever gate we hand it, and a coverage
gate is trivially satisfiable with assertion-free tests.

- **E1** Widen crate by crate, cheapest first, admitting each only once it
  proves fast enough to stay in CI: `profiles` → `import-graph` →
  `duplication` → `taint` → `rules-engine`.
- **E2** Mutation score as a first-class gate metric (the default gate
  already reserves it) and a mandatory condition on any crate `yunq agent`
  writes to.
- **E3** Evaluate `clj-mutate`/`mutate4go`-style scoping so a PR mutates only
  what it touched. Full-workspace mutation will not fit in a PR's time
  budget; diff-scoped mutation might.

## F. Performance debt (carried forward, unchanged in priority)

Target remains **≥100k LOC/s per core**; measured floor ~67.6k. The three
open items, in the order most likely to close the gap:

- **Arena-allocated AST.** Nodes are individually heap-allocated
  (`Vec<AstNode>` children). Node-kind labels are interned and text is
  zero-copy already; the allocation count per parse is the remaining term.
- **Cross-file phase caching.** The per-file analysis cache exists; the
  cross-file phase re-parses every file every run with no cache and no
  dependency-aware invalidation.
- **mmap for large files.** Lower value — needs unsafe to avoid re-copying
  into the existing `Arc<str>` buffer, and only pays on unusually large
  files.

CI gates on a 10% regression against the PR's own merge base, measured on the
same runner, so the gate never compares across hardware generations. Peak RSS
and p50/p99 per-file latency are reported but not yet gated — no established
target.

## G. Platform threads still open

- **Cross-file at write time.** `yunq hook`'s verdict is single-file, so
  cross-file taint and the cross-file architecture rules never participate in
  a pre-write decision. D2's import-graph checks are the first cross-file
  signal cheap enough to run there.
- **Provenance beyond the local ledger.** `.yunq-provenance.json` is
  per-path, local, gitignored, and does not reach the project-level quality
  gate.
- **Gherkin evidence is a claim, not a proof.** A `@covers` tag asserts that
  a scenario covers a path; nothing verifies the scenario runs or passes.
  Correlating execution with source paths (step-definition file/line metadata
  from a cucumber JSON report) is unstarted. The portable-pipeline shape in
  [Acceptance-Pipeline-Specification](https://github.com/unclebob/Acceptance-Pipeline-Specification)
  — Gherkin → JSON IR → generated entry points → runner — is the reference
  design if this is ever taken further.
- **Codex CLI.** Its tool hooks fire on shell commands only, not file writes,
  so no edit-time guardrail can be installed there. `yunq hook check` remains
  the portable path.
- **MCP.** Still no server, still deliberately. An MCP tool is *consulted*,
  and a model optimising for task completion learns not to consult something
  that might refuse it; a host hook is *invoked* and cannot be routed around.
  The one defensible use is planning-time and read-only —
  `yunq://policy/current` and `yunq://architecture/blueprint` ingested once
  before an agent plans an edit, so it starts from "this repo blocks `eval`"
  instead of discovering it by denial. Context, never enforcement.

---

## Decisions taken in this reform

| Decision | Rationale |
|---|---|
| Build `yunq agent` natively; do not fork ZeroClaw | Its differentiated core (providers, tool allowlist, isolation) is already in `infra/llm` + `core/agent-policy`; its bulk (30+ chat channels) is off-mission. A fork buys a session loop for a permanent rebase tax. |
| Policy enforcement in-process for our own agent | The 7ms process spawn is a tax paid to third-party hosts. Sharing one engine between agent, hook and CI gate is what stops the three from drifting. |
| Swarm takes swarm-forge's protocol, not its tmux | Durable handoff files and worktree isolation are the load-bearing ideas; tmux is a shell workaround for a problem a single binary does not have. |
| Roles get policy scopes | swarm-forge enforces discipline through workflow structure and says so explicitly. yunq has actual access controls and should use them. |
| CRAP before any new coverage work | Both inputs already exist and have never been multiplied. Highest ratio of signal to new code on the roadmap. |
| Architecture rules emit ordinary `Issue`s | Free reuse of gates, SARIF, PR decoration, and — critically — the agent policy, so a boundary violation is denied at write time rather than reported after merge. |
| ROADMAP split from DEVLOG | 1280 lines of session narrative made the plan unfindable. The rationale is worth keeping; it just is not a plan. |

## Sequencing

```
now ──► C (CRAP)            ─┐
        D1–D2 (boundaries)   ├─► independent, ship in any order
        E1 (mutation widen) ─┘

then ─► A1–A4 (agent runtime core)   ─► A5 (TUI)
                │
                └─► B1–B4 (swarm)  [needs headless A]

parallel ─► F (performance)  — continuous, gated in CI
            D3–D4 (I/A + arch view) — after D1–D2
            G — opportunistic
```

C, D1–D2 and E1 are startable immediately and touch nothing the agent work
touches. A is the long pole and everything in B depends on A running
headless. F is continuous and already gated. D3–D4 need D1's component model
first.

## Non-goals

- A general-purpose assistant runtime. No chat channels, no personal-assistant
  surface, no plugin marketplace. yunq edits repositories under a policy.
- An MCP server for enforcement (see G).
- An edition wall. Everything in this roadmap ships in the open repo; the
  hosted layer in `yunq-cloud` is convenience, never a gatekeeper.
- Self-assessment. No turn in which the model grades its own edit. The
  analyzer is the judge, or there is no verdict.
