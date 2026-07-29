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
| Analysis core | `rules-engine`, `ast`, `profiles`, `taint` (intra + cross-file), `duplication`, `symbols`, `import-graph`, `crap` (CC² × (1−coverage)³ + CC risk scoring) |
| Agent guardrail | `core/agent-policy` (1039 LOC): blocking/advisory rules, protected paths (incl. its own policy/gate config files), provenance, Gherkin evidence, circuit breaker, loop guard, single-use escalation tokens, audit log, gate-gaming detection (suppressions, skipped tests) |
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
- **A5 — Late feedback is part of done.** A3 defines "done" as the analyzer
  agreeing, which is true right up until the agent opens a PR — at which
  point review bots and CI post minutes after the push, and a PR that looked
  clean the instant it was pushed is not a PR that is finished. The agent
  needs to wait out that window rather than declaring victory into it: a
  backoff schedule, a settle window so one review batch is collected as one
  batch, and a ledger of already-triaged items so a re-run does not
  re-report what it already handled. Four terminal states, not two — quiet,
  new feedback, bot all-clear, and **inconclusive**. That last one carries
  the weight: "we looked and saw nothing" and "we could not look" must never
  collapse into the same exit code, which is the same discipline the rest of
  the codebase's fail-open behaviour needs everywhere. Fail-open must not
  mean fail-blind. Every ALM API call is status-checked on the way in for
  the same reason: error bodies arrive on the same channel as data, so an
  unchecked call reports a rate-limit page as findings. Lives in
  `infra/github` with the other ALM adapters.
- **A6 — TUI.** Last, deliberately. A headless `yunq agent run --task` that
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

- **C1** ✅ **done, as `core/crap`, not `rulesets/crap`.** Turned out `Rule`
  cannot read "the analysis context" as this bullet originally assumed:
  `AnalyzerService::analyze_files` returns a complete `AnalysisReport` before
  `bin/cli` has even read a coverage file off disk (`ingest_coverage` runs
  strictly after `scan_with_project_config`), so no `Rule::check(file, ast)`
  call ever has coverage in scope, regardless of how the trait is extended.
  Shipped instead as a plain algorithm crate (`yunq-crap`, mirroring
  `core/duplication`'s role: a pure engine `AnalyzerService`/the composition
  root invoke directly, not a `Rule` impl) plus plumbing: per-function
  cyclomatic complexity, extracted from `rulesets/code-smells::ComplexityRule`
  into `core/rules-engine::function_complexity` so both the existing rule and
  the new metric share one walk, is now computed once per file inside
  `AnalyzerService::analyze_one` and threaded onto
  `AnalysisReport::function_complexities` the same way `structural_metrics`
  already is (also plumbed through `CachedAnalysis`/`FileAnalysisCache` with
  the same fail-open migration older field additions use). `bin/cli`'s
  `crap` module calls `AnalysisReport::compute_crap_findings()` — a method on
  the report itself, mirroring the existing `coverage_on_new_code` precedent
  of joining two already-stored fields — right after `ingest_coverage`, and
  folds the results into ordinary `crap:high-risk-function` issues via
  `add_external_issues` (Major 5–30, Critical 30+), so they flow into SARIF,
  PR decoration and the agent policy with zero new plumbing, same as the
  gate-gaming findings did.
- **C2** ✅ **done.** `crap_worst_score` and `crap_high_risk_functions` (count
  scoring above the 30-point high-risk band) are ordinary measures on
  `MEASURE_TABLE`, `None` until a coverage report is ingested. The default
  gate now includes `crap_high_risk_functions > 0` — zero-tolerance, the same
  treatment blocker/critical issues get, defensible because the threshold has
  already done the filtering a raw coverage percentage can't.
- **C3** ✅ **done.** `render_text` prints a "Risk hotspots (CRAP)" section,
  worst score first; `--format json`'s `crap` array is the same ranked list,
  each entry carrying the score and both inputs (`sorted_crap`,
  `output.rs`). Left the main issue list's severity → file → line sort
  untouched rather than overloading it with one rule's own metric — the
  ranked list lives alongside it, not instead of it.
- **C4** Run coverage, don't only ingest it. Today CRAP needs a report piped
  in, which means the metric is only seen by people who already configured
  it — the ones who need it least. Detect the project's coverage command from
  its build files (`Cargo.toml` → `cargo llvm-cov --lcov`, `go.mod` → `go
  test -coverprofile`, `pom.xml` → JaCoCo, `pyproject.toml` → coverage.py,
  `package.json` → the runner's own flag) so CRAP works on first invocation.
  Config wins over detection, and a detected command is *offered* for
  persistence in `yunq.toml` rather than silently re-detected each run.
  **Opt-in, always** (`--run-coverage` or explicit config): a static analyzer
  that executes a repository's build commands on a bare `yunq scan` is a
  footgun, and the whole value of the analyzer is that running it is safe.
  Of the formats a survey of the ecosystem turns up, the only real ingest gap
  is Go's native coverprofile — the other four are already in.

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

## E. Gate integrity — mutation testing and anti-gaming

Two halves of one question: **is this gate load-bearing, or does it only look
like it?** Mutation testing asks whether the suite would notice a regression.
Anti-gaming asks whether the gate is still there at all. An agent optimising
for a gate has two strategies available — satisfy it, or remove it — and
right now the second is both cheaper and invisible.

### Mutation testing, widened

The CI mutation gate exists and works — it caught a real regression in
`yunq-agent-policy` (`Evaluation::is_empty` and `AgentPolicy::enabled` had
only true-case assertions, so the "replace body with `true`" mutant survived
both). It is scoped to exactly one crate.

Coverage says a line ran. Mutation says a test would have *noticed*. With A
and B shipping code written by yunq's own agent, that distinction stops being
academic: a coverage gate is trivially satisfiable with assertion-free tests.
The standard worth stating plainly is that **the suite must be able to catch
a revert of the change** — a test that passes whether or not the change is
there asserts nothing. Every mature agent workflow states that as a rule in a
prompt and hopes. A surviving mutant is the mechanical proof, which is the
only version of the rule that survives contact with a system optimising
against it.

- **E1** Widen crate by crate, cheapest first, admitting each only once it
  proves fast enough to stay in CI: `profiles` → `import-graph` →
  `duplication` → `taint` → `rules-engine`.
- **E2** Mutation score as a first-class gate metric (the default gate
  already reserves it) and a mandatory condition on any crate `yunq agent`
  writes to.
- **E3** Evaluate `clj-mutate`/`mutate4go`-style scoping so a PR mutates only
  what it touched. Full-workspace mutation will not fit in a PR's time
  budget; diff-scoped mutation might.

### Gate-gaming detection

The forbidden shortcut is not writing bad code — it is quietly lowering the
bar and then clearing it. Concretely: adding a coverage exclusion, adding a
suppression (`#[allow]`, `// nolint`, `# noqa`, `eslint-disable`,
`# type: ignore`), marking a test `#[ignore]`/`skip`, deleting a failing
test, weakening an assertion, or lowering a threshold in the project's own
config. Each is legitimate when a human does it deliberately and reviewably;
each is a silent gate bypass when it appears inside a change whose purpose
was to pass that gate.

The sharpest case is the self-referential one: an agent denied by
`yunq-policy.toml` editing `yunq-policy.toml` to move the offending rule into
`advisory_rules`. That is not a hypothetical — it is the single
highest-leverage move available to anything optimising for "the write lands".
A referee whose rulebook the players can edit is not a referee.

- **E4** ✅ **done.** `ai:suppression-added` and `ai:test-skipped` in
  `bin/cli/src/hook.rs` (`suppression_added_findings`/`test_skip_added_findings`),
  following the diff-against-on-disk shape `new_dependency_findings` set for
  the supply-chain guard — a suppression/skip already on a line before this
  write is not a finding, the same line introduced by it is. Covers
  `#[allow(...)]`, `eslint-disable`, `# noqa`, `# type: ignore`,
  `# pylint: disable`, `//nolint`, `# pragma: no cover`, `// istanbul ignore`
  (suppressions and coverage exclusions, one rule) and `#[ignore]`,
  `@pytest.mark.skip`, `@unittest.skip`, `.skip(`, `xit(`, `xdescribe(`
  (skipped tests, the other). Both `Severity::Major`, neither in the default
  policy's `blocking_rules` — opt-in via `advisory_rules`/`blocking_rules`,
  documented in `hook_install.rs`'s `POLICY_TEMPLATE`. Not attempted here:
  deleting a failing test outright and weakening an existing assertion — both
  need identifying *which* test/assertion changed meaning, not just spotting a
  new marker substring, and are open follow-ups under this same item.
- **E5** ✅ **done.** `hook install`'s `POLICY_TEMPLATE`
  (`bin/cli/src/hook_install.rs`) lists `yunq-policy.toml` (the rulebook
  itself) and `yunq.toml` (gate thresholds/exclusions) as `[[protected_path]]`
  entries alongside the pre-existing `.github/workflows/**`, so an agent
  denied by its own policy cannot resolve the denial by editing the policy.

**Bug found by dogfooding, not on this list, fixed alongside it:**
`bin/cli/src/hook.rs::analyze_content` mapped only `report.issues()` into
policy findings, never `report.hotspots()`. `owasp:command-execution` is
`FindingKind::Hotspot` by design (`rulesets/owasp/src/command_exec.rs`) and
is one of six rules in `AgentPolicy::default()`'s own built-in
`blocking_rules` — meaning the zero-config guardrail's flagship README
example ("an agent that tries to write a shell-injection sink gets its own
tool call denied") was not actually true out of the box; hotspot-classified
rules could never deny a write regardless of policy. Found by installing
`hook install` on this repository and hand-verifying `yunq hook claude-code`
against a real `os.system(user_input)` payload, which returned silent
`exit 0` where it should have denied. Fixed by folding `report.hotspots()`
into the same mapping, borrowing each hotspot's severity from the active
quality profile (`Hotspot` itself carries none — that is what distinguishes
it from an `Issue`) since `block_at_or_above` still needs one to compare
against, while `blocking_rules`/`escalate_rules` match by rule id regardless.
Regression-tested (`a_hotspot_rule_is_included_in_analyze_content_findings`,
`the_built_in_default_policy_actually_denies_a_hotspot_blocking_rule`).

**Design constraint, and why this is not just another rule:** every one of
these findings needs a *before* state, and the `Rule` trait deliberately sees
only one file's current content — a suppression that was always there is not
a finding, and the same line added in this change is. So these follow the
precedent `hook.rs::new_dependency_findings` already set for the supply-chain
guard: diff against the on-disk version at `PreToolUse` time and emit an
ordinary `Finding` that flows through `AgentPolicy::evaluate` like any other.
Same shape, second instance — which is a good sign the shape is right, and a
signal it may deserve to be a named abstraction rather than a third
hand-rolled copy.

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
| Gates are values, not instructions | Surveying the agent-workflow ecosystem (e.g. `theam/claude-dev-kit`, Apache-2.0 — a ~2500-line Claude Code plugin) shows the state of the art enforcing gates by *asking*: "never report a gate as passed without having run it" is a prompt line a model can violate silently. yunq is the one project positioned to make that structurally true, because the judge is a separate deterministic artifact. Learn the pipeline shape from such kits; do not adopt their enforcement architecture. |
| The policy file is itself a protected path | The highest-leverage move for anything optimising to make a write land is editing the rulebook, not the code. |
| Reimplement borrowed designs; do not vendor them | Useful prior art in this space is largely Apache-2.0 while yunq is MIT. Apache's attribution/NOTICE/patent terms travel with copied source; behaviour learned from reading it does not. |
| ROADMAP split from DEVLOG | 1280 lines of session narrative made the plan unfindable. The rationale is worth keeping; it just is not a plan. |

## Sequencing

```
done ──► E4–E5 (gate-gaming)
         C1–C3 (CRAP)

now  ──► D1–D2 (boundaries)     ─┐
         E1  (mutation widen)   ─┘ independent, ship in any order

then ─► A1–A4 (agent runtime core) ─► A5 (PR feedback loop) ─► A6 (TUI)
                │
                └─► B1–B4 (swarm)  [needs headless A]

parallel ─► F (performance)  — continuous, gated in CI
            C4 (run coverage) — now startable, C1–C3 shipped
            D3–D4 (I/A + arch view) — after D1–D2
            G — opportunistic
```

E4–E5 shipped first, ahead of everything else in their group, because they
are the precondition for the rest: every gate A and B are measured against is
only worth building if the agent cannot quietly edit it. C1–C3 (CRAP) shipped
next — cheapest high-value item, both inputs already existed. What's left in
the first group (D1–D2, E1) is startable immediately and still touches
nothing the agent work touches — pick either next. A is the long pole
and everything in B depends on A running headless. F is continuous and
already gated. D3–D4 need D1's component model first.

## Non-goals

- A general-purpose assistant runtime. No chat channels, no personal-assistant
  surface, no plugin marketplace. yunq edits repositories under a policy.
- An MCP server for enforcement (see G).
- An edition wall. Everything in this roadmap ships in the open repo; the
  hosted layer in `yunq-cloud` is convenience, never a gatekeeper.
- Self-assessment. No turn in which the model grades its own edit. The
  analyzer is the judge, or there is no verdict.
