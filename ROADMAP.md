# yunq Roadmap

> The forward-looking plan. Historical session-by-session narrative — and the
> design rationale behind everything already built — lives in
> [DEVLOG.md](DEVLOG.md).

## Mission

yunq began as an analyzer: *"what is wrong with this code?"*. It then became a
guardrail: *"may this write land?"*. It is now also an agent runtime:
**yunq writes the code too, and is the only agent runtime that cannot approve
its own work.**

Every coding agent on the market grades its own homework. yunq is the one
project where the judge already exists as a separate, deterministic,
150-rule artifact that predates the writer. In `yunq agent`, no edit reaches
disk without passing the same `core/agent-policy` evaluation that gates a
third-party agent, and no task is reported complete without the analyzer
agreeing.

## Where we are

| Area | State |
|---|---|
| Workspace | Hexagonal, enforced by Cargo: `bin → {infra, parsers, rulesets} → core` |
| Languages | 24 tree-sitter grammars |
| Rules | 150 `Rule`/`CrossFileRule` impls across 15 ruleset crates, including a hexagonal/DDD/SOLID gatekeeper for TypeScript, Python, Rust and Go |
| Analysis core | `rules-engine`, `ast`, `profiles`, `taint` (intra + cross-file), `duplication`, `symbols`, `import-graph`, `crap` (risk = complexity² × untestedness³ + complexity) |
| Agent guardrail | `core/agent-policy`: blocking/advisory rules, protected paths, provenance, Gherkin evidence, circuit breaker, loop guard, gate-gaming detection — hosted by `yunq hook` |
| Agent runtime | `core/agent` (session loop, closed tool set, in-process write gate, analyzer-as-done, budget/repeat guard, PR-feedback watch) via `yunq agent {run, tui, watch-pr}` |
| Swarm | `core/swarm` (worktree isolation, durable handoffs, per-role policy scoping, topologies) via `yunq swarm {roles, run, ...}` |
| Remediation | `core/remediation`: generate → sandbox → re-scan → verdict |
| CLI | `scan`, `fix`, `hook`, `agent`, `swarm`, `init`, `wizard` |
| Coverage ingest | LCOV, Cobertura, JaCoCo, llvm-cov, Istanbul |
| ALM adapters | GitHub, GitLab, Bitbucket, Azure DevOps |
| CI | tests, clippy, benchmark regression gate (10%), mutation gate |
| Performance | ~67.6k LOC/s measured floor; target ≥100k |
| Hosted layer | `yunq-cloud`, private repo — out of scope here |

Workstreams A (agent runtime) and B (swarm) are fully shipped. C1–C3 (CRAP),
D1–D3 (architecture fitness: boundaries, main sequence, tactical DDD), and
E4–E5 (gate-gaming detection) are fully shipped. What's below is what's
actually left.

---

## Open work

**Performance** — target ≥100k LOC/s per core, measured floor ~67.6k:
- Cross-file phase caching. The per-file analysis cache exists; the
  cross-file phase re-parses every file every run with no cache and no
  dependency-aware invalidation.
- mmap for large files. Lower value — needs `unsafe` to avoid re-copying
  into the existing `Arc<str>` buffer, and only pays on unusually large files.
- (Arena-allocated AST was tried and dropped — see DEVLOG. Raw parse latency
  improved but full-pipeline scan time did not; not worth the diff.)

**C4 — Run coverage, don't only ingest it.** CRAP currently needs a coverage
report piped in. Detect the project's coverage command from its build files
(`Cargo.toml` → `cargo llvm-cov`, `go.mod` → `go test -coverprofile`,
`pom.xml` → JaCoCo, `pyproject.toml` → coverage.py, `package.json` → the
runner's own flag). Config wins over detection; a detected command is
*offered* for persistence in `yunq.toml`, never silently re-run.
**Opt-in only** (`--run-coverage` or explicit config) — a static analyzer
executing build commands on a bare `yunq scan` is a footgun.

**E1–E3 — Mutation testing, further widening.** `profiles`, `import-graph`,
and `duplication` are admitted to the CI mutation gate (`dogfood-mutation`
matrix), each clearing the 60% score bar. Remaining: `taint` → `rules-engine`
→ `core/agent` (the highest-consequence decision logic added since
`core/agent-policy` itself). Also open: mutation score as a mandatory gate
on any crate `yunq agent` writes to (E2), and diff-scoped mutation so a PR
mutates only what it touched, since full-workspace mutation won't fit a PR's
time budget (E3).

**D4 — `yunq arch` viewer.** Layered interactive view: components as boxes
ranked by topological layer, cycles in red, drill-down, hover for the
specific import paths. Renders as a self-contained HTML file (must work over
SSH and attach to a PR comment), not a desktop window.

**Platform threads:**
- **Cross-file at write time.** `yunq hook`'s verdict is single-file, so
  cross-file taint and the cross-file architecture rules never participate
  in a pre-write decision.
- **Provenance beyond the local ledger.** `.yunq-provenance.json` is
  per-path, local, gitignored, and does not reach the project-level quality
  gate.
- **Gherkin evidence is a claim, not a proof.** A `@covers` tag asserts a
  scenario covers a path; nothing verifies the scenario runs or passes.
- **Codex CLI.** Its tool hooks fire on shell commands only, not file
  writes, so no edit-time guardrail can be installed there.
- **MCP.** Still no server, still deliberately — a host hook is *invoked*
  and cannot be routed around, while an MCP tool is only *consulted*. The
  one defensible use is planning-time, read-only context.

## Non-goals

- A general-purpose assistant runtime. No chat channels, no personal-assistant
  surface, no plugin marketplace. yunq edits repositories under a policy.
- An MCP server for enforcement.
- An edition wall. Everything here ships in the open repo; the hosted layer
  in `yunq-cloud` is convenience, never a gatekeeper.
- Self-assessment. No turn in which the model grades its own edit. The
  analyzer is the judge, or there is no verdict.
