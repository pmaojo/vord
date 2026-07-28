# yunq

A static analysis platform in Rust.

## Topology

The directory structure *is* the architecture — nested workspace globs define the boundaries:

```
yunq/
├── core/                       # PURE LOGIC — no I/O, no async runtime, no serde
│   ├── ast/                    # yunq-ast: neutral AST, LanguageIdentifier, SourceFile
│   ├── profiles/               # yunq-profiles: RuleId, Severity, QualityProfile, QualityGate, Rating
│   ├── rules-engine/           # yunq-rules-engine: ports (traits), Rule, CrossFileRule, AnalyzerService
│   ├── taint/                  # yunq-taint: intra-file + cross-file inter-procedural taint analysis
│   ├── agent-policy/           # yunq-agent-policy: Agent Permission Policy — may this agent write land?
│   └── duplication/            # yunq-cpd: copy-paste detection (rolling-window hashes)
├── infra/                      # OUTBOUND ADAPTERS
│   ├── memory/                 # in-memory storage/metrics (CLI, tests)
│   ├── fs/                     # gitignore-aware source loader, LCOV parser, caches
│   └── postgres/               # sqlx IssueStorage/IssueReader/MetricsTracker/changelog + JobQueue (scan_jobs table)
├── parsers/                    # INBOUND ADAPTERS (tree-sitter → neutral AST)
│   ├── treesitter-typescript/
│   ├── treesitter-rust/
│   ├── treesitter-python/
│   └── treesitter-go/
├── rulesets/                   # PLUGINS implementing the Rule trait
│   ├── owasp/                  # secrets, eval/exec, command-exec hotspots, taint injection (incl. cross-file)
│   ├── code-smells/            # TODO/FIXME, long functions, unwrap/expect, complexity (cyclomatic + cognitive)
│   └── rust/                   # Rust-only: undocumented unsafe, mem::transmute/forget, process::exit/abort
└── bin/                        # COMPOSITION ROOTS (testing dead-zones)
    ├── cli/                    # yunq scan — local end-to-end analysis
    ├── server/                 # axum API: scans, issues, hotspots, rules catalog
    └── worker/                 # scan_jobs consumer → AnalyzerService → Postgres
```

Dependency direction is enforced by Cargo: `bin → {infra, parsers, rulesets} → core`. The core defines **ports** (`AstParser`, `IssueStorage`, `IssueReader`, `IssueFacetReader`, `IssueWorkflow`, `HotspotStorage`, `MetricsTracker`, `JobQueue`, `AnalysisCache`); adapters implement them (DIP). Domain types are validated newtypes with fallible constructors and **no `serde::Deserialize`** — every edge (HTTP, Postgres, tree-sitter) owns its DTOs and translates in. Adding a language or ruleset means a new crate registered at a composition root; the engine never changes (OCP).

Proof of purity: `cargo tree -p yunq-rules-engine` — only core crates and `thiserror`.

```mermaid
graph TD
    subgraph bin["bin/ — composition roots"]
        CLI[yunq-cli]
        SERVER[yunq-server]
        WORKER[yunq-worker]
    end
    subgraph parsers["parsers/ — inbound adapters"]
        PTS[yunq-parser-typescript]
        PRS[yunq-parser-rust]
        PPY[yunq-parser-python]
        PGO[yunq-parser-go]
    end
    subgraph rulesets["rulesets/ — plugins"]
        ROW[yunq-rules-owasp]
        RSM[yunq-rules-smells]
    end
    subgraph infra["infra/ — outbound adapters"]
        IPG[yunq-infra-postgres]
        IMEM[yunq-infra-memory]
        IFS[yunq-infra-fs]
    end
    subgraph core["core/ — pure domain logic"]
        AST[yunq-ast]
        PROF[yunq-profiles]
        ENGINE[yunq-rules-engine<br/>ports + AnalyzerService]
        TAINT[yunq-taint]
        CPD[yunq-cpd]
    end
    CLI --> PTS
    CLI --> PRS
    CLI --> PPY
    CLI --> PGO
    CLI --> ROW
    CLI --> RSM
    CLI --> IMEM
    CLI --> IFS
    SERVER --> IPG
    SERVER --> ROW
    SERVER --> RSM
    WORKER --> IPG
    WORKER --> PTS
    WORKER --> PRS
    WORKER --> PPY
    WORKER --> PGO
    WORKER --> ROW
    WORKER --> RSM
    PTS --> AST
    PRS --> AST
    PPY --> AST
    PGO --> AST
    ROW --> ENGINE
    ROW --> TAINT
    RSM --> ENGINE
    IPG --> ENGINE
    IMEM --> ENGINE
    IFS --> ENGINE
    ENGINE --> AST
    ENGINE --> PROF
    ENGINE --> CPD
    TAINT --> AST

    style core fill:#1a2b3c,stroke:#4a9eff,color:#fff
    style infra fill:#2b1a1a,stroke:#ff8a4a,color:#fff
    style parsers fill:#1a2b1a,stroke:#4aff8a,color:#fff
    style rulesets fill:#2b2a1a,stroke:#ffdd4a,color:#fff
    style bin fill:#241a2b,stroke:#c04aff,color:#fff
```

No arrow ever points into `core/`. The core defines ports; everything else implements or consumes them.

## Quickstart

```sh
cargo run -p yunq-cli                  # no args, in a terminal: interactive wizard
                                        # (scope: whole repo / branch diff / path — then
                                        # agent prompt, guided remediation, or CI install)
cargo test --workspace                 # unit (fakes), fixtures, e2e — currently 80+ tests
cargo run -p yunq-cli -- scan fixtures # real scan: 4 languages, rules + taint + CPD + complexity
cargo run -p yunq-cli -- scan fixtures --format json
cargo run -p yunq-cli -- scan fixtures --fail-on critical      # exit 2 on severity breach
cargo run -p yunq-cli -- scan fixtures --enforce-gate          # exit 3 on quality gate failure
cargo run -p yunq-cli -- scan fixtures --coverage report.lcov  # ingest LCOV coverage
cargo run -p yunq-cli -- scan fixtures --cobertura report.xml # ingest Cobertura XML coverage
cargo run -p yunq-cli -- scan fixtures --jacoco report.xml    # ingest JaCoCo XML coverage
cargo run -p yunq-cli -- scan fixtures --llvm-cov report.json # ingest llvm-cov JSON coverage
cargo run -p yunq-cli -- scan fixtures --junit report.xml     # ingest JUnit test report
cargo run -p yunq-cli -- scan fixtures --mutation-report mutation.json  # ingest a Stryker-schema mutation report
cargo run -p yunq-cli -- scan fixtures --sarif ruff.sarif      # import another analyzer's findings
cargo run -p yunq-cli -- scan fixtures --sarif ruff.sarif --sarif eslint.sarif  # repeatable
cargo run -p yunq-cli -- init --yes                            # write .github/workflows/yunq.yml
cargo run -p yunq-cli -- hook install                          # gate an AI agent's writes (see below)
```

Example output:

```
BLOCKER  owasp:injection  vulnerable.ts:9:1  user input from `process.argv` reaches sink `eval`:
         `input` tainted by `process.argv`; `payload` tainted via `input`; `payload` reaches sink `eval`
```

## Server + worker (async pipeline)

The server enqueues `ScanJob`s into the `scan_jobs` table; workers claim them with `FOR UPDATE SKIP LOCKED` and wake up on `LISTEN`/`NOTIFY` (falling back to a 5s poll). No broker to run — it's the same Postgres database as issue storage:

```sh
export DATABASE_URL=postgres://yunq:yunq@localhost:5432/yunq

cargo run -p yunq-worker    # applies migrations, listens for scan jobs
cargo run -p yunq-server    # POST /scans {"project":"p","path":"/abs/checkout"}
```

The API surface: `POST /scans`, `GET /issues` (filters + pagination + facets), `POST /issues/{id}/transitions`, `PUT /issues/{id}/assignee`, `POST /issues/bulk-transition`, `GET /issues/{id}/changelog`, `GET /hotspots`, `PUT /hotspots/{id}/status`, `GET /rules`.

The server publishes its contract as **OpenAPI 3.1** at `GET /api-docs/openapi.json` (Swagger UI at `/swagger-ui`), generated with utoipa from the server-owned DTOs — the contract lives at the adapter boundary, domain types stay serde-free. Frontends can codegen clients from it (e.g. `openapi-typescript`). A committed export lives at [`api/openapi.json`](api/openapi.json); regenerate it any time with:

```sh
cargo run -p yunq-server -- openapi > api/openapi.json
```

## Agentic guardrail (Claude Code, Codex, pre-commit)

Every other entry point above answers *"what is wrong with this code?"* after
the fact. `yunq hook` answers *"may this write happen?"* — inside an
autonomous agent's edit loop, before the bytes reach disk.

```sh
cargo run -p yunq-cli -- hook install        # write yunq-policy.toml + .claude/settings.json
cargo run -p yunq-cli -- hook check file.py  # judge one file: exit 0 / 2 (denied) / 1 (yunq failed)
cargo run -p yunq-cli -- hook check file.py --format json  # structured verdict on stdout, for tooling
cargo run -p yunq-cli -- hook reset-circuit-breaker        # clear a tripped breaker after review
cargo run -p yunq-cli -- hook approve <token>               # authorize one escalated write after review
cargo run -p yunq-cli -- hook reset-loop-guard              # clear a tripped loop alarm after review
cargo run -p yunq-cli -- hook audit --limit 20               # tail the guardrail's decision log
```

Once installed, an agent that tries to write a shell-injection sink gets its
own tool call denied and the reason fed straight back into its context:

```
yunq blocked this write to `deploy.py`.

  1. python:subprocess-shell-true at line 3 — subprocess call with shell=True is
     vulnerable to shell injection if the command is ever influenced by external input
     [hard-blocked for agents]

This is an Agent Permission Policy block from yunq-policy.toml, not a style
preference. The file was NOT written. Rewrite the code so these findings do not
occur, then write it again.
```

The file never existed — the content judged was reconstructed from the tool
call's own arguments. Measured cost: **~7ms p50 per write**, process start
included (the circuit breaker, loop alarm and audit log below each add one
small file read/write per invocation on top of that, not yet independently
re-measured).

Every denial also carries a machine-readable form — the same violations as a
JSON object naming the exact rule, line and the deterministic condition that
must hold for it to clear — appended after the prose so an agent that wants
exact parsing does not have to pattern-match text. `hook check --format json`
speaks nothing but that JSON on stdout, for callers that never want prose at
all.

**Provenance: a stricter gate for AI-touched paths.** SonarQube's "AI Code
Assurance" flags a *project* as AI-generated by hand and applies a dedicated
quality gate to it. `yunq hook` does the same thing automatically and at file
granularity: every path a write has ever targeted (denied or not — an
attempted edit is itself a signal an agent is steering this file) is recorded
in `.yunq-provenance.json` (gitignored). The next write to that same path is
judged against `[agent.ai_touched]`'s severity threshold instead of the base
`block_at_or_above` — stricter if configured, identical otherwise. Only the
threshold moves: `blocking_rules`/`escalate_rules`/`advisory_rules` apply the
same regardless of provenance, since a categorical ban is exactly as
dangerous whether or not the file has agent history. No commit-trailer or
co-authorship claim is involved anywhere in this — deliberately: that
approach (`Co-authored-by: <model>`) is both contested (the U.S. Copyright
Office's guidance is not to list an AI as an author) and orthogonal to what
this guardrail needs, which is "should this path be judged more strictly",
not "who gets credit".

**Gherkin evidence gate.** The mechanical version of Uncle Bob Martin's
"surround the agents with constraints — unit tests, gherkin tests, QA
procedures" gauntlet: `[[gherkin_required]]` names glob patterns an agent may
only write to if at least one Gherkin scenario somewhere in the repository's
`.feature` files is tagged `@covers(<glob matching this path>)` — feature-
level or scenario-level, either counts. `yunq hook` scans `.feature` files for
that tag (no Gherkin execution, no cucumber-rust dependency — just the tag
lines, which are mechanically easy to find without a full parser) and denies
a matching write with no AST finding needed, the same "deny on path alone"
shape `protected_path` already uses. Off by default and commented out in the
installed template, unlike `protected_path`: turning it on immediately denies
every matching write until real `.feature` coverage exists, so it is opt-in
per repository once that coverage is ready, not a default anyone gets for
free. The scan itself is skipped entirely (no filesystem walk at all) when no
`[[gherkin_required]]` glob is configured, keeping the common case as fast as
before this landed.

**Circuit breaker.** An agent that cannot resolve a finding — a false
positive, or a vulnerability it does not know how to fix — will otherwise
retry the same write indefinitely, burning tokens against a wall. `yunq hook`
tracks how many times in a row the *same rule* has denied a write; the third
consecutive denial trips a breaker, and the denial text changes from "rewrite
and try again" to an explicit stop instruction: revert the change and get a
human to look at it. The count is per rule, persists across the separate
process invocations a hook loop makes (`.yunq-circuit-breaker.json` at the
repository root, gitignored), and resets the moment that rule stops being
denied — whether because it was fixed or because the agent moved on to
something else. `yunq hook reset-circuit-breaker` clears it after a human has
reviewed the stuck finding.

**Supply-chain: new dependencies.** No `Rule` in `core/rules-engine` can see
"this write adds a dependency that was not here before" — that trait analyses
one file's current content, with no concept of a prior version. `yunq hook`
diffs `package.json`/`requirements.txt` against the on-disk version at
`PreToolUse` time and turns any newly added dependency into an ordinary
`supply-chain:new-dependency` finding, which flows through the same
`blocking_rules`/`advisory_rules`/`block_at_or_above` policy as any AST
finding. It reports nothing by default (most new dependencies are
legitimate) — opt in per repository via `yunq-policy.toml`'s
`advisory_rules` or `blocking_rules`. This is intentionally *not* branded as
a sandbox: a WASM/WASI sandbox isolates code compiled to WASM, and cannot
meaningfully "sandbox-test" an arbitrary already-compiled shell command or
native npm/pip package before it runs, so this guardrail instead surfaces
the dependency for human review rather than claiming to have executed it
safely.

**Escalation: block pending human approval.** `blocking_rules` and
`block_at_or_above` are binary — always denied, no exceptions. `escalate_rules`
is the third tier for findings that are too risky to let an agent resolve
unsupervised but are not *always* wrong: the write is blocked exactly like a
denial, but the denial text carries a token
(`yunq hook approve <token>`) a human can redeem after reviewing the change.
Approval is single-use and write-specific — it authorizes one byte-identical
retry, computed from the path and the exact findings that escalated, never a
standing exemption for the rule. A rule also listed in `blocking_rules` stays
unconditionally denied; the hard-blocked list has no override, by design.

**Loop alarm.** The circuit breaker (above) only watches denials of the same
*rule*; it says nothing about an agent that keeps proposing the exact same
byte-identical write regardless of outcome — including a clean one, which is
just as strong a "the agent is stuck" signal. `yunq hook` separately tracks
the last write's `(path, content)` signature; the third identical write in a
row adds a `LOOP ALARM` line to the denial/advisory text telling the agent to
stop retrying and try something materially different. State lives in
`.yunq-loop-guard.json` (gitignored); `yunq hook reset-loop-guard` clears it.

**Audit log.** Every non-silent verdict — deny, advise, an unresolved
escalation, an approval being consumed — is appended as one JSON line to
`.yunq-audit.jsonl` (gitignored): timestamp, event, path, outcome, and the
same violation detail as the machine-readable block above. A clean write
leaves no trace, the same signal-to-noise judgement the denial text itself
makes. `yunq hook audit` tails it (`--format json` for the raw entries).

**Why a hook and not an MCP tool.** An MCP tool or an LSP is *consulted*: the
agent chooses whether to ask, and an agent optimising for task completion
learns not to ask. A host hook is *invoked* by the runtime on every matching
tool call and cannot be routed around. That is the difference between a
guardrail and a linter the model may consult — and it is why yunq does not
ship an MCP server as an alternative enforcement path. The one place MCP
could add value is *planning-time*, before the agent has even proposed an
edit — a read-only resource an agent's system prompt ingests up front (the
active policy, the architecture blueprint) — but that is a complement to the
hook, never a substitute for it: anything that must actually stop a write
stays on `PreToolUse`. See [ROADMAP.md](ROADMAP.md) Phase 6c.

### The Agent Permission Policy

`yunq-policy.toml` is not the quality gate. The gate asks "is this project
releasable?" over a whole analysis; the policy asks "may this one write land?"
over a single proposed edit — and the two disagree on purpose:

```toml
[agent]
block_at_or_above = "critical"

# Rules an agent may never introduce, whatever severity the profile gives them.
# An agent writing a shell sink is categorically riskier than a human doing it
# under review, even when the rule only scores as a warning.
blocking_rules = ["ai:llm-output-injection", "owasp:command-execution", "owasp:eval-usage"]

advisory_rules = []   # report, never deny — the escape hatch for a noisy rule
escalate_rules = []   # deny until a human runs `yunq hook approve <token>`

[[protected_path]]    # denied on path alone, no finding required
pattern = ".github/workflows/**"
reason = "CI definitions gate every other control; changes need human review."
```

### Host support

| Host | Integration | Can it deny? |
|---|---|---|
| **Claude Code** | `PreToolUse` on `Edit\|Write` | **Yes** — the write is prevented |
| **Claude Code** | `PostToolUse` on `Edit\|Write` | No — the write landed; feeds the finding back as context |
| **Codex CLI** | `yunq hook check` | Its tool hooks fire for shell commands only, not file writes |
| **pre-commit / CI** | `yunq hook check` | Exit 2 fails the commit or the job |

The two Claude Code hook points are asymmetric by design: **`PreToolUse`
prevents, `PostToolUse` teaches.** The wording the agent receives differs
accordingly — a model told "blocked" about a file that was in fact written
will move on and leave the finding in the tree.

**Failing open.** A malformed payload, an unreadable file or a policy that
does not parse lets the write proceed and reports on stderr. A guardrail that
wedges the agent loop on its own bug gets uninstalled within a day, and an
uninstalled guardrail blocks nothing. `hook check` is the exception: its
non-interactive callers can tell exit 1 (yunq broke) from exit 2 (policy
denied) and decide for themselves.

## Importing another analyzer's findings (SARIF)

`--sarif` merges a SARIF 2.x report into the scan. Every mainstream analyzer
emits it — ruff, ESLint, clippy, gosec, bandit, semgrep, CodeQL — so one
importer buys their whole rule catalogs without yunq reimplementing a single
check. Imported findings are ordinary issues from that point on: they render
in the output, count toward the severity measures, and can fail the quality
gate.

```bash
ruff check --output-format sarif . > ruff.sarif
cargo run -p yunq-cli -- scan . --sarif ruff.sarif --enforce-gate
```

- **Rule ids** are namespaced by the emitting tool (`ruff:e501`,
  `eslint:no-eval`, `codeql:js-sql-injection`) so imported rules stay
  visibly distinct from yunq's own.
- **Severity**: `properties.security-severity` (CVSS 0–10) wins when
  present; otherwise the SARIF `level` maps conservatively — `error` →
  `major`, not `critical`. A linter's "error" is its own default failure
  level, not a project-critical finding, and mapping it to `critical` would
  drown the gate.
- **Classification**: `vulnerability` when the rule carries a security
  signal (`security-severity`, or a `security`/`cwe-*`/`owasp-*` tag),
  `code smell` otherwise. There is no `bug` inference — SARIF has no field
  that distinguishes one, and guessing corrupts the Reliability rating.
- **Dropped**: results whose `kind` is not `fail`, results the tool already
  suppressed, and results with no location. The count is reported, not
  silently swallowed.

## Mutation testing

yunq runs no mutants itself — `--mutation-report` ingests the result of a
tool that already did, the same relationship `--sarif` has to a linter.
Bring your own mutation-testing run (`cargo-mutants`, StrykerJS,
Stryker.NET, Infection, …) exported to Stryker's **Mutation Testing
Elements** JSON schema, and yunq folds every mutant's status into a
`mutation_score` measure — `killed`/`timeout` mutants count as detected,
`survived`/`no coverage` count as undetected, `ignored`/`compile error`/
`runtime error`/`pending` mutants count toward neither, mirroring Stryker's
own formula. The default quality gate fails when `mutation_score < 60`,
same treatment `coverage < 80` already gets — both conditions are `NoValue`
(ignored) until the matching report is actually supplied.

```bash
cargo run -p yunq-cli -- scan . --mutation-report mutation.json --enforce-gate
```

This is deliberately the same posture as coverage/JUnit ingestion: yunq is
the gate that decides whether a build passes, not the tool that runs the
tests or the mutants — a test runner (or `cargo test`/`pytest`/mutation
tool) still has to produce the report yunq consumes.

## Adding a rule

1. Create (or extend) a crate under `rulesets/`.
2. Implement `yunq_rules_engine::Rule` (`id`, `applies_to`, `default_severity`, `check`).
3. Register it in the composition roots (`bin/cli`, `bin/worker`).

The engine, storage and parsers remain untouched.

## Roadmap

More languages, deeper duplication detection, quality gates/profiles, issue lifecycle, GitHub PR decoration — plus an AI **Remediation Agent** with a verify-before-suggest loop. See [ROADMAP.md](ROADMAP.md).
