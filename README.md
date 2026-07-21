# yunq

A SonarQube-alternative static analysis platform in Rust, built as a **hexagonal, SOLID Cargo workspace**: the volatile infrastructure (database, queue, parsers) never leaks into the core analysis logic.

## Topology

The directory structure *is* the architecture — nested workspace globs define the boundaries:

```
yunq/
├── core/                       # PURE LOGIC — no I/O, no async runtime, no serde
│   ├── ast/                    # yunq-ast: neutral AST, LanguageIdentifier, SourceFile
│   ├── profiles/               # yunq-profiles: RuleId, Severity, QualityProfile
│   ├── rules-engine/           # yunq-rules-engine: ports (traits), Rule, AnalyzerService
│   └── taint/                  # yunq-taint: intra-file taint analysis
├── infra/                      # OUTBOUND ADAPTERS
│   ├── memory/                 # in-memory storage/metrics (CLI, tests)
│   ├── fs/                     # gitignore-aware source loader
│   ├── postgres/               # sqlx IssueStorage/IssueReader/MetricsTracker
│   └── sqs/                    # aws-sdk-sqs JobQueue + consumer (floci/AWS)
├── parsers/                    # INBOUND ADAPTERS (tree-sitter → neutral AST)
│   ├── treesitter-typescript/
│   └── treesitter-rust/
├── rulesets/                   # PLUGINS implementing the Rule trait
│   ├── owasp/                  # hardcoded secrets, eval, taint-based injection
│   └── code-smells/            # TODO/FIXME, long functions, unwrap/expect
└── bin/                        # COMPOSITION ROOTS (testing dead-zones)
    ├── cli/                    # yunq scan — local end-to-end analysis
    ├── server/                 # axum API: POST /scans → SQS, GET /issues
    └── worker/                 # SQS consumer → AnalyzerService → Postgres
```

Dependency direction is enforced by Cargo: `bin → {infra, parsers, rulesets} → core`. The core defines **ports** (`AstParser`, `IssueStorage`, `IssueReader`, `MetricsTracker`, `JobQueue`); adapters implement them (DIP). Domain types are validated newtypes with fallible constructors and **no `serde::Deserialize`** — every edge (HTTP, SQS, Postgres, tree-sitter) owns its DTOs and translates in. Adding a language or ruleset means a new crate registered at a composition root; the engine never changes (OCP).

Proof of purity: `cargo tree -p yunq-rules-engine` — only core crates and `thiserror`.

## Quickstart

```sh
cargo test --workspace                 # 30 tests: unit (fakes), fixtures, e2e
cargo run -p yunq-cli -- scan fixtures # real scan: parsers + rules + taint
cargo run -p yunq-cli -- scan fixtures --format json
cargo run -p yunq-cli -- scan fixtures --fail-on critical  # exit 2 on breach
```

Example output:

```
BLOCKER  owasp:injection  vulnerable.ts:9:1  user input from `process.argv` reaches sink `eval`:
         `input` tainted by `process.argv`; `payload` tainted via `input`; `payload` reaches sink `eval`
```

## Server + worker (async pipeline)

The server enqueues `ScanJob`s to SQS; workers consume, analyze and persist to Postgres. Locally, SQS is served by an AWS emulator ([floci](https://floci.io/floci/)) — same client code as production AWS:

```sh
export YUNQ_AWS_ENDPOINT_URL=http://localhost:4566   # floci
export YUNQ_QUEUE_URL=http://localhost:4566/000000000000/yunq-scan-jobs
export DATABASE_URL=postgres://yunq:yunq@localhost:5432/yunq

cargo run -p yunq-worker    # applies migrations, long-polls the queue
cargo run -p yunq-server    # POST /scans {"project":"p","path":"/abs/checkout"}
```

The server publishes its contract as **OpenAPI 3.1** at `GET /api-docs/openapi.json` (Swagger UI at `/swagger-ui`), generated with utoipa from the server-owned DTOs — the contract lives at the adapter boundary, domain types stay serde-free. Frontends can codegen clients from it (e.g. `openapi-typescript`). A committed export lives at [`api/openapi.json`](api/openapi.json); regenerate it any time with:

```sh
cargo run -p yunq-server -- openapi > api/openapi.json
```

## Adding a rule

1. Create (or extend) a crate under `rulesets/`.
2. Implement `yunq_rules_engine::Rule` (`id`, `applies_to`, `default_severity`, `check`).
3. Register it in the composition roots (`bin/cli`, `bin/worker`).

The engine, storage and parsers remain untouched.

## Roadmap

Full SonarQube feature parity — more languages, duplication detection, quality gates/profiles, issue lifecycle, GitHub PR decoration — plus an AI **Remediation Agent** with a verify-before-suggest loop. See [ROADMAP.md](ROADMAP.md).
