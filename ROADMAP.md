# yunq Roadmap — the ultraperformant ultimate code analysis platform

Mission: **copy every feature SonarQube provides, then beat it** — on
performance, on architecture, on developer experience, and on agent-native
automation. Phase 1 (hexagonal workspace, working analyzer, CLI, SQS/Postgres
pipeline, OpenAPI contract) is **done**.

**Where yunq wins by design:**

- 100% pure, unit-testable analysis core — SonarQube couples analysis to a
  JVM platform monolith.
- OpenAPI 3.1 generated from code as a first-class contract; SonarQube's Web
  API has no complete formal spec.
- Local-first: full analysis with no server. The server adds persistence,
  history and collaboration — it is never a gatekeeper.
- Agent-native: the Remediation Agent's verify-before-suggest loop reuses the
  embedded analyzer as judge, in-process.
- Rust: no JVM warmup, small static binaries, predictable memory.

## Cross-cutting pillar — ULTRA performance (applies to every phase)

Target: **≥ 100k LOC/s per core** on rule execution, sub-second incremental
re-analysis on typical PRs.

- **Parallel by default**: per-file analysis fan-out with `rayon` in the CLI
  and worker (files are independent until cross-file phases; those get a
  staged parallel pipeline: parse ∥ → link → analyze ∥).
- **Incremental analysis**: content-hash cache keyed by
  (file digest, rule-set digest, parser version) — unchanged files are never
  re-parsed or re-analyzed; dependency-aware invalidation once cross-file
  taint lands. Cache lives beside the repo (CLI) and in Postgres (server).
- **Memory discipline**: replace per-node owned `String` text in `yunq-ast`
  with spans into a shared source buffer + string interning for identifiers
  (known inefficiency, flagged in Phase 1); arena allocation for AST nodes.
- **I/O**: mmap large files, batched Postgres writes (`COPY`/multi-row
  inserts), SQS batch send/receive.
- **Benchmarks as tests**: `criterion` suite over a large corpus vendored in
  `benches/corpus/`; CI fails on >10% regression. Track LOC/s, peak RSS,
  p99 file latency.
- **Scale-out**: stateless workers already horizontal on SQS; shard analysis
  of monorepos by directory subtree.

## Phase 2 — Analysis engine: full detection surface

- **Languages** (each a `parsers/treesitter-*` crate; zero engine changes):
  Python, Java, Go, C/C++, C#, JavaScript (beyond TS), PHP, Ruby, Kotlin,
  Swift, Scala, HTML/CSS, XML/JSON/YAML, Terraform/CloudFormation/K8s (IaC),
  Dockerfile, shell. Prioritized by user demand; the roster is open-ended.
- **Rule catalog at scale**: port the high-value Sonar rules per language;
  rule metadata (name, description in markdown, remediation effort function,
  tags, CWE / OWASP Top 10 / CERT mappings); `GET /rules` API with search.
- **Issue types & classification**: bug / vulnerability / code smell, plus
  MQR-style software-quality impacts (reliability, security,
  maintainability × severity) — support both classification modes like
  modern SonarQube.
- **Secrets detection**: dedicated ruleset (entropy + provider patterns:
  AWS, GCP, Azure, Stripe, private keys…), extending the Phase-1 rule.
- **Duplication detection (CPD)**: token-based, cross-file, per-language
  tokenizers reusing the parsers; duplicated blocks/lines/density metrics.
- **Metrics engine**: cyclomatic + cognitive complexity, LOC/statements/
  functions/classes, comment density, nesting depth — computed on the
  neutral AST in core.
- **Coverage ingestion**: LCOV, Cobertura, JaCoCo, `llvm-cov`, Istanbul;
  line + branch coverage, coverage-on-new-code.
- **Test report ingestion**: JUnit XML / test execution counts.
- **Cross-file taint analysis**: module graph (imports/exports as edges),
  inter-procedural summaries, sanitizer modeling — SonarQube sells this as
  commercial; yunq ships it open.

## Phase 3 — Project & quality model (Clean as You Code)

- Projects, applications, branches, pull requests as domain entities;
  analyses attached to (project, branch|PR).
- **New Code definition**: previous version / N days / reference branch /
  specific analysis — per project and per branch.
- **Quality Gates**: condition sets on any metric (new/overall scope),
  CaYC-recommended default gate, gate evaluation per analysis, per-project
  gate assignment, gate status API + badges (SVG).
- **Quality Profiles**: per-language activation sets with severity
  overrides (core type exists), inheritance chains, built-in "Sonar way"
  equivalent, compare/copy/backup-restore.
- **Ratings & debt**: A–E ratings for reliability/security/maintainability,
  technical-debt ratio, remediation effort aggregation.
- **Issue lifecycle**: open → confirmed → resolved → closed; resolutions
  (fixed, won't-fix, false-positive); assignment, comments, tags, bulk
  changes, changelog per issue.
- **Security hotspots**: distinct finding type with to-review/acknowledged/
  fixed/safe workflow and review metrics.
- **Housekeeping**: configurable retention of analyses/issues history.

## Phase 4 — API, web platform & collaboration

- **REST API parity**: pagination envelopes, rich filtering/faceting
  (severity, rule, file, assignee, tag, creation date…), measures +
  measure history, component tree navigation, `sources` endpoints with
  line-level annotations (coverage, duplication, issues, SCM blame) — the
  full data source for the frontend clone. Contract stays generated:
  `api/openapi.json`.
- **Auth**: local users + user tokens (already-hashed at rest), OAuth
  (GitHub/GitLab), SAML later; groups; global + per-project permissions,
  permission templates.
- **Webhooks** (analysis finished, gate changed) with delivery log +
  retries; **email notifications** per user subscription.
- **Project features**: badges, links, tags, favorites, project export/
  import between instances.
- **Background tasks**: task queue status API (SQS pipeline exists),
  per-project activity log, failure diagnostics.
- **Ops**: system info/health endpoints, audit log, Prometheus metrics.

## Phase 5 — SCM/ALM & CI integration

- **GitHub**: app installation, check runs, PR decoration (gate summary +
  inline comments on changed lines), status checks blocking merge.
- **GitLab / Bitbucket / Azure DevOps** behind the same `AlmGateway` port.
- **Scanner ergonomics**: `--project/--branch/--pr`, SCM blame capture,
  auto-detected CI context (GitHub Actions, GitLab CI); first-party CI
  actions/templates; monorepo support (multiple projects per repo).
- **IDE integration (SonarLint equivalent)**: `yunq-lsp` — an LSP server
  over the same core, with connected mode syncing the server's profile and
  issue suppressions. In-editor analysis in any LSP-capable editor beats
  SonarLint's per-IDE plugins.

## Phase 6 — AI: Remediation Agent & AI code governance

- **6a Core loop** (`yunq-remediation`): generate → sandbox → re-scan →
  verdict via ports: `FixGenerator` (Claude API adapter), `Sandbox` (git
  worktree adapter), verification by the embedded `AnalyzerService` —
  accept only if the original issue disappears and none appear.
- **6b Assign to Agent**: `POST /issues/{id}/assign-to-agent`, bulk action,
  one PR per issue via `PrGateway`; PR-scoped mode proposes fixes when a PR
  breaks its quality gate. Developer-in-the-loop always.
- **AI Code Assurance equivalent**: flag projects/files as AI-generated,
  enforce stricter gates on AI-authored code, provenance tracking.
- **Fix suggestions in-editor** through `yunq-lsp` connected mode.

## Phase 7 — Enterprise platform

- **Portfolios**: hierarchical aggregation across projects with rollup
  ratings and PDF/report exports.
- **Scale & HA**: multi-node server (stateless already), Postgres read
  replicas, blue-green migrations, monorepo sharding.
- **Governance**: SCIM provisioning, LDAP, advanced audit, data residency.

## Sequencing

Phases 2 and 3 are startable now and parallel; Phase 4 follows 3 closely so
the frontend swaps mocks for real endpoints incrementally. Performance pillar
work starts immediately (interning + rayon are Phase-2 groundwork). Phase 6a
prototypes as soon as 2/3 stabilize the issue model; 6b needs 4 + 5. Phase 7
last — nothing in it blocks product value earlier.
