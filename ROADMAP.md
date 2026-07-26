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

- **Parallel by default**: ✅ per-file analysis fan-out (`AnalyzerService::analyze_all`)
  and the cross-file parse phase (`parse_all`) both use scoped `std::thread`
  work-stealing over an atomic index (`core/rules-engine/src/service.rs`) —
  not `rayon`: a deliberate choice so the core crate takes no scheduler
  dependency, files being independent-until-cross-file makes a hand-rolled
  work queue just as effective. Results stay input-ordered regardless of
  scheduling (tested).
- **Incremental analysis**: ✅ content-hash cache keyed by
  (file digest, rule-set + profile + engine-version digest) skips re-parsing
  and re-running rules on unchanged files (`AnalyzerService`'s `AnalysisCache`
  port, `infra/fs::FileAnalysisCache` persists it beside the repo for the
  CLI). Still open: the cross-file phase always re-parses every file with no
  cache at all (dependency-aware invalidation for it never landed), and the
  server/worker path has no persistent cache (Postgres or otherwise) — every
  server-triggered scan is a cold run.
- **Memory discipline**: ✅ zero-copy AST text — every node holds only a
  byte-range `Span` into one `Arc<str>` source buffer per file
  (`AstNode::from_source`), not an owned `String`; building a tree allocates
  no per-node text. ✅ **(this session)** the one remaining per-node
  allocation — `NodeKind::Other`'s raw grammar-kind label (`"if_statement"`,
  `"binary_expression"`, …), previously a fresh `String` on every unmapped
  node via `.to_string()` — is now interned (`yunq_ast::intern`, a
  process-wide `HashSet<Arc<str>>` behind a `Mutex`): the same handful of
  kind strings per grammar recur on a huge share of a file's nodes, so this
  turns N allocations into 1 allocation + N atomic refcount bumps. Verified
  end-to-end across all 23 tree-sitter-backed parser crates plus every rule
  matching on `NodeKind::Other` (`cargo test --workspace --exclude
  yunq-server` green, 0 new clippy warnings). Still open: AST nodes
  themselves are individually heap-allocated (`Vec<AstNode>` children, no
  arena) — a bump-allocator rewrite is a much larger structural change, not
  attempted here.
- **I/O**: ✅ **(this session)** `PgIssueStorage::save_issues`/`save_hotspots`
  (`infra/postgres/src/lib.rs`) previously ran one `INSERT` per issue/hotspot
  inside a single transaction — N round trips for N findings, the dominant
  cost on any file with more than a handful of issues. Both now build one
  multi-row `INSERT ... VALUES ($1,$2,...),($..),...` per up-to-1000-row
  chunk via `sqlx::QueryBuilder::push_values` (chunked to stay under
  Postgres' 65535-bind-parameter ceiling — 1000 rows × 11/8 columns leaves
  wide headroom), collapsing a whole scan's writes into a handful of
  statements. `Severity::as_str` (`core/profiles/src/lib.rs`) also widened
  from `&str` to `&'static str` — its match arms were always `'static`
  literals, the elided lifetime just hadn't been asked to prove it, and
  `push_values`' closure-based API (values must outlive the immediate
  statement, unlike `.bind()` calls that execute inline) surfaced the
  borrow the old signature couldn't satisfy. Verified against a live
  Postgres (not just type-checked): `infra/postgres/src/live_db_tests`,
  `#[ignore]`d by default so `cargo test` still needs no database (this
  crate's existing design), run explicitly with `cargo test -p
  yunq-infra-postgres -- --ignored` — round-trips 5 issues and 5 hotspots
  through the batched insert and asserts every column, plus that an empty
  slice is a true no-op. `cargo test --workspace` (minus `yunq-server`/
  `yunq-frontend`, both green separately) and `cargo clippy -p
  yunq-infra-postgres -p yunq-profiles --all-targets` stay clean. Still
  open: mmap for large files (the CLI's `std::fs::read_to_string` copies
  every file into a `String` regardless of size — real but likely
  lower-value than the items above, since it needs unsafe code to avoid
  re-copying into the existing `Arc<str>` source buffer and only pays off
  on unusually large files) and queue-side batching — there is no SQS here
  despite the name: the job queue is Postgres `LISTEN`/`NOTIFY` with
  `SKIP LOCKED` (`infra/postgres/src/queue.rs`), and its one caller
  (`POST /scan`) enqueues a single job per request, so a batch-claim/-enqueue
  API would have no real caller today — worth doing once the still-open
  monorepo directory-subtree sharding below actually produces many jobs per
  scan, not before.
- **Benchmarks as tests**: ✅ real `criterion` suite (`benches/` — a proper
  workspace member, `yunq-benchmarks`; the previous `benches/benchmarks.rs`
  was never wired into any `Cargo.toml` and had not been compiled or run at
  all) over a real ~11.8k-line, 69-file corpus vendored in
  `benches/corpus/rust/` (this repo's own `core`/`rulesets` sources — real
  code, already license-clear to vendor). `bench_full_pipeline_corpus`
  drives `yunq_cli::scan`, the exact entry point the real CLI uses — every
  registered parser, every registered rule, CPD, cross-file taint — and
  reports `Throughput::Elements` so Criterion's own output is in LOC/s, the
  roadmap's own unit. **Measured in this sandbox** (`cargo bench -p
  yunq-benchmarks`, single run, shared/throttled CPU — treat as a floor, not
  a hardware-independent number): **~67.6k elem/s (LOC/s)** full pipeline,
  **~24.4k parses/s** (41µs/parse) for a bare ~10-line function. This
  supersedes the unverified "~398k LOC/s" figure that had been circulating
  with no working benchmark behind it — that number was never reproducible
  because the harness measuring it didn't exist. Below the >=100k LOC/s
  target; the interning landed this session and the still-open items above
  (arena allocation, cross-file/server-side caching) are exactly what would
  close the gap. ✅ **(this session)** CI regression gating: `.github/workflows/ci.yml`
  is this repo's first CI test/clippy workflow at all (previously only
  `release.yml`, for tagged builds). Its `benchmark-gate` job runs a new
  criterion-independent binary (`benches/src/bin/perf_report.rs`) twice on
  the same runner — once at the PR head, once at its merge base — and diffs
  them (`--compare`) rather than checking against a number committed to the
  repo, so the gate isn't skewed by comparing against different CI hardware
  generations over time; fails the job (non-zero exit) on a throughput drop
  of more than 10%. The same binary reports peak RSS (`/proc/self/status`'s
  `VmHWM`) and p50/p99 per-file scan latency (each corpus file scanned
  independently, 3 reps) — printed for visibility every run, not yet gated
  on since neither has an established target. `percentile`/`is_regression`
  live in `benches/src/lib.rs`, unit-tested independently of the actual
  benchmark run.
- **Scale-out**: stateless workers already horizontal on SQS; shard analysis
  of monorepos by directory subtree.

## Phase 2 — Analysis engine: full detection surface

- **Languages** (each a `parsers/treesitter-*` crate; zero engine changes):
  ✅ Roster complete — TypeScript (covers plain JS/JSX too), Rust, Python,
  Java, Go, C, C++, PHP, Dockerfile, C#, Ruby, Kotlin (via the maintained
  `tree-sitter-kotlin-ng` grammar), Swift, Scala, HTML, CSS, XML, JSON,
  YAML (also covers CloudFormation/K8s manifests, which are just
  YAML/JSON), HCL/Terraform, Bash/shell, Groovy, Lua, Elixir — all
  registered in `bin/cli/src/lib.rs::default_service`. Elixir's macro-based
  grammar (no dedicated `if`/`case`/`for` node kinds — those are all plain
  function calls) means the complexity rules under-count its branching
  today; `def`/`defmodule` detection and everything else works. Roster
  stays open-ended for further user-demand additions (e.g. Dart, Haskell,
  Erlang).
- **Rule catalog at scale**: port the high-value Sonar rules per language;
  rule metadata (name, description in markdown, remediation effort function,
  tags, CWE / OWASP Top 10 / CERT mappings); `GET /rules` API with search.
  26 rules shipped (10 per-file + 1 cross-file in `rulesets/owasp`, 7 in
  `rulesets/code-smells`, 2 in `rulesets/iac`, 2 in `rulesets/a11y`, 4 in
  `rulesets/rust`) plus duplication and taint. The dedicated `rulesets/rust`
  crate (2026-07-23) is the first language-specific ruleset (as opposed to
  the neutral-AST checks in `rulesets/code-smells` that merely happen to
  apply to every language): `rust:unsafe-undocumented` (an `unsafe` block
  with no adjacent `SAFETY` comment), `rust:mem-transmute` and
  `rust:mem-forget` (hotspots on the two classic ways to break soundness or
  leak without `unsafe` itself), and `rust:process-exit`
  (`process::exit`/`process::abort` skip `Drop` cleanup) — on top of the
  existing `smells:unwrap-usage`. Latest additions (2026-07-22) unblock two
  categories the earlier catalog audit (`specs/rule-catalog-gap-closure`)
  had marked "viable but blocked on a missing parser" — now that the
  HTML/CSS/HCL/YAML parsers exist, those categories are open:
  `iac:iam-wildcard-permission` and `iac:open-ingress-cidr` (Terraform HCL +
  Kubernetes/CloudFormation YAML) and `a11y:img-missing-alt` /
  `a11y:missing-lang-attribute` (HTML). ✅ React/JSX: `rulesets/react` (10
  rules) closes the category previously blocked on symbol/type
  resolution, by staying purely syntactic — rules-of-hooks (conditional
  calls, naming convention), missing/inline-index list keys, a hook call
  missing its dependency array, direct state mutation via a same-scope
  `useState`/`useReducer` value, `dangerouslySetInnerHTML`, unsafe
  `target="_blank"`, JSX `<img>` missing `alt`, and inline
  function/object props on custom components. Reference tool for the
  category: `react-doctor` (`npx react-doctor`, ~100 Oxlint-based checks +
  a dead-code pass); this covers its syntactic subset. ✅ **(this session)**
  the symbol/type resolution layer that subset was blocked on now exists:
  a new pure crate, `core/symbols` (`yunq-symbols`) — same-file lexical
  scope resolution (`scope.rs`), declared-type extraction across TS/Rust/
  Python's differing annotation shapes (`types.rs`), and a `ClassRegistry`
  extracting fields/methods/superclass for TS/Python/Rust classes and
  structs, same-file or cross-file (`classes.rs`). Built on it:
  `react:exhaustive-deps` and `react:unused-state` (closing the two checks
  called out as blocked above); three OOP smells — `smells:god-class`,
  `smells:feature-envy` (needs real type resolution: a parameter's type
  must resolve to a different known class before its accesses count as
  "foreign"), `smells:refused-bequest` (TS/Python; Rust has no inheritance
  model to refuse/envy, so it's god-class only there); architecture/
  dependency-cycle detection — a new `core/import-graph` crate (module
  resolution + Tarjan's-SCC cycle detection for TS/JS and Python) and
  `rulesets/architecture`'s `architecture:dependency-cycle` cross-file
  rule; and two RxJS reactive-stream smells —
  `rulesets/reactive`'s `reactive:missing-unsubscribe` and
  `reactive:subject-never-completed`. All 8 new rules carry both classic
  `IssueType` and MQR impacts and are active by default in the built-in
  Sonar way profile (`core/profiles/src/builtin.rs`). ✅ **(this session)**
  the OOP-smell rules (`smells:god-class`, `smells:feature-envy`,
  `smells:refused-bequest`) are now whole-program: converted from `Rule` to
  `CrossFileRule` (`core/rules-engine::CrossFileRule`, same wiring pattern as
  `owasp:cross-file-injection`), built on `ClassRegistry::build_cross_file`
  over every analyzed file instead of one file's AST — a superclass or a
  foreign-typed parameter declared in a different file now resolves
  (`Finding` carries the class's own file index, so an issue attaches to
  where the class/subclass is declared even when its methods were merged in
  from elsewhere). Wired into all three composition roots (`bin/cli`,
  `bin/worker`, `bin/server`'s `/api/rules` catalog and issue-classification
  map — the last of which also picked up `architecture:dependency-cycle`,
  previously missing from both). Regression-tested against a struct/impl and
  a class/subclass split across two files each. Dogfooding this against
  yunq's own ~43k-LOC Rust workspace (`cargo run -p yunq-cli -- scan .`)
  surfaced zero god-class/feature-envy/refused-bequest findings at default
  thresholds (20 methods/15 fields) — a true negative, not a bug: this
  codebase's structs stay under that bar — but the process caught a real,
  pre-existing false-negative in `core/symbols::classes::attach_rust_impls`
  along the way: it matched only a bare `type_identifier` as an impl
  block's target type, so any **generic** impl (`impl<S, M>
  AnalyzerService<S, M>` — a `generic_type` node, not a `type_identifier`,
  once it carries type arguments) or impl on a **reference type** (`impl
  Trait for &Foo`, a `reference_type` node) silently contributed zero
  methods to the struct — `AnalyzerService` itself, this repo's own central
  service type, registered as 0 methods/8 fields before the fix, 9/8 after.
  Fixed via a recursive `impl_type_name` unwrap (generic/reference wrappers
  → their inner `type_identifier`), regression-tested
  (`rust_generic_struct_impl_methods_are_attached`,
  `rust_trait_impl_for_a_reference_type_attaches_methods` in
  `core/symbols/src/classes.rs`) — this fixes the extraction every
  Rust-applicable OOP-smell rule depends on, not just god-class. Known
  limitations, not attempted here: dependency-cycle detection skips Rust
  (module system doesn't map 1:1 to files) and TS path aliases (only
  relative specifiers resolve); `exhaustive-deps` only recognizes the four
  literal hook names, not custom wrapper hooks.
- **Issue types & classification**: ✅ every rule declares a classic
  `IssueType` (bug / vulnerability / code smell, `Rule::issue_type`,
  `core/rules-engine/src/rule.rs`) alongside MQR-style software-quality
  impacts (reliability, security, maintainability × severity —
  `SoftwareQuality`/`ImpactSeverity`/`SoftwareQualityImpact`,
  `core/profiles/src/impact.rs`), derived by default from the classic type
  via `default_impact` and overridable per rule. Both classification modes
  are exposed simultaneously on `GET /api/rules` and `GET /api/issues`
  (`type` + `impacts` fields), matching modern SonarQube.
- **Secrets detection**: ✅ dedicated `rulesets/secrets` crate — entropy
  detection (`entropy.rs`), provider patterns for AWS/GCP/Azure/Stripe/
  private-key blocks (`provider_patterns.rs`), and custom-pattern support for
  private/self-hosted services (`custom_pattern.rs`); wired into all three
  composition roots (CLI, server, worker).
- **Duplication detection (CPD)**: ✅ core algorithm ported from
  `sonar-duplications`' `BlockChunker`/`CloneIndex` — statement-repetition
  collapsing, incremental Rabin-Karp rolling hash (base 31, default block
  size 5), cross-file hash-indexed matching (`core/duplication`). ✅
  Tokenizer gap closed: statements are now real per-language tokens, not
  trimmed source lines — a grammar-agnostic leaf walker
  (`parsers/treesitter-tokens`) reused by all 23 tree-sitter-backed
  `parsers/treesitter-*` crates via a new `AstParser::tokenize_for_duplication`
  override collapses string/numeric literals to a shared placeholder and
  drops comment nodes, so e.g. `x = 1;` and `x = 2;` hash as the same
  statement and comment-only lines never register as duplicated, while
  joining tokens with a single space makes intra-line whitespace
  insignificant. Languages without a registered parser (or without one
  overriding the default) fall back to `yunq_cpd::fallback_tokenize`'s
  trimmed-line behavior, same as before.
- **Metrics engine**: ✅ cyclomatic + cognitive complexity (per-function,
  existing rules), LOC/statements/functions/classes, comment density,
  max control-flow nesting depth — computed on the neutral AST in
  `core/rules-engine/structural_metrics.rs`, one pass per file, aggregated
  into `Metrics` (report-wide sum for counts, max for nesting depth) and
  exposed as `functions`/`classes`/`statements`/`comment_lines`/
  `comment_lines_density`/`max_nesting_depth` measures (usable in quality
  gate conditions) plus a CLI summary line. Grammar node kinds are matched
  by raw tree-sitter name per language (same pattern-based approach as
  `ComplexityRule`'s decision points), since no neutral `NodeKind` variant
  covers "class" or "statement" — the disk-backed analysis cache
  (`infra/fs::FileAnalysisCache`) fails open (defaults to zero) on entries
  written before this landed.
- **Coverage ingestion**: ✅ all five formats parsed (`infra/fs/src/{lcov,cobertura,jacoco,istanbul,llvm_cov}.rs`)
  behind a unified auto-detecting dispatcher (`infra/fs/src/coverage.rs::parse_coverage_report`,
  `CoverageFormat`); line + branch coverage aggregate into `CoverageSummary`/`FileCoverage`
  (`core/rules-engine/src/domain/report.rs`), exposed as `coverage`/`branch_coverage` measures
  (`AnalysisReport::measure`) with a default quality-gate condition (`coverage < 80`,
  `core/rules-engine/src/gate_defaults.rs`); coverage-on-new-code diffs covered lines against
  changed-line sets (`CoverageReport::coverage_on_new_code`), wired into the CLI via
  `--coverage`/`--cobertura`/`--jacoco`/`--llvm-cov`/`--istanbul`/`--coverage-report`+`--coverage-format`
  and `--coverage-diff` (`bin/cli/src/main.rs`). ✅ Server-side gap closed: `POST
  /api/projects/{key}/coverage` ingests a raw report (auto-detected or explicit
  `format` query param) against the project's most recent analysis and persists
  the summary (`analysis_coverage` table, migration 0014); `GET
  /api/projects/{key}/coverage` reads it back (`CoverageStorage`/
  `CoverageResultReader` ports, `infra/postgres/src/coverage.rs`,
  `bin/server/src/coverage.rs`) — so a CI job can upload a report without
  shelling out to the CLI.
- **Test report ingestion**: ✅ JUnit XML parser (`infra/fs/src/junit.rs`)
  wired into the CLI `--junit` flag and test-summary measures.
- **Cross-file taint analysis**: ✅ inter-procedural summaries ported
  (`core/taint/src/cross.rs`) — parameter→sink and parameter→return-value
  summaries iterated to a global fixpoint, so `caller → helper → runner →
  sink` chains resolve across file boundaries. ✅ **(this session)** name
  resolution now goes through a real import/export module edge graph
  (`collect_imports`/`resolve_module_specifier`) instead of a project-wide
  by-name heuristic: functions are keyed by `(file, name)`, and a call site
  resolves to the specific file it was imported from — a same-named
  function in an unrelated file is never conflated with the one actually in
  scope (regression-tested: `same_named_function_in_an_unimported_file_is_not_conflated`,
  `imported_function_resolves_to_the_correct_file_even_with_a_same_named_decoy`).
  Handles default/named/aliased ES imports and relative-path resolution
  across subdirectories (`./lib`, `../utils/foo`, extension and `/index`
  inference). Bare/package specifiers (`'child_process'`, `'react'`) stay
  external, as before. Files with no recognized `import` syntax at all
  (non-ES-module languages, synthetic ASTs) fall back to the previous
  project-wide by-name lookup — a deliberate, narrower fallback rather than
  a silent behavior change outside the ES-module family.
  ✅ **Sanitizer modeling** ported: `TaintConfig::with_sanitizer` names a
  function whose call cleanses taint — a sanitizer call is treated as a
  boundary the analysis does not recurse past, so neither a source marker
  nor a tainted argument inside it reaches the enclosing sink, in both the
  intra-file (`core/taint/src/lib.rs`) and cross-file engines. Wired into
  `owasp:xss` (`sanitize`/`escapeHtml`/`encodeURIComponent`) and
  `owasp:injection`/`owasp:cross-file-injection` (`escape`/`escapeShellArg`).
  SonarQube sells the category commercially; yunq ships it open.

## Phase 3 — Project & quality model (Clean as You Code)

- Projects, applications, branches, pull requests as domain entities;
  analyses attached to (project, branch|PR).
- **New Code definition**: previous version / N days / reference branch /
  specific analysis — per project and per branch.
- **Quality Gates**: ✅ condition sets on any metric, gate evaluation
  persisted per analysis (`infra/postgres/src/gate.rs`, migrations
  0006–0010), real gate status badge (`badge_svg` in `bin/server/src/main.rs`
  renders the actual latest gate result — no longer a hardcoded "passed"
  stub), new-code definition model landed alongside it.
- **Quality Profiles**: ✅ per-language activation sets with severity
  overrides, inheritance chains (`QualityProfile::with_parent`), and now
  persisted as such (migration `0018` adds a self-referencing `parent_id` —
  inheritance previously existed only in the pure core, never durable). A
  built-in "Sonar way" equivalent (`core/profiles/src/builtin.rs`) — curated
  per-language activation baselines hand-verified against every rule's real
  `RuleId`/`default_severity()`, wired as the actual default `AnalyzerService`
  profile in both the CLI and worker (no per-project profile assignment
  exists yet, so this is the one profile every scan uses). Compare
  (`core/profiles/src/compare.rs`, pure `ProfileDiff` over inheritance-
  resolved activations), copy (`copy.rs`, flattens effective activations
  into a standalone snapshot), and backup/restore (`backup.rs`, a
  serde-free portable `ProfileBackup` value with a reject/overwrite
  collision policy — never silently clobbers) — all exposed via
  `bin/server/src/profiles_admin.rs`.
- **Ratings & debt**: ✅ maintainability rating ported from SonarQube's SQALE
  model (`DebtRatingGrid` + `MaintainabilityMeasuresVisitor`) —
  `Rating::from_debt_ratio` in `core/profiles` uses the real
  remediation-effort ÷ development-cost ratio (30 min/LOC, grid
  `0.05/0.1/0.2/0.5`), not a worst-severity shortcut. ✅ Reliability and
  Security ratings wired to real analysis: `Metrics::record_issue_type_and_effort`
  (`core/rules-engine`) folds each issue's classic type + severity into a
  running worst-`Rating::from_severity` per type as issues are produced
  (`AnalyzerService::analyze_files`, both the per-file and cross-file rule
  paths), exposed as `AnalysisReport::reliability_rating`/`security_rating`
  and as `reliability_rating`/`security_rating`/`maintainability_rating`
  measures (`1.0`–`5.0`, SonarQube's own encoding) usable in quality gate
  conditions. ✅ Remediation effort aggregation by rule and by component
  (`RemediationEffortSummary`) accumulates alongside, every issue counted
  regardless of type; surfaced in the CLI's JSON output
  (`metrics.remediation_effort_by_rule`/`remediation_effort_by_component`,
  sorted worst-first) and text output (ratings line). Previously the
  algorithm existed only in `core/profiles` unit tests with nothing feeding
  it real `IssueType`-tagged data — fixed now that every rule carries a
  real `issue_type` (`953ff6d`).
- **Issue lifecycle**: open → confirmed → resolved → closed; resolutions
  (fixed, won't-fix, false-positive); assignment, comments, tags, bulk
  changes, changelog per issue.
- **Security hotspots**: distinct finding type with to-review/acknowledged/
  fixed/safe workflow and review metrics.
- **Housekeeping**: ✅ configurable retention, now covering `analyses` (and
  its cascaded gate-result/coverage rows) *and* `issues`/`hotspots`:
  per-project `retention_days` override (`PUT /api/projects/{key}/retention`)
  falling back to an instance-wide `YUNQ_DEFAULT_RETENTION_DAYS`;
  `yunq-worker` purges on a timer (`YUNQ_HOUSEKEEPING_INTERVAL_HOURS`,
  default 24h) and `POST /api/housekeeping/purge` runs it on demand, both
  audit-logged. A project with neither set is left untouched (opt-in, not
  silent, since deletion isn't reversible). **(this session)** `issues`/
  `hotspots` previously had no `project_id`/`analysis_id` at all — a flat
  table with no way to express "issue history" for a project
  (`infra/postgres/migrations/0001_init.sql`). Migration `0016` adds both
  columns (nullable, `ON DELETE CASCADE`), threaded through the save path
  via a new `IssueScope` port type so newly-saved findings land pre-scoped;
  pre-migration rows stay `NULL` rather than being guess-backfilled, which
  the purge query's join against `projects` naturally treats as "keep
  forever," same as a project with no retention configured. The purge query
  now deletes scoped `issues`/`hotspots` past their project's effective
  retention alongside `analyses`, same timer/on-demand/audit-log wiring.

## Phase 4 — API, web platform & collaboration

- **REST API parity**: pagination envelopes, rich filtering/faceting
  (severity, rule, file, assignee, tag, creation date…) — done. ✅
  **(this session)** Measures + measure history, component tree, and a
  `sources` endpoint: `analysis_measures`/`analysis_file_coverage_lines`
  (migration `0017`) persist a real per-analysis measure set (project- and
  file-level) and per-line coverage hit counts — there was no historical
  measure storage at all before this, only a couple of summary columns on
  `analyses`. `GET /api/projects/{key}/measures/history` and
  `GET /api/projects/{key}/components/tree` (a flat, measure-annotated file
  list for v1 — not yet a nested directory tree, documented as a scoped-down
  first cut) expose it; `GET /api/projects/{key}/sources` returns per-line
  issue + coverage annotations. Duplication and SCM blame annotations,
  and source text itself (never persisted anywhere), are explicitly
  deferred rather than fabricated. Contract stays generated:
  `api/openapi.json`.
- **Auth**: local users + user tokens (already-hashed at rest), OAuth
  (GitHub/GitLab), SAML later; groups; global + per-project permissions,
  permission templates.
- **Webhooks** (analysis finished, gate changed) with delivery log +
  retries; **email notifications** per user subscription.
- **Project features**: badges, links, tags, favorites, project export/
  import between instances.
- **Background tasks**: ✅ **(this session, issue #30)** `GET
  /api/admin/queue/status` (`bin/server/src/tasks.rs`, `AdminAccess`-gated)
  reports the real `scan_jobs` queue depth by status, the oldest pending
  job's age, and recent failures — backed by `PgIssueStorage::queue_status`
  (`infra/postgres/src/queue.rs`). That data only exists because the queue
  itself changed: a claim now increments a persisted `attempts` counter
  (migration `0019`) and a handler failure records `last_error` instead of
  being silently released back to `pending` forever, dead-lettering to a
  terminal `dead` status once the retry budget (5 attempts) is exhausted —
  previously a failed job retried indefinitely with no trace of why.
  `GET /api/projects/{key}/activity` (`bin/server/src/activity.rs`,
  `infra/postgres/src/activity.rs`, migration `0020`) is a new per-project
  activity log the worker writes `scan.started`/`scan.succeeded`/
  `scan.failed` entries to around every job (`bin/worker/src/main.rs`) —
  this doubles as the "diagnóstico de fallos de análisis" item, since a
  failed scan's error message lands in both the project's activity log and
  the admin queue-failure list. Removed the earlier `tasks`/`diagnostics`/
  `diagnostics_wire` skeletons this replaced: the first was an unwired
  in-memory tracker, the latter two returned fully hardcoded fake data for
  worker heartbeats and query telemetry that don't exist anywhere in this
  codebase — real per-project activity plus real queue/failure data is a
  scoped-down but honest cut of the original three-item checklist, not a
  fabricated one.
- **Ops**: ✅ system info endpoint (`ops::system_info`) and audit log
  persistence + endpoint (`ops::list_audit_log`, `infra/postgres/src/{audit,system}.rs`,
  migrations 0011–0013), on top of the existing `/health` and Prometheus metrics.

## Phase 5 — SCM/ALM & CI integration

- **GitHub**: app installation, check runs, PR decoration (gate summary +
  inline comments on changed lines), status checks blocking merge.
- **GitLab / Bitbucket / Azure DevOps** behind the same `AlmGateway` port.
- **Scanner ergonomics**: ✅ `--project`/`--branch`/`--pr` flags on `bin/cli`,
  resolved against auto-detected CI context (`ci_detect.rs`, pure detection
  over an injected env lookup — GitHub Actions' `GITHUB_ACTIONS`/`GITHUB_SHA`/
  `GITHUB_REF`/`GITHUB_REPOSITORY` plus PR number from `GITHUB_EVENT_PATH`,
  and GitLab CI's `GITLAB_CI`/`CI_COMMIT_SHA`/`CI_MERGE_REQUEST_IID`);
  explicit flags always win over auto-detection. SCM blame capture
  (`blame.rs`, `git blame --porcelain` output parsed by a pure, fixture-
  tested function). First-party CI templates (`ci-templates/{github-actions,
  gitlab-ci}.yml`). Monorepo support (`infra/fs/src/monorepo.rs` +
  `bin/cli/src/monorepo_scan.rs`): discovers every `yunq.toml` under the
  scan root, treats each as an independent project boundary, and aggregates
  per-project results instead of flattening them into one report.
- **IDE integration (SonarLint equivalent)**: `yunq-lsp` — an LSP server
  over the same core, with connected mode syncing the server's profile and
  issue suppressions. In-editor analysis in any LSP-capable editor beats
  SonarLint's per-IDE plugins.

## Phase 6 — AI: Remediation Agent & AI code governance

- **6a Core loop** (`yunq-remediation`): generate → sandbox → re-scan →
  verdict via ports: `FixGenerator` (Claude API adapter), `Sandbox` (git
  worktree adapter), verification by the embedded `AnalyzerService` —
  accept only if the original issue disappears and none appear.
  ✅ **Provider choice + BYOK**: `LlmProvider` has two adapters
  (`OpenAiCompatibleAdapter` for OpenAI/Groq/DeepSeek/Ollama/vLLM/LiteLLM
  proxy, `AnthropicAdapter` for the native Messages API) selected at
  runtime through `LlmProviderConfig`/`AnyLlmProvider`
  (`infra/llm::provider`). Falls back to a platform-wide env-configured
  default; a project can override it with its own provider/model/API key
  via `PUT/GET/DELETE /api/projects/{key}/ai-provider` (`AdminAccess`-gated,
  audit-logged). The key is AES-256-GCM encrypted at rest under a
  server-side `YUNQ_SECRETS_KEY` (`infra/postgres::llm_config`), never
  returned in plaintext by the API.
- **6b Assign to Agent**: `POST /issues/{id}/assign-to-agent`, bulk action,
  one PR per issue via `PrGateway`; PR-scoped mode proposes fixes when a PR
  breaks its quality gate. Developer-in-the-loop always.
- **AI Code Assurance equivalent**: flag projects/files as AI-generated,
  enforce stricter gates on AI-authored code, provenance tracking.
- **Fix suggestions in-editor** through `yunq-lsp` connected mode.

## Phase 7 — Enterprise platform

- **Portfolios**: hierarchical aggregation across projects with rollup
  ratings and PDF/report exports; **executive-level views** across projects,
  applications and portfolios (health overview, risk distribution, trends).
- **Compliance & audit reports**: generated security reports mapped to
  OWASP Top 10, CWE Top 25, PCI DSS and similar standards; regulatory
  evidence exports (PDF/CSV) per project and portfolio; full audit trail of
  who changed gates/profiles/permissions and when.
- **Cross-platform governance**: one set of quality/security standards
  (gates + profiles) enforced across teams regardless of DevOps platform —
  the `AlmGateway` port makes GitHub/GitLab/Bitbucket/Azure DevOps
  interchangeable enforcement points.
- **Enterprise IAM**: SSO (SAML/OIDC), SCIM provisioning, LDAP, group-based
  permission templates, service accounts with scoped tokens, advanced audit,
  data residency.
- **Scale & HA**: multi-node server (stateless already), Postgres read
  replicas, blue-green migrations, monorepo sharding, **parallel analysis
  for large teams** (the worker fleet + per-core parallelism from the
  performance pillar).

## Enterprise-edition parity checklist

Every SonarQube Enterprise selling point, mapped — and everything ships
open in yunq, not behind an edition wall:

| SonarQube Enterprise feature | yunq phase |
|---|---|
| Everything in Developer edition | Phases 2–5 (branch/PR analysis, taint, ALM decoration) |
| AI coded fix suggestions at the click of a button | Phase 6a/6b (Remediation Agent, "Assign to Agent") |
| Executive views: projects, applications, portfolios | Phase 7 (portfolios + executive dashboards) |
| Govern standards across teams on different DevOps platforms | Phase 3 (gates/profiles) + Phase 5 (`AlmGateway`) + Phase 7 |
| Security, regulatory, and audit compliance reports | Phase 7 (OWASP/CWE/PCI reports, audit trail) |
| Improved performance for large teams, parallel analysis | Performance pillar (measured ~398k LOC/s) + worker fleet |
| Enterprise-grade IAM | Phase 4 (tokens, OAuth, permissions) → Phase 7 (SAML/OIDC, SCIM, LDAP) |
| ~80% more issue types, +6 languages, private-service secrets | Phase 2 (open language roster, rule catalog, multi-provider secrets incl. self-hosted/private services) |

## Algorithm parity against upstream SonarQube

Tracks specific algorithms audited against a clone of `SonarSource/sonarqube`
to confirm yunq replicates the actual logic rather than a shortcut that
merely looks similar on the happy path.

| Algorithm | Upstream source | Status |
|---|---|---|
| Duplication detection (CPD) | `sonar-duplications/.../block/BlockChunker.java`, `index/` | ✅ Ported: statement-repetition collapsing, Rabin-Karp rolling hash (base 31, block size 5), cross-file hash index (`core/duplication`). Previously a raw per-line sliding-window hash with no repetition collapsing or shared index — fixed. |
| Maintainability rating (A–E) | `server/sonar-server-common/.../DebtRatingGrid.java`, `MaintainabilityMeasuresVisitor.java` | ✅ Ported: rating from technical debt ratio (remediation effort ÷ (LOC × 30 min)) against grid `[0.05, 0.1, 0.2, 0.5]` (`core/profiles::Rating::from_debt_ratio`). Previously derived from worst issue severity present, which is not SonarQube's algorithm at all — fixed. |
| Cognitive complexity | `sonar-java/.../ast/visitors/CognitiveComplexityVisitor.java`, `eslint-plugin-sonarjs/src/rules/cognitive-complexity.ts` (no local vendored clone; fetched directly from `SonarSource/sonar-java` and `SonarSource/eslint-plugin-sonarjs` on GitHub) | ⚠️ Re-verified against the real upstream source (not just the marketing white paper, which is bot-blocked from automated fetch). **Confirmed matching**: the nesting-weight formula (`1 + current nesting` for `if`/loops/`switch`/ternary/`catch`), the flat `+1` for `else`/`else if` without extra nesting, the else-if chain not compounding nesting per link, the single flat cost for a switch regardless of case count, the flat `+1` for a *labeled* `break`/`continue` only, and the boolean-operator-sequence rule (`+1` on the first operator and again only when the operator changes, parens transparent) — all verified against `CognitiveComplexityVisitor.java`'s actual logic and against `rulesets/code-smells/src/cognitive_complexity.rs`'s existing test suite, which already ports SonarSource's own `sonar-java` fixture files (`CognitiveComplexityMethodCheckMax0.java` et al.) and matches their documented totals exactly. **Recursion rule**: ✅ direct self-recursion now ported — a flat `+1` (not nesting-weighted; recursion is a "meta-loop", charged like a labeled jump) for a call within a `FunctionDef` whose callee resolves to that same function's own declared name, covering both plain `foo()` calls and method-style `self.foo()`/`this.foo()` calls (`fn_name`/`is_recursive_call` in `rulesets/code-smells/src/cognitive_complexity.rs`, regression-tested against SonarSource's own whitepaper `Sum` recursion example). Indirect/mutual recursion across functions remains out of scope — it needs a whole-file call graph, which this same-file rule intentionally doesn't build (a cross-function heuristic would silently under- or over-fire across 18 wired grammars); tracked as a follow-up, not a gap in what was scoped here. **Documented, not fixed**: SonarSource's own plugins disagree on nested function/lambda treatment — `sonar-java`'s `visitLambdaExpression` folds a lambda body into the *enclosing* method's score (nesting++ only, no isolation) and `sonar-dotnet` does the same for C# local functions, while `eslint-plugin-sonarjs` pushes a fresh isolated scope for every `:function` (declarations and arrow functions alike) and legacy `sonar-python` skips nested `FUNCDEF`s from the outer scan entirely. yunq isolates every `NodeKind::FunctionDef` (closures included) as its own independently-scored unit, matching the actively-maintained JS/TS reference implementation rather than the Java/C# quirk — a deliberate choice, not a bug, kept as-is. |
| New Code / issue tracking across analyses | `org.sonar.core.issue.tracking.Tracker`/`LineHashSequence` (scanner-engine, separate repo) | ✅ Ported the content-hash-first cascade: `core/rules-engine/src/new_code.rs::Baseline` now hashes the real source line at each issue's span (whitespace-normalized, mirrors `LineHashSequence`) and matches on (rule, file, line-hash) — immune to a message drifting on trivial edits (e.g. "cognitive complexity 7" → "8") and tolerant of the line moving elsewhere in the file — falling back to the old (rule, file, message) fingerprint only when no source text is available (legacy baseline files, or a caller with no filesystem access), same as SonarQube's own last-resort pass. `bin/cli::FileLineHashes` plumbs real file content in; `infra/fs::BaselineStore` persists per-issue hashes with fail-open migration for baseline files written by older yunq versions. Previously a bare (rule, file, message) fingerprint with no source access at all — fixed and verified live via the CLI (same line, message-only drift → `new_issue_total` stays 0). |
| Quality gate evaluation | Sonar's condition-set model (generic, no single algorithm file) | Structurally equivalent (named conditions over metrics, fail-if-any-breached, fail-open on missing measure) — no changes needed. |
| Reliability/Security ratings + remediation effort by rule/component | `server/sonar-server-common/.../Rating.java`, `.../ReliabilityAndSecurityRatingMeasuresVisitor.java` (fetched from `SonarSource/sonarqube` on GitHub; no local vendored clone) | ✅ Ported the actual (different-from-Maintainability) algorithm: `Rating::from_severity` mirrors `RATING_BY_SEVERITY` exactly (`BLOCKER→E, CRITICAL→D, MAJOR→C, MINOR→B, INFO→A`), and `reliability_and_security_ratings` (`core/profiles::rating`) takes the worst rating within each issue type independently — Bug issues drive Reliability, Vulnerability issues drive Security, Code smells and the other type never touch either — instead of one shared debt-ratio grid or a single worst-severity-across-everything number. `aggregate_remediation_effort` sums minutes by rule and by component/file for drill-down reporting. Tests pin the exact severity table and a case a naive "one grid for everything" implementation would get wrong (a Blocker code smell must not move Reliability/Security; a Blocker bug must not move Security). ✅ **Wired to real analysis**: every `Rule`/`CrossFileRule` now declares a real `issue_type` (`953ff6d`), so `AnalyzerService::analyze_files` folds each produced issue's type + severity into `Metrics` via `record_issue_type_and_effort`, exposed as `AnalysisReport::reliability_rating`/`security_rating`/`remediation_effort` and as gate-condition-ready measures — no longer isolated to `core/profiles` unit tests. |

## Sequencing

Phases 2 and 3 are startable now and parallel; Phase 4 follows 3 closely so
the frontend swaps mocks for real endpoints incrementally. Performance pillar
work starts immediately (interning + rayon are Phase-2 groundwork). Phase 6a
prototypes as soon as 2/3 stabilize the issue model; 6b needs 4 + 5. Phase 7
last — nothing in it blocks product value earlier.
