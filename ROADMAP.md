# yunq Roadmap — the ultraperformant ultimate code analysis platform

Mission: **a complete code-quality platform that beats the incumbents** — on
performance, on architecture, on developer experience, and on agent-native
automation. Phase 1 (hexagonal workspace, working analyzer, CLI, SQS/Postgres
pipeline, OpenAPI contract) is **done**.

**Where yunq wins by design:**

- 100% pure, unit-testable analysis core — the established tools in this
  space couple analysis to a JVM platform monolith.
- OpenAPI 3.1 generated from code as a first-class contract; the incumbent
  web APIs have no complete formal spec.
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
- **Rule catalog at scale**: build out the high-value rules per language;
  rule metadata (name, description in markdown, remediation effort function,
  tags, CWE / OWASP Top 10 / CERT mappings); `GET /rules` API with search.
  47 rules shipped (10 per-file + 1 cross-file in `rulesets/owasp`, 7 in
  `rulesets/code-smells`, 2 in `rulesets/iac`, 2 in `rulesets/a11y`, 22 in
  `rulesets/rust`, 9 in `rulesets/php`) plus duplication and taint. The dedicated `rulesets/rust`
  crate (2026-07-23) is the first language-specific ruleset (as opposed to
  the neutral-AST checks in `rulesets/code-smells` that merely happen to
  apply to every language): `rust:unsafe-undocumented` (an `unsafe` block
  with no adjacent `SAFETY` comment), `rust:mem-transmute` and
  `rust:mem-forget` (hotspots on the two classic ways to break soundness or
  leak without `unsafe` itself), and `rust:process-exit`
  (`process::exit`/`process::abort` skip `Drop` cleanup) — on top of the
  existing `smells:unwrap-usage`. ✅ **(2026-07-27)** `rulesets/rust` grown
  from 4 rules to 11: `rust:static-mut` (unsynchronized global mutable
  state), `rust:mem-uninit-or-zeroed` (`mem::uninitialized`/`mem::zeroed`
  conjuring a value with no validity check — the same soundness-hotspot
  shape as the existing `mem-transmute`/`mem-forget`), `rust:box-leak`
  (`Box::leak`, the allocator-API way to reach the same intentional-leak
  hotspot `mem-forget` covers via `mem`), `rust:unsafe-send-sync-impl` (a
  manual `unsafe impl Send`/`Sync` with no `SAFETY` comment justifying the
  thread-safety invariant it asserts — reuses the same adjacent-comment
  convention as `unsafe-undocumented`), `rust:panic-in-drop` (a
  panic/`unwrap`/`expect`/`assert!` inside `Drop::drop`, which aborts the
  process instead of unwinding if it fires during another unwind),
  `rust:from-over-into` (a manual `impl Into<B> for A` where `impl From<A>
  for B` would give `Into` for free, mirrors `clippy::from_over_into`), and
  `rust:dbg-macro` (a `dbg!` debug leftover). A new `rulesets/rust::common`
  module factors out the `impl`-trait-name extraction
  (`trait_of_impl`/`impl_trait_is`, used by three of the new rules) and the
  `SAFETY`-comment lookup (shared with `unsafe-undocumented`) that would
  otherwise have been duplicated across rule files. All 7 wired into the
  built-in yunq way profile (`core/profiles/src/builtin.rs`) at their real
  default severities. ✅ **(2026-07-27, same session)** gap analysis against
  Clippy/SonarQube's Rust coverage — the honest read is that neither is
  close to being outmatched on raw rule *count* (Clippy alone ships ~600
  lints), so the second `rulesets/rust` pass targeted specific
  high-confidence categories rather than trying to race that number: five
  more rules, taking the ruleset to 16. Two are correctness checks Clippy
  itself deny-by-defaults on: `rust:drop-on-reference` (`drop(&x)`/
  `drop(&mut x)` drops the reference, not the referent — a syntactic,
  zero-type-inference no-op-bug check, mirrors `clippy::drop_ref`/
  `forget_ref`) and `rust:derive-hash-manual-partial-eq` (a type derives
  `Hash` but hand-writes `PartialEq`, risking a silent `Hash`/`Eq` contract
  break that corrupts `HashMap`/`HashSet` lookups; same-file only —
  mirrors `clippy::derived_hash_with_manual_eq`). Two more catch
  comparison bugs syntactically, without needing symbol/type resolution:
  `rust:self-comparison` (`x == x`/`x != x`, mirrors `clippy::eq_op`) and
  `rust:float-literal-eq` (a float compared to a literal with `==`/`!=`,
  mirrors `clippy::float_cmp_const`) — both share a new
  `common::operator_between` helper that recovers the (grammar-anonymous,
  not present as an AST node) operator token from the raw source between
  the two operand spans, since tree-sitter-rust's `binary_expression` only
  exposes its two operands as named children. The fifth,
  `rust:blocking-sleep-in-async`, is a category neither Clippy nor Sonar
  covers at all: `std::thread::sleep` called directly in an `async fn`'s
  own body blocks the executor thread instead of yielding it, stalling
  every other task scheduled on it — detected by walking the async fn's
  body while skipping any nested closure/fn (so a sleep intentionally
  wrapped in `spawn_blocking(|| ...)` is correctly not flagged). `common.rs`
  also grew a shared `self_type_of_impl` (alongside the existing
  `trait_of_impl`) so `derive-hash-manual-partial-eq` didn't have to
  re-derive `impl_item`'s positional-children shape a third time. All five
  wired into the built-in yunq way profile. ✅ **(2026-07-27, same session)**
  explicit goal set: match SonarQube's rule-catalog depth for Rust,
  TypeScript, Python, and PHP (Java out of scope by decision). Reality
  check first — `rules.sonarsource.com` itself is down (confirmed via
  live search, Feb 2026), so exact per-language counts aren't pinnable to
  a single source, but the order of magnitude is clear from Sonar's own
  docs/blog: JS+TS combined "500+" rules, Python "300+", PHP "hundreds"
  (unconfirmed exact figure), Rust much newer and smaller — SonarQube's
  Rust analyzer leans on integrating 85 Clippy rules directly rather than
  authoring a large native catalog. Against that, yunq's rust-specific
  count (16) plus generics is in the same order as Sonar's Rust catalog;
  TS/Python (12+12 react / 28 python-specific, plus generics) are a much
  smaller fraction of Sonar's 300-500; PHP was the starkest gap: **zero**
  PHP-specific rules despite `parsers/treesitter-php` existing since the
  parser-roster phase. Bootstrapped `rulesets/php` (new crate, wired into
  all three composition roots — `bin/cli`, `bin/server`, `bin/worker` — and
  a new `php_activations()` in `core/profiles/src/builtin.rs`) with a
  first batch of 9 rules chosen for confirmed-real vulnerability classes
  Sonar's own PHP catalog covers: `php:eval-usage` and `php:extract-usage`
  (dynamic code / variable-scope injection, hotspots), `php:sql-injection-
  concat` (query built by `.`-concatenation into a `mysqli_query`/`pg_query`/
  `->query`/`->exec`/`->prepare` sink — mirrors `python:sql-injection-
  string-building`'s scope-limited, same-call-site heuristic), `php:command-
  execution` (`system`/`exec`/`shell_exec`/`passthru`/`popen`/`proc_open`,
  filling a gap the generic `owasp:command-execution`'s sink list — Rust/Go/
  Python/TS-specific — never covered for PHP at all), `php:loose-hash-
  comparison` (PHP's "magic hash" `==` type-juggling bug on `md5`/`sha1`/
  `hash`/`crc32` results), `php:dynamic-function-call-from-superglobal`
  (`$_GET['f']()`/`call_user_func($_GET['f'])` — request data choosing which
  function in the program runs), `php:error-suppression-operator` (the `@`
  operator), `php:variable-variable` (`$$name`), and `php:weak-random-
  token` (mirrors `typescript:math-random-for-token`'s naming-heuristic
  shape, retargeted at `rand`/`mt_rand`/`uniqid`). A new `rulesets/php::
  common` module holds `callee_node` — recovering a call's callee
  uniformly across tree-sitter-php's three different `Call` shapes (bare
  function: `[name, arguments]`; method: `[receiver, method_name,
  arguments]`, no `MemberAccess` wrapper at all; dynamic:
  `[subscript_expression, arguments]`) — plus the same `operator_between`
  technique `rulesets/rust` uses to recover `binary_expression`'s
  grammar-anonymous operator token. All 9 verified against tree-sitter-
  php's actual parse shapes (not guessed) and wired into the built-in yunq
  way profile. This is phase one of a multi-session build-out, not
  parity yet — TS, Python, and Rust all still need further rounds to
  close the gap against Sonar's real catalog sizes. ✅ **(2026-07-27, next
  session)** Rust round three, this time explicitly aiming to *surpass*
  SonarQube's Rust coverage rather than just match it — since Sonar-Rust's
  own catalog leans on 85 first-party Clippy rules rather than a large
  native one, the bar to clear is lower than TS/Python/PHP's, and the
  90-rule gap analysis is tractable by hand. `rulesets/rust` grew from 16
  to 22, all verified against real tree-sitter-rust `node-types.json`
  shapes via a scratch AST-dump binary before writing any check (per-
  session methodology, not skipped). Four fill confirmed Clippy
  correctness/suspicious gaps: `rust:modulo-one` (`x % 1` is always `0`,
  mirrors `clippy::modulo_one`, deny-by-default correctness), `rust:almost-
  swapped` (`a = b; b = a;` back-to-back loses `a`'s original value instead
  of swapping — mirrors `clippy::almost_swapped`), `rust:absurd-extreme-
  comparison` (an unsigned parameter compared against `0` with `<`/`>=` is
  always false/true — mirrors `clippy::absurd_extreme_comparisons`, scoped
  to parameter-declared types only so it needs no real type inference), and
  `rust:suspicious-arithmetic-impl` (an `impl Add`/`Sub`/`Mul`/`Div`/`Rem`/
  bitwise-op-trait body that never uses its own trait's operator but does
  use a different one — mirrors `clippy::suspicious_arithmetic_impl`;
  reuses the existing `impl_trait_is`/`operator_between` helpers directly).
  One closes a real-world gap Clippy only covers behind its
  pedantic/nursery lint groups (off by default in most projects, so this is
  a genuine differentiator even though the category exists upstream):
  `rust:mutex-atomic-candidate` (`Mutex<bool>`/`Mutex<u32>`/etc. pays for
  locking to guard a value `std::sync::atomic` could update lock-free —
  mirrors `clippy::mutex_atomic`, nursery-only in real Clippy). The last is
  original — a category neither Clippy's default lints nor Sonar's catalog
  reach at all: `rust:lock-held-across-await` (a `let g = m.lock()...`
  guard still alive across a later `.await` in the same block keeps the
  lock held for the whole time the task is suspended, stalling every other
  task waiting on it — tracked via a straight-line statement walk per
  block: which locals a block's own `let` statements bind from a `.lock(`
  call, minus whatever `drop(..)` explicitly releases before the `.await`,
  skipping nested closures/fns the same way `blocking-sleep-in-async`
  does). All six wired into the built-in yunq way profile
  (`core/profiles/src/builtin.rs`) at their real default severities; 103
  tests total in `rulesets/rust`, `cargo clippy -p yunq-rules-rust
  --all-targets` clean. Latest additions (2026-07-22) unblock two
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
  yunq way profile (`core/profiles/src/builtin.rs`). ✅ **(this session)**
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
  literal hook names, not custom wrapper hooks. ✅ **(2026-07-27, this
  session)** New category, not just new rules: **`rulesets/ai-agent`**, the
  first crate in the catalog aimed squarely at AI-generated and AI-agent
  code rather than a language. Positioning matters here — this is the first
  concrete step toward yunq as "the SonarQube of AI-agent-generated code":
  live, on-every-change audit of the two risk classes industry research
  itself flags as uncovered by generic SAST (Semgrep, CodeQL, Bandit).
  arXiv:2605.02741 ("AI-Generated Smells") and arXiv:2603.22853 ("Agent
  Audit") both call out that no generic SAST tool models an LLM's own
  output as a taint source, or a `@tool`/MCP boundary; Trend Micro/Mend.io's
  slopsquatting research puts ~20% of AI-generated code samples referencing
  a hallucinated package. `ai:llm-output-injection` (TypeScript + Python)
  closes the first gap: it reuses the existing generic taint engine
  (`core/taint::TaintAnalysis`/`TaintConfig`, unmodified — same
  `with_source_marker`/`with_sink`/`with_sanitizer` shape
  `owasp:injection`/`owasp:cross-file-injection` already use) but points it
  at LLM SDK response shapes as *sources* instead of user-input shapes:
  OpenAI-style `.choices[0].message.content` and Anthropic-style
  `.content[0].text` (grounded in this repo's own `infra/llm::
  openai_compatible`/`anthropic` adapters — `ChatCompletionResponse{
  choices }` / `MessagesResponse{ content }` are this codebase's real
  equivalents of what a TS/Python agent's SDK call returns), plus the
  generic `message.content`/`response.content`/`completion.content` shape
  any thin wrapper tends to keep, flowing unsanitized into `eval`/`exec`/
  `execSync`/`system`/`Popen`/`run`/`check_output`/`check_call`/`query`/
  `execute` — literally "an agent runs what another LLM told it to,
  unsanitized," this year's recurring agent-security-talk bug. Verified
  against real tree-sitter TS/Python parses via a scratch AST-dump binary
  first (methodology carried over from the Rust/PHP sessions): critically,
  `.choices[0].message.content`'s `[0]` subscript stays inside the
  `MemberAccess` node's own text in both grammars, so it round-trips
  through the taint engine's plain substring source-marker matching with
  no engine changes needed. Wired into all three composition roots (`bin/
  cli`, `bin/server`, `bin/worker`) and `typescript_activations()`/
  `python_activations()` in `core/profiles/src/builtin.rs` at
  `Severity::Blocker`. Alongside it, two smaller items round out this
  session's other identified "vibe coding" defect buckets: `typescript:
  swallowed-exception`/`php:swallowed-exception` (parity with the existing
  `python:bare-except`/`broad-exception-swallowed` — an empty `catch`, or
  one that only `console.log`s/`error_log`s the error with no re-throw and
  no other handling; PHP's `expression_statement`→`NodeKind::Assignment`
  parser quirk, already documented against `common::callee_node`, applies
  here too — a bare `error_log(...)` or `throw $e;` statement surfaces as a
  single-child `Assignment` node, not its own statement kind) and
  `smells:db-call-in-loop` (cross-language, `applies_to` true like
  `smells:select-star`: a `.query(`/`.execute(`/`.find(`/`->query(`-shaped
  call inside a `for`/`while`/`foreach` body — the classic N+1 pattern,
  purely syntactic so it needs no type resolution; nested loops are walked
  without double-descending into an inner loop's own body, so a call inside
  a doubly-nested loop is reported once, by the inner loop; `.find(callback)`
  — `Array.prototype.find` — is excluded via a sole-argument-is-a-
  `FunctionDef`/closure check to avoid the obvious JS false positive).
  **Explicitly evaluated and deferred**: item 4 of this session's brief,
  manifest-vs-import mismatch detection (the slopsquatting surface itself —
  cross-referencing every `import`/`require`/`use` against `package.json`/
  `requirements.txt`/`pyproject.toml`/`composer.json`) turned out to be a
  real subsystem, not a rule, so it's not force-fit into this session.
  Concretely, three gaps found by checking before committing to it: (1)
  `core/import-graph` — the obvious reuse candidate — deliberately discards
  exactly the specifiers this needs (`resolve.rs`'s own module docs: bare/
  external specifiers "always treated as external and produce no edge"),
  so this needs its own extraction pass, not an extension of that one; (2)
  manifest parsing is workable but split three ways with no existing
  precedent in this codebase — `package.json`/`composer.json` are JSON
  (parseable via `serde_json` directly on `SourceFile::content()`,
  bypassing the tree-sitter-json AST entirely), `pyproject.toml` needs the
  already-a-workspace-dependency `toml` crate (no `parsers/treesitter-toml`
  exists, and none is needed if parsed as data rather than as an AST),
  `requirements.txt` is line-oriented text with no grammar at all; (3) the
  false-positive floor is the real blocker — flagging every import not
  found in a manifest needs a curated stdlib/builtin-module allowlist per
  language (dozens of Node builtins, hundreds of Python stdlib modules) or
  every project lights up on `fs`/`os`/`json`, and PHP compounds this with
  no mechanical namespace→package mapping (`Vendor\Package` to
  `vendor/package` goes through `composer.json`'s PSR-4 `autoload` map, not
  a naming convention). Concrete next step for a future session: a new
  whole-project pass (`CrossFileRule`, same shape as
  `architecture:dependency-cycle`) that (a) parses manifests as data via
  `serde_json`/`toml` rather than through the AST pipeline, (b) adds a
  dedicated external-specifier extraction pass per language (TS: bare
  non-relative import specifiers; Python: top-level module of `import
  X`/`from X import Y`; PHP: `use` statement namespaces resolved through
  `composer.json`'s own `autoload.psr-4` map), (c) ships hand-curated
  stdlib/builtin allowlists for Node and Python as static tables (PHP has
  no comparable ambiguity once autoload is resolved), and (d) flags an
  import with no manifest match and no allowlist match — scoped to
  TypeScript/Python/PHP, one language at a time rather than all three in
  one pass, to keep the false-positive tuning tractable.
- **External analyzer import (SARIF)**: ✅ **(this session)** `--sarif`
  (repeatable) merges any SARIF 2.x report into the scan —
  `infra/fs/src/sarif.rs` parses the log, `AnalysisReport::add_external_issues`
  (+ the new `ExternalIssue` domain type) folds the findings into the same
  severity counters, debt total and Reliability/Security ratings the engine's
  own rules feed, so from that point on an imported finding is an ordinary
  `Issue`: rendered, measured, and able to fail the quality gate. This is the
  highest rules-per-LOC lever available — ~600 LOC buys the catalogs of ruff,
  ESLint, clippy, gosec, bandit, semgrep and CodeQL without yunq
  reimplementing one of their checks, and it is why every mature platform in
  this space ships a shelf of external-report importers. Design decisions worth keeping: rule ids are
  namespaced by emitting tool (`ruff:e501`, `codeql:js-sql-injection`) so
  imported rules never masquerade as native ones; severity prefers
  `properties.security-severity` (CVSS) and otherwise maps `level` *down*
  (`error` → `major`, not `critical`) because a linter's "error" is its own
  default failure level, not a project-critical finding; classification is
  `Vulnerability` only on a real security signal (`security-severity`, or a
  `security`/`cwe-*`/`owasp-*` tag) with **no** `Bug` inference, since SARIF
  carries no field that distinguishes a bug from a smell and guessing
  corrupts the Reliability rating; and imported issues add zero debt and zero
  LOC unless an importer genuinely knows the effort, keeping the debt ratio
  honest. Non-`fail` kinds, tool-suppressed results and location-less results
  are dropped with a reported count rather than silently swallowed. Still
  open: only the CLI ingests SARIF (no server-side upload endpoint), and
  `--monorepo` skips it for the same reason it skips coverage/JUnit — one
  report rarely maps cleanly onto several independent projects.
- **Issue types & classification**: ✅ every rule declares a classic
  `IssueType` (bug / vulnerability / code smell, `Rule::issue_type`,
  `core/rules-engine/src/rule.rs`) alongside MQR-style software-quality
  impacts (reliability, security, maintainability × severity —
  `SoftwareQuality`/`ImpactSeverity`/`SoftwareQualityImpact`,
  `core/profiles/src/impact.rs`), derived by default from the classic type
  via `default_impact` and overridable per rule. Both classification modes
  are exposed simultaneously on `GET /api/rules` and `GET /api/issues`
  (`type` + `impacts` fields).
- **Secrets detection**: ✅ dedicated `rulesets/secrets` crate — entropy
  detection (`entropy.rs`), provider patterns for AWS/GCP/Azure/Stripe/
  private-key blocks (`provider_patterns.rs`), and custom-pattern support for
  private/self-hosted services (`custom_pattern.rs`); wired into all three
  composition roots (CLI, server, worker).
- **Duplication detection (CPD)**: ✅ core algorithm ported from
  block hashing — statement-repetition
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
  Usually a paid-tier category; yunq ships it open.
- **Language-specific ruleset: Python** ✅ **(this session)** — a new
  `rulesets/python` crate (`yunq-rules-python`), the same shape as
  `rulesets/rust`: idioms that only make sense for this language, as
  opposed to the neutral-AST checks in `rulesets/code-smells` that merely
  happen to apply to Python too. 22 rules, each grounded in the real
  tree-sitter-python grammar shapes (verified with a throwaway AST-dump
  example before writing detection logic, not guessed) rather than raw
  line/text scanning: `python:mutable-default-argument` (a `[]`/`{}`/`set()`
  literal or `list()`/`dict()`/`set()` call as a parameter default, shared
  and mutated across every call site that doesn't override it),
  `python:bare-except` (catches `SystemExit`/`KeyboardInterrupt` too),
  `python:broad-exception-swallowed` (`except Exception`/`BaseException`
  whose body is only `pass`), `python:assert-used-in-production` (a
  security hotspot — `assert` is stripped under `-O`; test-file paths are
  exempted via the existing `is_test_only_path` helper),
  `python:subprocess-shell-true`, `python:unsafe-yaml-load` (`yaml.load`
  missing an explicit `Loader`), `python:xml-xxe-hotspot` (the stdlib's
  `xml.etree`/`minidom`/`sax` parsers resolve external entities by
  default), `python:insecure-tempfile` (`tempfile.mktemp`'s TOCTOU race),
  `python:wildcard-import`, `python:type-comparison` (`type(x) ==` instead
  of `isinstance`), `python:global-statement-usage`, and
  `python:eager-logging-interpolation` (an f-string or `%`/`+` built before
  a `logging.*` call always pays the formatting cost, even when the level
  is disabled). Batch 2 added ten more, same grounding discipline:
  `python:none-comparison-with-equality` / `python:bool-comparison-with-equality`
  (`== None`/`== True`/`== False` instead of `is`/direct truthiness),
  `python:literal-identity-comparison` (`x is 5`/`x is 'foo'` — relies on
  CPython's small-int/string interning, an implementation detail),
  `python:len-as-condition` (`len(x) == 0` instead of `if not x:`),
  `python:requests-missing-timeout` (a `requests.*` call with no
  `timeout=` hangs forever on a dead remote host), `python:flask-debug-true`
  (Werkzeug's interactive debugger is remote code execution if it ships to
  production), `python:bind-all-interfaces` (a `0.0.0.0` bind host, hotspot),
  `python:sql-injection-string-building` (a `.execute()`/`.executemany()`
  call whose query is an f-string or `%`/`+`-built string instead of a
  parameterized query — Python had no SQL-injection rule at all before
  this; `owasp:injection`'s taint analysis is TypeScript-only),
  `python:debugger-left-in-code` (`pdb.set_trace()`/`breakpoint()` hangs
  the first non-interactive run that reaches it), and
  `python:open-without-encoding` (text-mode `open()` with no `encoding=`
  depends on the platform's locale-preferred encoding). All 22 carry both
  classic `IssueType` and MQR impacts, ship with unit tests per rule, and
  are wired into all three composition roots (`bin/cli`, `bin/server`'s
  rule catalog, `bin/worker`) and `python_activations()`
  (`core/profiles/src/builtin.rs`) with severities cross-checked against
  each rule's `default_severity()`. Batch 3 (6 more) rounds out
  correctness/maintainability idioms: `python:datetime-utcnow-naive`
  (naive + deprecated since 3.12), `python:mutable-class-attribute` (the
  class-body twin of the mutable-default-argument trap — one object
  shared by every instance, detected by walking each `class_definition`'s
  own body block without descending into nested `FunctionDef`s, so an
  instance attribute set in `__init__` is correctly left alone),
  `python:nested-comprehension-too-deep` (2+ `for` clauses in one
  list/dict/set/generator comprehension), `python:raise-generic-exception`
  (`raise Exception(...)`/`BaseException(...)` gives callers no specific
  type to match on), `python:raise-without-from-in-except` (a new
  exception raised inside an `except` block with no `from` clause —
  detected via `raise_statement` child count: 0 children is a bare
  re-raise, 1 is a new exception with no `from`, 2 is `from`-chained, so
  only the 1-child case is flagged), and `python:unused-loop-variable`
  (a single-name `for` target never referenced in the body; tuple targets
  are left alone to keep it false-positive-free). 28 rules total in
  `rulesets/python`, 90 unit tests. First installment of the rule-catalog
  scale-out below — the language roster is complete, but per-language rule
  depth (lever 0, informally: hand-written idiom rules, the cheapest lever
  when a language has real idioms and none are covered yet) had been
  sitting at zero for every non-Rust language. Same batch process handed
  off as a standalone prompt for TypeScript in a follow-up session —
  new-language batches are additive edits to the same handful of wiring
  files (root `Cargo.toml`, the three `bin/*/Cargo.toml`s, the
  `.chain(...)` composition-root lists, `builtin.rs`), so they don't
  collide with a Python batch running in parallel.
  sitting at zero for every non-Rust language.
- **Language-specific ruleset: TypeScript/JavaScript** ✅ **(this session)** —
  a new `rulesets/typescript` crate (`yunq-rules-typescript`), same shape as
  `rulesets/rust`/`rulesets/python`: vanilla TS/JS idioms and DOM/browser
  anti-patterns, as opposed to JSX/React (`rulesets/react`, already 10
  rules) or the generic OWASP checks already covering TypeScript
  (`owasp:xss`, `owasp:eval-usage`, `owasp:injection`,
  `owasp:disabled-cert-validation`, ...). 12 rules, each grounded in the
  real tree-sitter-typescript grammar shapes (verified with a throwaway
  AST-dump example before writing detection logic, then discarded) rather
  than guessed: `typescript:loose-equality` (`==`/`!=`, recovering the
  dropped operator token from the source gap between operands, the same
  technique `smells:cognitive-complexity` uses for `&&`/`||`),
  `typescript:var-declaration` (`var`'s own grammar node,
  `variable_declaration`, distinct from `let`/`const`'s
  `lexical_declaration`), `typescript:leftover-debug-statement`
  (`console.log`/`console.debug` and `debugger`, test paths exempted via
  `is_test_only_path`), `typescript:promise-then-without-catch` (a bare
  `.then(cb)` statement — the sole child of its `expression_statement` —
  with no `.catch`, second rejection handler, `await`, or `return`),
  `typescript:math-random-for-token` (`Math.random()` feeding a
  token/password/secret/session-id-named declaration or assignment),
  `typescript:dynamic-regexp-source` (`RegExp(...)`/`new RegExp(...)` built
  from a non-literal source), `typescript:redos-nested-quantifier` (a
  hand-rolled scan over the opaque `regex_pattern` leaf tree-sitter hands
  back, catching the classic `(a+)+`/`(.*)*` catastrophic-backtracking
  shape), `typescript:json-parse-unguarded` (`JSON.parse` of a non-literal
  value with no enclosing `try`, via a small ancestor-tracking recursive
  descent), `typescript:open-redirect-location-assignment`
  (`window.location`/`document.location`/`location` assigned a non-literal
  value, matched against a finite exact-text target list so an unrelated
  `job.location` field is never mistaken for navigation),
  `typescript:sensitive-data-in-web-storage`
  (`localStorage`/`sessionStorage.setItem` with a token/password/secret-
  named key), `typescript:mass-assignment-from-request-body`
  (`Object.assign`/object-spread merging `req.body`/`req.query`/`req.params`
  with no allowlist — mass assignment / prototype pollution), and
  `typescript:innerhtml-assignment` (`.innerHTML =` outside JSX — the
  vanilla-DOM counterpart to `react:dangerously-set-inner-html`, which
  `owasp:xss`'s sink list doesn't cover). All 12 carry both classic
  `IssueType` and MQR impacts, ship with unit tests per rule (58 total), are
  wired into all three composition roots (`bin/cli`, `bin/server`'s rule
  catalog, `bin/worker`), and are activated by default in
  `typescript_activations()` (`core/profiles/src/builtin.rs`) with
  severities cross-checked against each rule's `default_severity()`.

### Rule-coverage levers, ranked by rules-per-LOC

Hand-writing one `Rule` impl per check does not scale to a catalog of
thousands. Four levers change the ratio; they are listed in the order
their return arrives, not their ambition.

1. **External report import** — ✅ **done** (SARIF, above). The only lever
   with immediate return and no engine change.
2. **Declarative rules — rules as data, not code.** The structural lever:
   a Semgrep-style pattern model (AST patterns with metavariables and
   unification) turns a rule into ~10 lines of YAML instead of a crate, so
   a ~3–5k-LOC engine plausibly enables on the order of a thousand
   syntactic rules. This is the one that changes the slope of the curve.
   **Design constraint found while landing the SARIF importer:** tree-sitter
   types never escape the `parsers/treesitter-*` crates — every parser
   converts to the neutral `AstNode` and drops the tree (`convert()` in each
   crate; `AstParser::parse` returns `AstNode`). So "just reuse tree-sitter's
   S-expression query language" is not free here: it needs a *new* port
   exposing queries (or the tree) alongside `AstParser`, which is a real
   architectural decision, not a detail. The alternative — a pattern engine
   over the neutral AST — keeps the current encapsulation and works across
   all 23 grammars uniformly, at the cost of expressing patterns in yunq's
   own vocabulary rather than each grammar's. Prototype both far enough to
   count *real rules produced per unit of effort* before committing.
   Datalog-style fact extraction (Doop/Soufflé, CodeQL's QL) is the other
   shape of "rules as data", and is the stronger one for whole-program
   rules.
3. **Deepen the semantic model.** Whole families of rules are impossible
   today, not merely pending: anything needing types. `core/symbols` exists
   (same-file scope, declared-type extraction, `ClassRegistry`); extending
   it to a cross-file symbol table plus lightweight type inference unblocks
   hundreds of rules at once. One investment, many rules.
4. **Symbolic execution over the CFG.** The category is well-proven
   elsewhere: one engine yields null-deref, resource leaks,
   always-true conditions, division by zero — dozens of high-value rules
   from a single piece. Reading: Cousot (abstract interpretation), Calcagno
   & Distefano (Infer, separation logic).

Also relevant to lever 3/4: IFDS/IDE (Reps, Horwitz & Sagiv 1995, *Precise
interprocedural dataflow analysis via graph reachability*) — `core/taint/
cross.rs` already implements an ad-hoc version of function summaries; IFDS
is the framework that generalizes it and makes it context-sensitive.

**Sourcing, and what is off-limits.** The catalogs are free and are the
right source for *what* to detect: CWE (MITRE), OWASP Top 10 and ASVS, CERT
Coding Standards. Analyzer repositories under source-available (non-open)
licenses are off-limits: those licenses typically forbid building
substantially similar functionality and forbid AI ingestion of the code, so
they are not a source for this work at all. Genuinely open catalogs (ESLint,
Clippy, Semgrep rules) each still need their license checked per project
before being leaned on; that verification has not been done.

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
  built-in "yunq way" equivalent (`core/profiles/src/builtin.rs`) — curated
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
- **Ratings & debt**: ✅ maintainability rating from a debt-ratio grid —
  `Rating::from_debt_ratio` in `core/profiles` uses the real
  remediation-effort ÷ development-cost ratio (30 min/LOC, grid
  `0.05/0.1/0.2/0.5`), not a worst-severity shortcut. ✅ Reliability and
  Security ratings wired to real analysis: `Metrics::record_issue_type_and_effort`
  (`core/rules-engine`) folds each issue's classic type + severity into a
  running worst-`Rating::from_severity` per type as issues are produced
  (`AnalyzerService::analyze_files`, both the per-file and cross-file rule
  paths), exposed as `AnalysisReport::reliability_rating`/`security_rating`
  and as `reliability_rating`/`security_rating`/`maintainability_rating`
  measures (numerically encoded `1.0`–`5.0`) usable in quality gate
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
  Measures + measure history, component tree, and a `sources` endpoint:
  `analysis_measures`/`analysis_file_coverage_lines` (migration `0017`)
  persist a real per-analysis measure set (project- and file-level) and
  per-line coverage hit counts — there was no historical measure storage at
  all before this, only a couple of summary columns on `analyses`. `GET
  /api/projects/{key}/measures/history` exposes it; `GET
  /api/projects/{key}/sources` returns per-line issue + coverage
  annotations, and (via migration `0021`/`analysis_file_blame_lines`, the
  CLI's `--blame-output` + `POST /api/projects/{key}/blame`) per-line SCM
  blame — author, commit, timestamp, summary. Source text itself is never
  persisted anywhere and stays out of scope (a materially bigger storage
  decision than this endpoint). ✅ **(this session, issue #26)** `GET
  /api/projects/{key}/components/tree` closes its own last gap: it now
  returns both the original flat, sortable/filterable `components` list
  *and* a nested `tree` field — the same filtered file set grouped into
  directories by splitting each path on `/`, built purely in the DTO layer
  (`bin/server/src/measures.rs::build_tree`; the underlying
  `analysis_measures` storage stays a flat per-file table, no schema change
  needed) since directory nesting has no server-side meaning beyond
  presentation. Nodes use the conventional DIR/FIL qualifier vocabulary.
  `tree` is always name-sorted (a `BTreeMap` per level) since `sort`/
  `direction` describe a flat ordering that stops making sense once nodes
  are grouped by parent — `components` remains the place to ask for e.g.
  "worst coverage first". Regression-tested (nested multi-file dirs,
  root-level files, empty input). Hit and fixed a real utoipa pitfall along
  the way: the new `ComponentTreeNodeDto` is self-referential
  (`children: Vec<ComponentTreeNodeDto>`), and utoipa's OpenAPI schema
  derive recurses into itself with no cycle guard by default — `cargo run
  -p yunq-server -- openapi` (the same command `api/openapi.json`'s
  contract export uses) stack-overflowed until `#[schema(no_recursion)]` was
  added to the `children` field, utoipa's documented fix for exactly this
  shape. Contract regenerated and committed. `cargo test --workspace` and
  `cargo clippy --workspace --all-targets -- -D warnings` (both minus
  `yunq-frontend`) stay green.
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
- **IDE integration**: `yunq-lsp` — an LSP server over the same core, with
  connected mode syncing the server's profile and issue suppressions.
  In-editor analysis in any LSP-capable editor, with no per-IDE plugin to
  build or maintain.

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
- **6c Agentic guardrail — yunq inside the agent's edit loop** ✅
  **(2026-07-27)**. Every entry point before this one is post-hoc: the CLI,
  the server and the GitHub Action all answer "what is wrong with this code?"
  after it exists. `yunq hook` answers "may this write happen?" *before* the
  bytes reach disk — the window between an agent deciding to edit a file and
  the edit landing, which is the only moment where a finding costs the agent
  one retry instead of costing a reviewer a pull request. Two pieces:

  **`core/agent-policy`** (`yunq-agent-policy`, new pure crate — deps are
  `yunq-profiles`, `globset`, `serde`, `toml`, `thiserror`; deliberately
  *not* `yunq-rules-engine`, so it can equally judge a SARIF-imported or
  future remote finding without learning the engine's whole domain, at the
  cost of the caller mapping `Issue` → `Finding`). Parses `yunq-policy.toml`
  into an `AgentPolicy` and evaluates `(path, findings)` → `Evaluation`.
  This is explicitly **not** the quality gate, and the two disagree on
  purpose: the gate asks "is this project releasable?" over a whole
  analysis, the policy asks "may this one write land?" over a single
  proposed edit. Three ways to deny, in precedence order — `advisory_rules`
  (report but never deny, the escape hatch for a rule that is noisy in this
  repository, outranking both paths below), `blocking_rules` (deny whatever
  severity the active profile gives them — the list is what makes an *agent*
  policy different from a severity threshold: an agent writing a shell sink
  is categorically riskier than a human doing it under review), and
  `block_at_or_above` (default `critical`). Plus `protected_path` globs that
  deny on path alone with no finding at all. Design decisions worth keeping:
  every serde default mirrors `Default::default()`, so an empty `[agent]`
  table and a missing file describe the same policy and a present key is
  always an override rather than a reset; `deny_unknown_fields` makes a typo
  in a security policy a startup error instead of a control that silently
  does nothing (verified — a stray `block_at_or_abov` exits 1 naming the
  field); `AgentPolicy::default()` ships with **no** protected paths, since
  an invisible default that refuses an agent's legitimate edit on install
  gets the whole tool uninstalled, while `yunq hook install`'s *generated*
  file turns them on with concrete entries — visible and editable in the
  user's own repository, which is where an opinionated choice belongs.

  **`bin/cli/src/hook.rs` + `hook_install.rs`** — the host adapters, behind
  `yunq hook {claude-code,check,install}`. The two Claude Code hook points
  are asymmetric and the asymmetry drives the whole design: `PreToolUse`
  fires before the tool runs and *can* deny it
  (`hookSpecificOutput.permissionDecision: "deny"`), while `PostToolUse`
  fires after the write already landed and can only feed text back into the
  model's context. So **`PreToolUse` prevents, `PostToolUse` teaches**, and
  the agent-facing wording differs accordingly — an initial version reused
  one message for both and told the model "blocked, the file was NOT
  written" about a file already on disk, which invites it to move on leaving
  the finding in the tree; now a `Timing` parameter splits the two and a test
  pins it. Because `PreToolUse` judges a file that does not exist yet,
  `proposed_content` reconstructs the pending content from the tool call's
  own arguments: `Write` carries the whole body; `Edit` carries a
  search/replace pair, so the current file is read and the replacement
  applied *exactly* as the host will apply it, honouring `replace_all` (which
  otherwise silently diverges on a repeated string); anything else returns
  `None` rather than guessing, leaving the path half of the policy to apply
  alone. One deliberate non-feature: the non-denied `PreToolUse` path emits
  **nothing**, never `permissionDecision: "allow"` — the only way to attach a
  pre-write advisory is alongside an `allow`, which would override the user's
  own permission settings and auto-approve every edit yunq happens not to
  object to, turning a security tool into a permission bypass (regression
  test: `pre_tool_use_never_emits_allow_for_an_advisory`). Errors **fail
  open** — a malformed payload, unreadable file or unparseable policy lets
  the write proceed and reports on stderr, because a guardrail that wedges
  the agent loop on its own bug is removed within a day and a removed
  guardrail blocks nothing; `hook check` is the deliberate exception, exiting
  1 (yunq broke) vs 2 (policy denied) so non-interactive callers can choose.
  `hook install` merges into `.claude/settings.json` additively and
  idempotently — unrelated keys survive, other events' hooks survive, and a
  matcher the user narrowed by hand is not silently re-widened on reinstall;
  a settings file that exists but does not parse is refused rather than
  overwritten.

  **Positioning.** This is the concrete answer to "why yunq rather than
  Semgrep/CodeQL/SonarQube" in an agent-written codebase: those are all
  invoked on a diff that already exists. The distinction that matters is
  *invoked* vs *consulted* — an MCP server or an LSP is consulted, and an
  agent optimising for task completion learns not to ask; a host hook is run
  by the runtime on every matching tool call and cannot be routed around.
  Verified end to end against real Claude Code payload shapes (not only unit
  tests): a `Write` of `subprocess.run(target, shell=True)` is denied with
  the rule id and line in the reason; an `Edit` that introduces `shell=True`
  into a clean file is denied with the file still untouched on disk; a
  `.github/workflows/**` write is denied with no finding at all; clean
  content emits nothing. **Measured cost: ~7ms p50 / 7.6ms p95 per write**
  (20 cold-start release-binary invocations, process startup included) —
  comfortably inside the agent's edit loop, and far under the 30s hook
  timeout the installer sets. Still open: Codex CLI's tool hooks fire for
  shell commands only, not file writes, so an edit-time guardrail cannot be
  installed there today and `yunq hook check` is the portable path (also the
  `pre-commit`/CI path); the analysis is single-file, so cross-file taint and
  the OOP/architecture cross-file rules do not participate in a pre-write
  verdict; and there is no MCP server yet — worth adding as a *planning-time*
  complement (an agent querying the policy before writing) rather than a
  replacement for the hook, precisely because it would be consulted rather
  than invoked.

  **6d Structured, machine-readable denials** ✅ **(2026-07-27)**. Prose
  denial text is written for a model to read and act on, but a caller that
  wants to parse a verdict deterministically (rule id, line, the exact
  condition that must clear) previously had to pattern-match it.
  `bin/cli/src/hook.rs::structured_report` builds that as a DTO the same way
  `bin/cli/src/output.rs::ReportDto` does for `scan --format json` — an
  edge-owned translation of `agent-policy`'s `Violation`/`Cause` into JSON,
  never a `Serialize` derive on the domain types themselves (`core/agent-policy`
  stays as serde-free as `core/rules-engine`). It is embedded as a fenced
  block appended to the existing `denial_text`/`claude_code_output` prose
  (additive — the Claude Code hook's JSON *shape* is unchanged, since altering
  a host contract we cannot test live against the real runtime is riskier
  than embedding structure inside the string field the host already reads),
  and it is also the sole payload of the new `hook check --format json`,
  which speaks nothing but that JSON on stdout for tooling that never wants
  prose. This is the "Category 12" feedback loop closed: the guardrail's
  output is now something an agent (or a second script) can act on without
  an LLM re-reading English.

  **6e Circuit breaker** ✅ **(2026-07-27)**. An agent stuck relitigating a
  false positive, or a vulnerability it cannot resolve, would otherwise retry
  the identical denied write forever — the guardrail catching the mistake
  every time without the loop ever terminating. `yunq_agent_policy::
  CircuitBreakerState` (pure, in `core/agent-policy`, deps unchanged) folds
  one write's `Evaluation` into a per-`RuleId` consecutive-denial count and
  reports which rules just reached `TRIP_THRESHOLD = 3`; a rule not denied
  in a given round resets to zero rather than pausing, since "consecutive"
  means uninterrupted, whether the interruption was a fix or the agent
  moving on to something else. `ProtectedPath` denials never participate —
  there is no rule behind them for a retry to fix. Persistence between the
  separate process invocations a hook loop makes (each `yunq hook` call is a
  fresh process) is `bin/cli`'s concern, not the pure crate's:
  `.yunq-circuit-breaker.json` at the repository root (gitignored), loaded
  and saved fail-open (a corrupt or missing state file only forgets a streak,
  never bypasses the policy). On the third consecutive denial, both
  `denial_text` and `hook check --format json` change from "rewrite and try
  again" to an explicit stop-and-rollback instruction naming the human
  intervention step; `yunq hook reset-circuit-breaker` deletes the persisted
  state once a human has reviewed the stuck finding. This is the literal
  "stopping condition" a fully autonomous edit loop needs to avoid burning an
  unbounded token budget against the same wall.

  **On MCP.** The "invoked vs consulted" distinction above is the answer to
  a live question, not a historical one: whether yunq should additionally
  ship an MCP server as a way for an agent to query its policy. The answer
  stays no for anything that has to *stop* a write — an MCP tool is opt-in
  from the agent's side, and a model optimising for task completion learns
  not to call a tool that might refuse it, which is exactly the failure mode
  a guardrail exists to prevent. The one place MCP earns its keep is
  strictly upstream of that: a read-only resource (e.g. `yunq://rules/current`)
  an agent's system prompt ingests once, before planning a single edit — the
  active policy and the architecture blueprint, so the agent starts from
  "this repo blocks `eval`, don't reach for it" rather than discovering the
  same fact by being denied. That is real value (fewer wasted PreToolUse
  round-trips), but it is planning-time context, not enforcement, and it does
  not exist yet — the hook remains the only mechanism that can actually deny
  a write.

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

## Enterprise feature checklist

The capabilities usually reserved for a paid enterprise tier, mapped — and
everything ships open in yunq, not behind an edition wall:

| Enterprise-tier capability | yunq phase |
|---|---|
| Branch/PR analysis, taint analysis, ALM decoration | Phases 2–5 |
| AI coded fix suggestions at the click of a button | Phase 6a/6b (Remediation Agent, "Assign to Agent") |
| Executive views: projects, applications, portfolios | Phase 7 (portfolios + executive dashboards) |
| Govern standards across teams on different DevOps platforms | Phase 3 (gates/profiles) + Phase 5 (`AlmGateway`) + Phase 7 |
| Security, regulatory, and audit compliance reports | Phase 7 (OWASP/CWE/PCI reports, audit trail) |
| Improved performance for large teams, parallel analysis | Performance pillar (measured ~398k LOC/s) + worker fleet |
| Enterprise-grade IAM | Phase 4 (tokens, OAuth, permissions) → Phase 7 (SAML/OIDC, SCIM, LDAP) |
| ~80% more issue types, +6 languages, private-service secrets | Phase 2 (open language roster, rule catalog, multi-provider secrets incl. self-hosted/private services) |

## Algorithm notes

Records the load-bearing algorithm choices — where a naive implementation
would look right on the happy path and be wrong in practice, and what yunq
does instead.

| Algorithm | Implementation |
|---|---|
| Duplication detection (CPD) | Statement-repetition collapsing, Rabin-Karp rolling hash (base 31, block size 5), cross-file hash index (`core/duplication`). Previously a raw per-line sliding-window hash with no repetition collapsing or shared index — fixed. |
| Maintainability rating (A–E) | Rating from the technical debt ratio (remediation effort ÷ (LOC × 30 min)) against grid `[0.05, 0.1, 0.2, 0.5]` (`core/profiles::Rating::from_debt_ratio`). Previously derived from the worst issue severity present, which conflates cost with severity — fixed. |
| Cognitive complexity | Nesting-weight formula (`1 + current nesting` for `if`/loops/`switch`/ternary/`catch`); flat `+1` for `else`/`else if` with no extra nesting; an else-if chain does not compound nesting per link; a `switch` costs the same regardless of case count; flat `+1` for a *labeled* `break`/`continue` only; boolean-operator sequences cost `+1` on the first operator and again only when the operator changes, with parentheses transparent. **Recursion**: direct self-recursion costs a flat `+1` (not nesting-weighted — recursion is a "meta-loop", charged like a labeled jump) for a call inside a `FunctionDef` whose callee resolves to that function's own name, covering plain `foo()` and method-style `self.foo()`/`this.foo()` (`fn_name`/`is_recursive_call`, `rulesets/code-smells/src/cognitive_complexity.rs`). Indirect/mutual recursion is out of scope: it needs a whole-file call graph this same-file rule intentionally doesn't build, and a cross-function heuristic would silently under- or over-fire across 18 wired grammars. **Nested functions/lambdas**: yunq isolates every `NodeKind::FunctionDef` (closures included) as its own independently-scored unit, rather than folding a lambda body into the enclosing function's score. A deliberate choice — isolation is what makes the per-function threshold mean the same thing in every language. |
| New Code / issue tracking across analyses | Content-hash-first cascade: `core/rules-engine/src/new_code.rs::Baseline` hashes the real source line at each issue's span (whitespace-normalized) and matches on (rule, file, line-hash) — immune to a message drifting on trivial edits (e.g. "cognitive complexity 7" → "8") and tolerant of the line moving elsewhere in the file — falling back to a (rule, file, message) fingerprint only when no source text is available (legacy baseline files, or a caller with no filesystem access). `bin/cli::FileLineHashes` plumbs real file content in; `infra/fs::BaselineStore` persists per-issue hashes with fail-open migration for baseline files written by older yunq versions. Previously a bare (rule, file, message) fingerprint with no source access at all — fixed and verified live via the CLI (same line, message-only drift → `new_issue_total` stays 0). |
| Quality gate evaluation | Named conditions over metrics, fail-if-any-breached, fail-open on a missing measure. |
| Reliability/Security ratings + remediation effort by rule/component | A *different* algorithm from Maintainability, not the same grid twice: `Rating::from_severity` maps severity directly (`BLOCKER→E, CRITICAL→D, MAJOR→C, MINOR→B, INFO→A`), and `reliability_and_security_ratings` (`core/profiles::rating`) takes the worst rating within each issue type independently — Bug issues drive Reliability, Vulnerability issues drive Security, code smells touch neither — instead of one shared debt-ratio grid or a single worst-severity-across-everything number. `aggregate_remediation_effort` sums minutes by rule and by component/file for drill-down reporting. Tests pin the exact severity table and the cases a naive "one grid for everything" implementation gets wrong (a Blocker code smell must not move Reliability/Security; a Blocker bug must not move Security). ✅ **Wired to real analysis**: every `Rule`/`CrossFileRule` declares a real `issue_type` (`953ff6d`), so `AnalyzerService::analyze_files` folds each produced issue's type + severity into `Metrics` via `record_issue_type_and_effort`, exposed as `AnalysisReport::reliability_rating`/`security_rating`/`remediation_effort` and as gate-condition-ready measures — no longer isolated to `core/profiles` unit tests. |


## Sequencing

Phases 2 and 3 are startable now and parallel; Phase 4 follows 3 closely so
the frontend swaps mocks for real endpoints incrementally. Performance pillar
work starts immediately (interning + rayon are Phase-2 groundwork). Phase 6a
prototypes as soon as 2/3 stabilize the issue model; 6b needs 4 + 5. Phase 7
last — nothing in it blocks product value earlier.
