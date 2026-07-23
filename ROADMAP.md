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
  a dead-code pass); this covers its syntactic subset; the same-scope
  tracking used here (`own_scope_descendants` in
  `rulesets/react/src/common.rs`) is still not full symbol resolution, so
  `exhaustive-deps`-style checks (does the effect body reference
  something outside its dependency array?) and unused-state/dead-code
  detection remain out of reach and open. Still open otherwise: OOP
  smells, architecture/dependency cycles, and reactive-stream smells all
  need the same symbol/type resolution the AST doesn't do yet.
- **Issue types & classification**: bug / vulnerability / code smell, plus
  MQR-style software-quality impacts (reliability, security,
  maintainability × severity) — support both classification modes like
  modern SonarQube.
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
- **Cross-file taint analysis**: ✅ inter-procedural summaries and
  project-wide function resolution ported (`core/taint/src/cross.rs`) —
  parameter→sink and parameter→return-value summaries iterated to a global
  fixpoint, so `caller → helper → runner → sink` chains resolve across file
  boundaries; name resolution is a project-wide-by-name heuristic rather
  than a real import/export edge graph, a deliberate zero-config tradeoff.
  ⚠️ Still open: **sanitizer modeling** — no concept yet of a function that
  strips taint from a value, so any call reaching a summarized sink-bound
  parameter is flagged regardless of intervening sanitization. SonarQube
  sells the category commercially; yunq ships it open.

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
- **Quality Profiles**: per-language activation sets with severity
  overrides (core type exists), inheritance chains, built-in "Sonar way"
  equivalent, compare/copy/backup-restore.
- **Ratings & debt**: ✅ maintainability rating ported from SonarQube's SQALE
  model (`DebtRatingGrid` + `MaintainabilityMeasuresVisitor`) —
  `Rating::from_debt_ratio` in `core/profiles` uses the real
  remediation-effort ÷ development-cost ratio (30 min/LOC, grid
  `0.05/0.1/0.2/0.5`), not a worst-severity shortcut. Reliability and
  security ratings (per-issue-type debt) and remediation effort aggregation
  by rule/component are still open.
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
- **Ops**: ✅ system info endpoint (`ops::system_info`) and audit log
  persistence + endpoint (`ops::list_audit_log`, `infra/postgres/src/{audit,system}.rs`,
  migrations 0011–0013), on top of the existing `/health` and Prometheus metrics.

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
| Reliability/Security ratings + remediation effort by rule/component | `server/sonar-server-common/.../Rating.java`, `.../ReliabilityAndSecurityRatingMeasuresVisitor.java` (fetched from `SonarSource/sonarqube` on GitHub; no local vendored clone) | ✅ Ported the actual (different-from-Maintainability) algorithm: `Rating::from_severity` mirrors `RATING_BY_SEVERITY` exactly (`BLOCKER→E, CRITICAL→D, MAJOR→C, MINOR→B, INFO→A`), and `reliability_and_security_ratings` (`core/profiles::rating`) takes the worst rating within each issue type independently — Bug issues drive Reliability, Vulnerability issues drive Security, Code smells and the other type never touch either — instead of one shared debt-ratio grid or a single worst-severity-across-everything number. `aggregate_remediation_effort` sums minutes by rule and by component/file for drill-down reporting. Tests pin the exact severity table and a case a naive "one grid for everything" implementation would get wrong (a Blocker code smell must not move Reliability/Security; a Blocker bug must not move Security). **Not wired to real analysis yet**: `RuleMetadata` (`core/rules-engine`) has no `issue_type` field, and the rule catalog has zero rules classified as `Bug` today (only code smells and OWASP/secrets vulnerabilities) — wiring now would be speculative plumbing with no observable effect until `specs/rule-catalog-gap-closure` adds real bug-detecting rules; deferred with the algorithm itself already verified and tested in isolation. |

## Sequencing

Phases 2 and 3 are startable now and parallel; Phase 4 follows 3 closely so
the frontend swaps mocks for real endpoints incrementally. Performance pillar
work starts immediately (interning + rayon are Phase-2 groundwork). Phase 6a
prototypes as soon as 2/3 stabilize the issue model; 6b needs 4 + 5. Phase 7
last — nothing in it blocks product value earlier.
