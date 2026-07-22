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
- **Duplication detection (CPD)**: ✅ core algorithm ported from
  `sonar-duplications`' `BlockChunker`/`CloneIndex` — statement-repetition
  collapsing, incremental Rabin-Karp rolling hash (base 31, default block
  size 5), cross-file hash-indexed matching (`core/duplication`). Remaining
  gap vs. upstream: statements are trimmed source lines, not real
  per-language tokenizer output, so literal/whitespace normalization isn't
  token-accurate yet — swap in per-language tokenizers reusing the
  `parsers/treesitter-*` crates to close it.
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
| Cognitive complexity | not in `sonarqube/sonarqube` core (per-language plugins) | Existing `rulesets/code-smells/cognitive_complexity.rs` already implements SonarSource's published nesting-weight + boolean-operator-sequence rules; not re-verified against a primary source in this pass since the reference implementation isn't in this repo. |
| New Code / issue tracking across analyses | scanner-engine issue tracker (separate repo, not in `sonarqube/sonarqube`) | Not upstream-verified. `core/rules-engine/src/new_code.rs` uses a simpler rule+file+message fingerprint rather than Sonar's line-diff/Levenshtein tracker; open gap, not yet audited against a primary source. |
| Quality gate evaluation | Sonar's condition-set model (generic, no single algorithm file) | Structurally equivalent (named conditions over metrics, fail-if-any-breached, fail-open on missing measure) — no changes needed. |

## Sequencing

Phases 2 and 3 are startable now and parallel; Phase 4 follows 3 closely so
the frontend swaps mocks for real endpoints incrementally. Performance pillar
work starts immediately (interning + rayon are Phase-2 groundwork). Phase 6a
prototypes as soon as 2/3 stabilize the issue model; 6b needs 4 + 5. Phase 7
last — nothing in it blocks product value earlier.
