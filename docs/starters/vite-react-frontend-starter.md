# The `vite-react-frontend-starter` profile

A curated, blocking Vord profile for Vite+React projects that follow the
bulletproof-react layered convention:

```
src/
  components/                    presentational — renders, does not fetch
  features/<feature>/
    api/                         data-fetching hooks (React Query)
    hooks/                       UI-state hooks only, no server data
    components/                  feature-scoped presentational components
  infra/                         the one place allowed to build a transport client
```

```
vord scan . --profile vite-react-frontend-starter --enforce-gate
```

`--profile` and the rules it activates are new — see "Rolling this out"
below for the one thing to check before you turn `--enforce-gate` on.

## Why a dedicated ruleset instead of extending `rulesets/react`

`rulesets/react` is Vord's generic React-the-framework ruleset (hooks
rules, JSX rules) — it applies to any React codebase, bulletproof-react-shaped
or not. This profile's own rules (`rulesets/vite-react`) encode one specific
starter's *directory convention* instead — the same reason
`rulesets/architecture` (hexagonal boundaries) is a crate of its own rather
than folded into a language ruleset. The profile composes
`vite-react::all_rules()` with a curated subset of `rulesets/react`,
`rulesets/secrets`, `rulesets/owasp` and `rulesets/typescript` — see
`core/profiles/src/starters.rs` for the exact activation list.

## What's blocked

| Rule | Severity | What it checks | Example |
|---|---|---|---|
| `vite-react:no-data-layer-import-in-view` | Blocker | Import graph, per-file | `src/components/**` or `src/features/**/components/**` importing `@tanstack/react-query`/`zustand`/`react-router-dom`, or a `src/infra/**` module directly |
| `vite-react:no-transport-call-in-view` | Blocker | AST call-expression, per-file | a raw `fetch(...)`/`axios.<verb>(...)` call inside `components/**` or `features/**/hooks/**` |
| `vite-react:transport-client-outside-infra` | Blocker | AST call-expression, per-file | `axios.create(...)` or `new Axios(...)` anywhere outside `src/infra/**` |

## What's warned

| Rule | Severity | What it checks | Example |
|---|---|---|---|
| `vite-react:data-hook-outside-api-dir` | Major | AST call/import, per-file | a `useQuery`/`useMutation`/`useInfiniteQuery` call, or a React Query import, inside `features/**/hooks/**` instead of `features/**/api/**` |
| `vite-react:hardcoded-base-url` | Major | AST binding, per-file | a `baseURL`/`endpoint`/`url`-named binding holding a hardcoded `http(s)://` literal outside `src/infra/**` and config files |
| `vite-react:tailwind-space-between` | Minor | JSX attribute, per-file | `space-x-*`/`space-y-*` in a `className`/`class` — Tailwind deprecated `space-between` utilities in favor of `gap-*` |

Reused as-is from the rest of the platform (no new code, same severities the
"vord way" profile already gives them where applicable):
`react:bulletproof-folder-structure`, `react:feature-directory-isolation`,
`react:no-fetch-in-useeffect`, `react:rules-of-hooks-naming`,
`react:rules-of-hooks-conditional`, `react:exhaustive-deps`,
`react:unsafe-target-blank`, `react:jsx-img-missing-alt`,
`react:missing-list-key`, `react:no-async-client-component`, all of
`secrets:*`, plus a generic OWASP/TypeScript baseline (XSS, eval, SSRF,
injection, loose equality, unguarded `JSON.parse`, `innerHTML` assignment,
swallowed exceptions, …).

## What Vord cannot detect natively (and why)

These were explicitly scoped out rather than implemented as brittle
heuristics — each belongs to a tool that already does it well:

| Convention | Why not a Vord rule | Use instead |
|---|---|---|
| Storybook co-location (`Component.stories.tsx` next to `Component.tsx`) | A filesystem presence check, not a code-shape check — no false-positive risk to manage, but also no code semantics for Vord's AST-based engine to add | A `find`/`test -f` check in CI, or `eslint-plugin-storybook`'s own rules |
| GitHub Actions SHA pinning (`uses: actions/checkout@<sha>` not `@v4`) | YAML supply-chain policy, orthogonal to source-code analysis | [`zizmor`](https://github.com/woodruffw/zizmor) or GitHub's own dependency review, imported via `--sarif` like any other tool |
| Folder-per-unit structure enforcement (every component gets its own directory) | A repo-wide layout convention with many legitimate exceptions (single-file components, barrel files) — a rigid check here would be a constant source of overrides, not a real signal | `eslint-plugin-boundaries` or a small repo-local script owning your team's exact convention |
| i18n hardcoded-text detection (a JSX text node that should be a translation key) | Extremely high false-positive rate without a real i18n-string inventory to check against (labels, punctuation, code samples in docs all look like "hardcoded text" to a naive check) | `eslint-plugin-i18next`/`i18n-tasks`, which have access to the actual translation catalog |
| "validate all responses with Zod" | Requires understanding a project's actual schema definitions and which functions are "the boundary," not just AST shape — a generic version would either miss most real boundaries or flag internal helper functions constantly | A repo-local ESLint rule, or a design-time review checklist |

## Pre-push and CI

```bash
vord scan . --profile vite-react-frontend-starter --enforce-gate \
  && pnpm typecheck \
  && pnpm lint \
  && pnpm test \
  && pnpm storybook:build \
  && npx stylelint "src/**/*.css"
```

`vord scan --enforce-gate` exits with status 3 on a blocker/critical finding
or a parse failure (see [Rolling this out](#rolling-this-out) for the
in-between-severity note) — chain it first so a native finding fails fast,
before the slower `pnpm` steps run at all. The gate for this profile
(`vord_cli::vite_react_gate`) is the same blocker/critical/parse-failure
gate every profile uses, minus the `coverage`/`mutation_score` conditions:
Vord doesn't measure JS test coverage or run mutants — that's `pnpm test`'s
job (and Stryker's, if you run mutation testing), not this gate's.

## Importing ESLint/Stylelint findings via SARIF

Vord's `--sarif <path>` flag (repeatable) merges another analyzer's findings
into the same scan — they count toward the severity totals and the quality
gate exactly like a native `vite-react:*`/`react:*` finding, and are
namespaced by tool (`eslint:*`, `stylelint:*`) so you can always tell a
native finding from an imported one in the report.

ESLint, with the SARIF formatter:

```bash
npx eslint --format @microsoft/eslint-formatter-sarif \
  --output-file eslint-results.sarif src
```

Stylelint, with a SARIF formatter:

```bash
npx stylelint "src/**/*.css" \
  --custom-formatter stylelint-formatter-sarif \
  > stylelint-results.sarif
```

Then:

```bash
vord scan . --profile vite-react-frontend-starter --enforce-gate \
  --sarif eslint-results.sarif \
  --sarif stylelint-results.sarif
```

## Explicit exceptions

Every rule in `rulesets/vite-react` supports a per-rule glob exceptions
list, declared under `[vite_react.exceptions]` in `vord.toml` — the escape
hatch for a deliberate, reviewed exception (a legacy component mid-migration,
say), never an implicit one:

```toml
[vite_react.exceptions]
"vite-react:no-data-layer-import-in-view" = ["src/components/LegacyWidget/**"]
```

An unrecognized rule id in this table is ignored rather than failing the
scan (a forward-compatible posture, the same one `[[rules.custom]]` already
takes) — double-check the id against the table above if an exception
doesn't seem to take effect. A ready-to-copy starting point (this exact
table, plus `[analysis]`/`[gate]`) lives at
`rulesets/vite-react/vord.toml.template`.

## Rolling this out

`--profile` and the `vite-react-frontend-starter` name are new additions —
running `vord scan .` with no `--profile` flag is completely unaffected by
any of this (the "vord way" profile never activates a `vite-react:*` id).
`vord.toml`'s `[analysis] profile` field is recorded but not yet read by the
CLI, so `--profile vite-react-frontend-starter` must currently be passed on
the command line even if it's also set in `vord.toml`.

Before turning `--enforce-gate` on for the first time, run the scan without
it (`vord scan . --profile vite-react-frontend-starter`, no `--enforce-gate`)
and read the report: the layering rules above are blockers by design (this
starter's convention is meant to be load-bearing, not advisory), so an
established codebase migrating onto this profile should expect a real first
batch of findings and either fix them or add reviewed
`[vite_react.exceptions]` entries before wiring the gate into a pre-push
hook or required CI check.
