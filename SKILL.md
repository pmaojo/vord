---
name: yunq-static-analysis
description: Instructions for AI coding agents on how to run, configure, and enforce static analysis guardrails, project templates, and quality gates using the yunq CLI.
---

# yunq Static Analysis & Guardrail Skill for AI Agents

`yunq` is a high-performance, single-binary static analysis platform in Rust (24 languages, zero JVM/server requirements). It serves both as a code scanner (`yunq scan`) and an agentic write-gate (`yunq hook`) that judges an AI agent's edits *before* they hit disk.

---

## 🚀 Quickstart for AI Agents

### 1. Bootstrapping a New Clean Project (`yunq kickoff`)
When starting a project or feature, use `yunq kickoff` to generate versionless, AI-aligned directory structures and `yunq.toml` configurations:

```bash
yunq kickoff react-bulletproof   # Bulletproof React feature layout (src/features/<feature>/...)
yunq kickoff rust-clean          # Hexagonal Rust workspace (core/, infra/, bin/)
yunq kickoff python-clean        # Modern Python package (src/domain/, src/infrastructure/, src/api/)
yunq kickoff typescript-clean    # Clean TypeScript library layout
```

### 2. Scanning Code & Verifying Fixes (`yunq scan`)
Run analysis after making code edits to ensure zero static analysis violations or quality gate breaches:

```bash
yunq scan .                      # Analyze current repository
yunq scan . --format json        # Get structured JSON findings
yunq scan . --fail-on critical   # Exit non-zero if Critical/Blocker findings exist
yunq scan . --enforce-gate       # Exit 3 if quality gate fails
```

### 3. Agentic Pre-Write Guardrail (`yunq hook`)
Before writing or modifying a file, judge the draft payload against repository policies (`yunq-policy.toml`):

```bash
yunq hook check <filepath>       # Exit 0 (allowed), 2 (denied by policy), 1 (error)
yunq hook check <filepath> --format json
```

---

## 🎯 Key Opinionated Rules & Best Practices

AI agents operating in repositories governed by `yunq` MUST follow these standards:

### Bulletproof React & Architecture (`yunq-rules-react`, `yunq-rules-architecture`)
- **`react:bulletproof-folder-structure`**: Co-locate code inside `src/features/<feature_name>/` (containing `api/`, `components/`, `hooks/`, `routes/`, `types/`). Avoid placing loose `.tsx` files in `src/`.
- **`react:feature-directory-isolation`**: Cross-feature imports must use the public index API (`import { ... } from '@/features/auth'`). Deep internal imports across features (`@/features/auth/components/internal`) are blocked.
- **`react:no-default-export`**: Use explicit named exports (`export const MyComponent = ...`). `export default` is disallowed.
- **`react:no-fetch-in-useeffect`**: Do not invoke `fetch()` or `axios()` inside `useEffect`. Use TanStack Query/SWR or custom hooks.
- **`react:context-provider-value-memo`**: Wrap Context Provider values in `useMemo` to prevent consumer re-renders.
- **`react:no-nested-components`**: Never declare component functions inside another component's render body.

### Naming Conventions
- **React Components**: `PascalCase` filenames and function names (`UserProfile.tsx`).
- **Event Handlers**: `handle[Event]` for internal handlers (`handleClick`), `on[Event]` for callback props (`onClick`).
- **Booleans**: Must start with `is`, `has`, `should`, or `can` (`isLoading`, `hasPermission`).
- **Rust**: `PascalCase` for structs/enums/traits, `snake_case` for functions/variables/modules.
- **Python**: `CapWords` for classes, `snake_case` for functions/variables, `UPPER_SNAKE_CASE` for constants.

### Rust Practices (`yunq-rules-rust`)
- **`rust:disallow-unwrap-expect`**: Do not use `.unwrap()` or `.expect()` in non-test source files. Propagate errors via `?` or `match`/`if let`.
- **`rust:disallow-panic-macros`**: Do not use `panic!`, `todo!`, `unimplemented!`, or `unreachable!` in production code.

### Python Practices (`yunq-rules-python`)
- **`python:missing-type-annotations`**: All public functions must have explicit return type annotations (`def foo(...) -> ReturnType:`).
- **`python:modern-type-syntax`**: Use PEP 585/604 syntax (`list[str]`, `dict[K, V]`, `str | None`) instead of `typing.List`/`typing.Optional`.
- **`python:unclosed-open-file`**: Always open files using `with open(...) as f:` context managers.

### AI Guardrails (`yunq-rules-ai-agent`)
- **`ai-agent:no-dynamic-reflection`**: Disallow dynamic evaluation/reflection (`eval`, `exec`, `getattr(obj, var)`) with unchecked string inputs.
- **`ai-agent:no-wildcard-reexports`**: Disallow `export * from ...` in index files; explicitly name all re-exported symbols.

---

## ⚙️ Configuration (`yunq.toml`)

Configure rules, quality gates, and swarm pipelines in `yunq.toml`:

```toml
[profile]
name = "recommended"

[rules]
"react:bulletproof-folder-structure" = "major"
"react:feature-directory-isolation" = "major"
"rust:disallow-unwrap-expect" = "major"
"python:missing-type-annotations" = "major"
"ai-agent:no-wildcard-reexports" = "major"

[swarm]
topology = "two-pack" # planner -> coder

[[swarm.role]]
name = "coder"
worktree = ".yunq/worktrees/coder"
protected_paths = [
  { pattern = "core/domain/**", reason = "Core domain is read-only for coders" }
]
blocking_rules = ["owasp:nosql-injection", "react:feature-directory-isolation"]
```

---

## 🐝 Multi-Agent Workflows (`yunq swarm`)

Run multi-agent pipelines with role isolation and durable handoffs:

```bash
yunq swarm run --task "Implement user authentication feature"  # Drive configured topology
yunq swarm handoff-send --from planner --to coder --summary "Spec defined"
yunq swarm handoff-deliver                                     # Route outbox to recipient inboxes
yunq swarm handoff-inbox --role coder                          # Read pending handoffs
```
