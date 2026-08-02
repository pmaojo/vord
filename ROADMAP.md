# Roadmap

## Extensive Fixtures

The core priority for the upcoming releases is to greatly expand the test fixtures used by `vord`. The internal 5-file fixture is no longer sufficient for empirically validating precision or testing performance regressions at scale.

We need real-world codebases to measure our rule engine's effectiveness, accuracy, and parsing speed.

### Planned Fixture Repositories

We will adopt open-source repositories to act as powerful and extensive test fixtures. These repositories have been selected based on their size, complexity, and idiomatic use of their respective languages.

#### Python
- **Django / Flask**: Large, widely-used web frameworks that heavily rely on metaprogramming, complex inheritance, and deep module trees. Excellent for testing DDD/SOLID metrics and taint tracking.
- **python-mini-projects**: A diverse collection of small to medium scripts and tools, ideal for testing various coding styles, structural complexity, and typical code smells.
- **TensorFlow (Python bindings)**: Extremely large codebase, great for stressing parser performance and handling C-extensions or complex type hints.

#### Rust
- **Goose**: An open-source AI agent project that is built in Rust. It offers a modern, real-world Rust codebase to test our architecture boundaries, borrow-checker semantics, and trait implementations.
- **Cargo / Ripgrep**: Established, idiomatic Rust codebases. They provide excellent stress testing for our module resolution and macro handling capabilities.

#### TypeScript / JavaScript
- **VSCode**: An incredibly large and complex TypeScript project. It will be the ultimate stress test for our `class-fan-out`, component metrics, and dependency cycle rules.
- **React**: A fundamental library with functional and class-based patterns, essential for ensuring our rules appropriately handle JSX/TSX and functional components.
- **N8N / Dify**: Workflow automation and AI agent platforms built in TypeScript, offering modern, real-world complexity to evaluate architectural and DDD rules.

### Implementation Plan
1. Submodule or download specific tagged releases of these repositories into a dedicated `corpora/` or `fixtures/extended/` directory (ignored by git, but fetched by CI).
2. Wire up `scripts/benchmark-corpora.sh` to run our engine against these repositories.
3. Establish baseline metrics (LOC/s, memory usage, false positive rates) for each repository.
4. Integrate the execution into our CI pipeline for performance regression testing.
