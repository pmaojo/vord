# Roadmap

## 1. More Powerful and Extensive Test Fixtures
Currently, our fixtures are minimal. We need to expand them to cover significantly more edge cases, deeper architectural structures, and real-world scale codebases to ensure both accuracy and performance at scale.

### 1.1 Python
- Evaluate and select complex, popular Python open-source repositories to serve as comprehensive fixtures.
- Test deep inheritance, complex metaclassing, dynamic attribute access, and multi-file taint paths.
- Repositories to investigate:
  - `django`
  - `flask`
  - `requests`
  - `fastapi`

### 1.2 Rust
- Incorporate open-source Rust repositories to test our capabilities with memory safety paradigms, lifetimes, traits, and generics.
- Focus on heavy macro usage, complex module structures, and `unsafe` blocks.
- Repositories to investigate:
  - `ripgrep`
  - `tokio`
  - `actix-web`

### 1.3 TypeScript
- Add fixtures for complex TypeScript codebases to stress our SOLID, DDD, and Hexagonal layer validations.
- Focus on large multi-package workspaces, complex conditional types, and intricate import graphs.
- Repositories to investigate:
  - `nestjs`
  - `vscode`
  - `prisma`

### 1.4 General Enhancements
- Expand fixtures to also cover negative test cases (e.g. malformed code).
- Ensure fixtures include edge cases for all of our security and architectural checks across supported languages.