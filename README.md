# yunq

A Rust Cargo Workspace structured using **Hexagonal Architecture** (Ports and Adapters).

## Crate Layout
- `crates/domain`: Core domain models and business logic.
- `crates/application`: Application services (use cases) and ports (interfaces/traits).
- `crates/adapters/db`: Outbound database adapters (e.g. in-memory database).
- `crates/adapters/web`: Inbound web adapters (e.g. Axum HTTP endpoints).
- `crates/bootstrap`: Wires everything together and starts the application.
