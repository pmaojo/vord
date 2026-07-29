//! Cross-file architecture rules — whole-program checks over the import
//! graph, not any single file's AST. Same `CrossFileRule` plugin model as
//! `owasp::CrossFileInjectionRule`.

mod boundary_violation;
mod dependency_cycle;

pub use boundary_violation::BoundaryViolationRule;
pub use dependency_cycle::DependencyCycleRule;

use yunq_rules_engine::CrossFileRule;

/// Every zero-config whole-program rule in this ruleset, for composition
/// roots. `BoundaryViolationRule` is deliberately not here — it needs
/// `[architecture]` from `yunq.toml`, which isn't in scope wherever
/// `all_cross_rules()` is called (see its own doc comment); composition
/// roots that have loaded project config construct and register it
/// separately.
pub fn all_cross_rules() -> Vec<Box<dyn CrossFileRule>> {
    vec![Box::new(DependencyCycleRule::new())]
}
