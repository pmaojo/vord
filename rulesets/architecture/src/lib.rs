//! Cross-file architecture rules — whole-program checks over the import
//! graph, not any single file's AST. Same `CrossFileRule` plugin model as
//! `owasp::CrossFileInjectionRule`.

mod dependency_cycle;

pub use dependency_cycle::DependencyCycleRule;

use yunq_rules_engine::CrossFileRule;

/// Every whole-program rule in this ruleset, for composition roots.
pub fn all_cross_rules() -> Vec<Box<dyn CrossFileRule>> {
    vec![Box::new(DependencyCycleRule::new())]
}
