//! Architecture rules: the hexagon itself, enforced.
//!
//! Two kinds live here. Most are whole-program checks over the import graph
//! (`CrossFileRule`, same plugin model as `owasp::CrossFileInjectionRule`) —
//! layering direction, import cycles, declared boundaries, Martin's component
//! metrics. One is per-file (`FrameworkInDomainRule`), because a domain file
//! importing `sqlalchemy` needs nothing but its own path and its own import
//! list to be a finding.
//!
//! The layering rules are zero-config on purpose: `BoundaryViolationRule` can
//! only speak once someone writes `[architecture]` in `yunq.toml`, while
//! `HexagonalLayerRule` and `FrameworkInDomainRule` read the layering
//! vocabulary the industry already shares (`yunq_import_graph::layer_of`) and
//! fail a build on the first scan.

mod boundary_violation;
mod census;
mod dependency_cycle;
mod framework_in_domain;
mod hexagonal_layer;
mod main_sequence;
mod stable_dependencies;

pub use boundary_violation::BoundaryViolationRule;
pub use dependency_cycle::DependencyCycleRule;
pub use framework_in_domain::FrameworkInDomainRule;
pub use hexagonal_layer::HexagonalLayerRule;
pub use main_sequence::MainSequenceRule;
pub use stable_dependencies::StableDependencyRule;

use yunq_rules_engine::{CrossFileRule, Rule};

/// Every per-file rule in this ruleset, for composition roots.
pub fn all_rules() -> Vec<Box<dyn Rule>> {
    vec![Box::new(FrameworkInDomainRule::new())]
}

/// Every zero-config whole-program rule in this ruleset, for composition
/// roots. `BoundaryViolationRule` is deliberately not here — it needs
/// `[architecture]` from `yunq.toml`, which isn't in scope wherever
/// `all_cross_rules()` is called (see its own doc comment); composition
/// roots that have loaded project config construct and register it
/// separately.
pub fn all_cross_rules() -> Vec<Box<dyn CrossFileRule>> {
    vec![
        Box::new(DependencyCycleRule::new()),
        Box::new(HexagonalLayerRule::new()),
        Box::new(MainSequenceRule::default()),
        Box::new(StableDependencyRule::default()),
    ]
}
