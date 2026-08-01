//! Architecture rules: the hexagon itself, enforced.

mod boundary_violation;
mod census;
mod dependency_cycle;
mod folder_naming_casing;
mod framework_in_domain;
mod functional_module;
mod graph_architecture;
mod hexagonal_layer;
mod main_sequence;
mod stable_dependencies;
mod vertical_slice_coupling;

pub use boundary_violation::BoundaryViolationRule;
pub use dependency_cycle::DependencyCycleRule;
pub use folder_naming_casing::FolderNamingCasingRule;
pub use framework_in_domain::FrameworkInDomainRule;
pub use functional_module::FunctionalModuleRule;
pub use graph_architecture::{GraphCircularDependencyRule, GraphMissingContractRule};
pub use hexagonal_layer::HexagonalLayerRule;
pub use main_sequence::MainSequenceRule;
pub use stable_dependencies::StableDependencyRule;
pub use vertical_slice_coupling::VerticalSliceCouplingRule;

use yunq_rules_engine::{CrossFileRule, Rule};

/// Every per-file rule in this ruleset, for composition roots.
pub fn all_rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(FrameworkInDomainRule::new()),
        Box::new(FolderNamingCasingRule::new()),
        Box::new(FunctionalModuleRule::default()),
        Box::new(GraphCircularDependencyRule::new()),
        Box::new(GraphMissingContractRule::new()),
        Box::new(VerticalSliceCouplingRule::new()),
    ]
}

/// Every zero-config whole-program rule in this ruleset, for composition
/// roots.
pub fn all_cross_rules() -> Vec<Box<dyn CrossFileRule>> {
    vec![
        Box::new(DependencyCycleRule::new()),
        Box::new(HexagonalLayerRule::new()),
        Box::new(MainSequenceRule::default()),
        Box::new(StableDependencyRule::default()),
    ]
}
