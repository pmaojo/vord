//! Maintainability rules (code smells), pluggable via the `Rule` trait.
//!
//! The OOP/design half of this ruleset is organized around SOLID, one rule per
//! principle per failure mode: `god-class`/`low-cohesion`/`class-fan-out`/
//! `constructor-over-injection` (Single Responsibility, measured by size,
//! clumping, reach and dependency count), `open-closed-violation`/
//! `type-check-chain` (Open/Closed, from the type side and the control-flow
//! side), `liskov-not-implemented`/`refused-bequest`/
//! `override-narrows-contract`/`deep-inheritance` (Liskov, and the hierarchies
//! that make it unprovable), `fat-interface` (Interface Segregation), and
//! `concrete-dependency`/`service-locator` (Dependency Inversion, for a
//! dependency constructed and for one looked up).

mod class_fan_out;
mod cognitive_complexity;
mod commented_out_code;
mod complexity;
mod concrete_dependency;
mod constructor_over_injection;
mod db_call_in_loop;
mod deep_inheritance;
mod fat_interface;
mod feature_envy;
mod god_class;
mod liskov_not_implemented;
mod long_function;
mod low_cohesion;
mod open_closed_violation;
mod override_narrows_contract;
mod refused_bequest;
mod select_star;
mod service_locator;
mod todo_comment;
mod type_check_chain;
mod unwrap_usage;

pub use class_fan_out::ClassFanOutRule;
pub use cognitive_complexity::CognitiveComplexityRule;
pub use commented_out_code::CommentedOutCodeRule;
pub use complexity::ComplexityRule;
pub use concrete_dependency::ConcreteDependencyRule;
pub use constructor_over_injection::ConstructorOverInjectionRule;
pub use db_call_in_loop::DbCallInLoopRule;
pub use deep_inheritance::DeepInheritanceRule;
pub use fat_interface::FatInterfaceRule;
pub use feature_envy::FeatureEnvyRule;
pub use god_class::GodClassRule;
pub use liskov_not_implemented::LiskovNotImplementedRule;
pub use long_function::LongFunctionRule;
pub use low_cohesion::LowCohesionRule;
pub use open_closed_violation::OpenClosedViolationRule;
pub use override_narrows_contract::OverrideNarrowsContractRule;
pub use refused_bequest::RefusedBequestRule;
pub use select_star::SelectStarRule;
pub use service_locator::ServiceLocatorRule;
pub use todo_comment::TodoCommentRule;
pub use type_check_chain::TypeCheckChainRule;
pub use unwrap_usage::UnwrapUsageRule;

use yunq_rules_engine::{CrossFileRule, Rule};

/// Every per-file rule in this ruleset, for composition roots.
pub fn all_rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(TodoCommentRule::new()),
        Box::new(LongFunctionRule::default()),
        Box::new(UnwrapUsageRule::new()),
        Box::new(ComplexityRule::default()),
        Box::new(CognitiveComplexityRule::default()),
        Box::new(CommentedOutCodeRule::new()),
        Box::new(SelectStarRule::new()),
        Box::new(DbCallInLoopRule::new()),
        Box::new(FatInterfaceRule::default()),
        Box::new(TypeCheckChainRule::default()),
        Box::new(ConstructorOverInjectionRule::default()),
        Box::new(ServiceLocatorRule::new()),
    ]
}

/// Every whole-program rule in this ruleset, for composition roots. The
/// OOP-smell rules need every file's classes at once so a superclass or a
/// foreign-typed parameter declared in a different file still resolves.
pub fn all_cross_rules() -> Vec<Box<dyn CrossFileRule>> {
    vec![
        Box::new(GodClassRule::default()),
        Box::new(FeatureEnvyRule::default()),
        Box::new(RefusedBequestRule::new()),
        Box::new(LowCohesionRule::default()),
        Box::new(LiskovNotImplementedRule::new()),
        Box::new(ConcreteDependencyRule::new()),
        Box::new(OpenClosedViolationRule::new()),
        Box::new(ClassFanOutRule::default()),
        Box::new(DeepInheritanceRule::default()),
        Box::new(OverrideNarrowsContractRule::new()),
    ]
}
