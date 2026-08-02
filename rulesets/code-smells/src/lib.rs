//! Maintainability rules (code smells), pluggable via the `Rule` trait.

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
mod structural_smell;
mod todo_comment;
mod type_check_chain;
mod unreachable_code;
mod unwrap_usage;
mod ck_metrics;
mod halstead_mi;

pub use ck_metrics::CkMetricsRule;
pub use class_fan_out::ClassFanOutRule;
pub use halstead_mi::{HalsteadMiConfig, HalsteadMiRule};
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
pub use structural_smell::StructuralSmellRule;
pub use todo_comment::TodoCommentRule;
pub use type_check_chain::TypeCheckChainRule;
pub use unreachable_code::UnreachableCodeRule;
pub use unwrap_usage::UnwrapUsageRule;

use vord_rules_engine::{CrossFileRule, Rule};

/// Every per-file rule in this ruleset, for composition roots.
pub fn all_rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(ComplexityRule::default()),
        Box::new(CognitiveComplexityRule::default()),
        Box::new(TodoCommentRule::new()),
        Box::new(LongFunctionRule::default()),
        Box::new(UnwrapUsageRule::new()),
        Box::new(SelectStarRule::new()),
        Box::new(DbCallInLoopRule::new()),
        Box::new(CommentedOutCodeRule::new()),
        Box::new(UnreachableCodeRule::new()),
        Box::new(TypeCheckChainRule::default()),
        Box::new(ServiceLocatorRule::new()),
        Box::new(HalsteadMiRule::default()),
    ]
}

/// Every cross-file rule in this ruleset, for composition roots.
pub fn all_cross_rules() -> Vec<Box<dyn CrossFileRule>> {
    vec![
        Box::new(FeatureEnvyRule::default()),
        Box::new(LiskovNotImplementedRule::new()),
        Box::new(OpenClosedViolationRule::new()),
        Box::new(RefusedBequestRule::new()),
        Box::new(ConcreteDependencyRule::new()),
        Box::new(OverrideNarrowsContractRule::new()),
        Box::new(CkMetricsRule::default()),
    ]
}
