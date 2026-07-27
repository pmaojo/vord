//! Maintainability rules (code smells), pluggable via the `Rule` trait.

mod cognitive_complexity;
mod commented_out_code;
mod complexity;
mod feature_envy;
mod god_class;
mod long_function;
mod refused_bequest;
mod select_star;
mod todo_comment;
mod unwrap_usage;

pub use cognitive_complexity::CognitiveComplexityRule;
pub use commented_out_code::CommentedOutCodeRule;
pub use complexity::ComplexityRule;
pub use feature_envy::FeatureEnvyRule;
pub use god_class::GodClassRule;
pub use long_function::LongFunctionRule;
pub use refused_bequest::RefusedBequestRule;
pub use select_star::SelectStarRule;
pub use todo_comment::TodoCommentRule;
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
    ]
}

/// Every whole-program rule in this ruleset, for composition roots. The
/// OOP-smell rules need every file's classes at once so a superclass or a
/// foreign-typed parameter declared in a different file still resolves.
pub fn all_cross_rules() -> Vec<Box<dyn CrossFileRule>> {
    vec![Box::new(GodClassRule::default()), Box::new(FeatureEnvyRule::default()), Box::new(RefusedBequestRule::new())]
}
