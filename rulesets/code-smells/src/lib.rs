//! Maintainability rules (code smells), pluggable via the `Rule` trait.

mod cognitive_complexity;
mod complexity;
mod long_function;
mod todo_comment;
mod unwrap_usage;

pub use cognitive_complexity::CognitiveComplexityRule;
pub use complexity::ComplexityRule;
pub use long_function::LongFunctionRule;
pub use todo_comment::TodoCommentRule;
pub use unwrap_usage::UnwrapUsageRule;

use yunq_rules_engine::Rule;

/// Every rule in this ruleset, for composition roots.
pub fn all_rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(TodoCommentRule::new()),
        Box::new(LongFunctionRule::default()),
        Box::new(UnwrapUsageRule::new()),
        Box::new(ComplexityRule::default()),
        Box::new(CognitiveComplexityRule::default()),
    ]
}
