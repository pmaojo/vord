//! PHP-specific rules: idioms and vulnerability classes that only make
//! sense for this language — dynamic code/variable execution (`eval`,
//! `extract`, a function call whose name comes from request data), the
//! `@` error-control operator, PHP's `==`/`!=` type-juggling "magic hash"
//! bug, SQL/OS-command injection through PHP's own sink functions (not
//! covered by the generic `owasp:command-execution`, whose sink list is
//! Rust/Go/Python/TypeScript-specific), variable variables, and building a
//! security-sensitive value from a non-cryptographic random source.
//! Language-neutral checks (hardcoded secrets, weak crypto, pending task
//! comments, …) that also apply to PHP live in `rulesets/owasp` and
//! `rulesets/code-smells`.

mod common;

mod command_execution;
mod dynamic_function_call;
mod error_suppression_operator;
mod eval_usage;
mod extract_usage;
mod loose_hash_comparison;
mod sql_injection_concat;
mod swallowed_exception;
mod variable_variable;
mod weak_random_token;

pub use command_execution::CommandExecutionRule;
pub use dynamic_function_call::DynamicFunctionCallRule;
pub use error_suppression_operator::ErrorSuppressionOperatorRule;
pub use eval_usage::EvalUsageRule;
pub use extract_usage::ExtractUsageRule;
pub use loose_hash_comparison::LooseHashComparisonRule;
pub use sql_injection_concat::SqlInjectionConcatRule;
pub use swallowed_exception::SwallowedExceptionRule;
pub use variable_variable::VariableVariableRule;
pub use weak_random_token::WeakRandomTokenRule;

use vord_rules_engine::Rule;

/// Every rule in this ruleset, for composition roots.
pub fn all_rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(EvalUsageRule::new()),
        Box::new(ExtractUsageRule::new()),
        Box::new(ErrorSuppressionOperatorRule::new()),
        Box::new(LooseHashComparisonRule::new()),
        Box::new(CommandExecutionRule::new()),
        Box::new(SqlInjectionConcatRule::new()),
        Box::new(DynamicFunctionCallRule::new()),
        Box::new(VariableVariableRule::new()),
        Box::new(WeakRandomTokenRule::new()),
        Box::new(SwallowedExceptionRule::new()),
    ]
}
