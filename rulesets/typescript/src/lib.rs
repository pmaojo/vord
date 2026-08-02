//! Vanilla TypeScript/JavaScript rules: language idioms and DOM/browser
//! anti-patterns.

mod boolean_naming;
mod buffer_noassert;
mod common;
mod dynamic_regexp_source;
mod innerhtml_assignment;
mod json_parse_unguarded;
mod leftover_debug_statement;
mod loose_equality;
mod mass_assignment_from_request_body;
mod math_random_for_token;
mod no_explicit_any;
mod open_redirect_location_assignment;
mod oxlint_adapter;
mod promise_then_without_catch;
mod redos_nested_quantifier;
mod sensitive_data_in_web_storage;
mod swallowed_exception;
mod var_declaration;

pub use boolean_naming::BooleanNamingRule;
pub use buffer_noassert::BufferNoassertRule;
pub use dynamic_regexp_source::DynamicRegexpSourceRule;
pub use innerhtml_assignment::InnerHtmlAssignmentRule;
pub use json_parse_unguarded::JsonParseUnguardedRule;
pub use leftover_debug_statement::LeftoverDebugStatementRule;
pub use loose_equality::LooseEqualityRule;
pub use mass_assignment_from_request_body::MassAssignmentFromRequestBodyRule;
pub use math_random_for_token::MathRandomForTokenRule;
pub use no_explicit_any::NoExplicitAnyRule;
pub use open_redirect_location_assignment::OpenRedirectLocationAssignmentRule;
pub use oxlint_adapter::OxlintAdapterRule;
pub use promise_then_without_catch::PromiseThenWithoutCatchRule;
pub use redos_nested_quantifier::RedosNestedQuantifierRule;
pub use sensitive_data_in_web_storage::SensitiveDataInWebStorageRule;
pub use swallowed_exception::SwallowedExceptionRule;
pub use var_declaration::VarDeclarationRule;

use yunq_rules_engine::Rule;

/// Every rule in this ruleset, for composition roots.
pub fn all_rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(DynamicRegexpSourceRule::new()),
        Box::new(InnerHtmlAssignmentRule::new()),
        Box::new(JsonParseUnguardedRule::new()),
        Box::new(LeftoverDebugStatementRule::new()),
        Box::new(LooseEqualityRule::new()),
        Box::new(MassAssignmentFromRequestBodyRule::new()),
        Box::new(MathRandomForTokenRule::new()),
        Box::new(OpenRedirectLocationAssignmentRule::new()),
        Box::new(PromiseThenWithoutCatchRule::new()),
        Box::new(RedosNestedQuantifierRule::new()),
        Box::new(SensitiveDataInWebStorageRule::new()),
        Box::new(SwallowedExceptionRule::new()),
        Box::new(VarDeclarationRule::new()),
        Box::new(BooleanNamingRule::new()),
        Box::new(NoExplicitAnyRule::new()),
        Box::new(OxlintAdapterRule::new()),
        Box::new(BufferNoassertRule::new()),
    ]
}
