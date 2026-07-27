//! Vanilla TypeScript/JavaScript rules: language idioms and DOM/browser
//! anti-patterns that apply to plain TS/JS (no JSX/React — see
//! `rulesets/react` for that). Generic OWASP checks that already apply to
//! TypeScript (`owasp:xss`, `owasp:eval-usage`, `owasp:injection`, ...) live
//! in `rulesets/owasp`; this crate only adds detections not already covered
//! there.

mod common;
mod dynamic_regexp_source;
mod innerhtml_assignment;
mod json_parse_unguarded;
mod leftover_debug_statement;
mod loose_equality;
mod mass_assignment_from_request_body;
mod math_random_for_token;
mod open_redirect_location_assignment;
mod promise_then_without_catch;
mod redos_nested_quantifier;
mod sensitive_data_in_web_storage;
mod swallowed_exception;
mod var_declaration;

pub use dynamic_regexp_source::DynamicRegexpSourceRule;
pub use innerhtml_assignment::InnerHtmlAssignmentRule;
pub use json_parse_unguarded::JsonParseUnguardedRule;
pub use leftover_debug_statement::LeftoverDebugStatementRule;
pub use loose_equality::LooseEqualityRule;
pub use mass_assignment_from_request_body::MassAssignmentFromRequestBodyRule;
pub use math_random_for_token::MathRandomForTokenRule;
pub use open_redirect_location_assignment::OpenRedirectLocationAssignmentRule;
pub use promise_then_without_catch::PromiseThenWithoutCatchRule;
pub use redos_nested_quantifier::RedosNestedQuantifierRule;
pub use sensitive_data_in_web_storage::SensitiveDataInWebStorageRule;
pub use swallowed_exception::SwallowedExceptionRule;
pub use var_declaration::VarDeclarationRule;

use yunq_rules_engine::Rule;

/// Every rule in this ruleset, for composition roots.
pub fn all_rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(LooseEqualityRule::new()),
        Box::new(VarDeclarationRule::new()),
        Box::new(LeftoverDebugStatementRule::new()),
        Box::new(PromiseThenWithoutCatchRule::new()),
        Box::new(MathRandomForTokenRule::new()),
        Box::new(DynamicRegexpSourceRule::new()),
        Box::new(RedosNestedQuantifierRule::new()),
        Box::new(JsonParseUnguardedRule::new()),
        Box::new(OpenRedirectLocationAssignmentRule::new()),
        Box::new(SensitiveDataInWebStorageRule::new()),
        Box::new(MassAssignmentFromRequestBodyRule::new()),
        Box::new(InnerHtmlAssignmentRule::new()),
        Box::new(SwallowedExceptionRule::new()),
    ]
}
