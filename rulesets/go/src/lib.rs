//! Go-specific rules: idioms and vulnerability classes that only make sense
//! for this language, as opposed to the neutral-AST checks in
//! `rulesets/code-smells` that merely happen to apply to Go too, or the
//! generic `rulesets/owasp` checks that already cover Go's `exec.Command`
//! hotspot (`owasp:command-execution`) and disabled TLS verification
//! (`owasp:disabled-cert-validation`). SQL injection via string
//! concatenation (no generic rule covers Go here — `owasp:injection`'s
//! taint analysis is TypeScript-only), building a security-sensitive value
//! from `math/rand`, a `context.WithValue` key collision hazard, a
//! single-value type assertion that panics instead of reporting failure, a
//! `defer` piling up inside a loop instead of running per iteration, and a
//! goroutine capturing its enclosing loop variable by reference.

mod common;

mod context_value_string_key;
mod defer_in_loop;
mod goroutine_loop_var_capture;
mod sql_injection_concat;
mod unchecked_type_assertion;
mod weak_random_token;

pub use context_value_string_key::ContextValueStringKeyRule;
pub use defer_in_loop::DeferInLoopRule;
pub use goroutine_loop_var_capture::GoroutineLoopVarCaptureRule;
pub use sql_injection_concat::SqlInjectionConcatRule;
pub use unchecked_type_assertion::UncheckedTypeAssertionRule;
pub use weak_random_token::WeakRandomTokenRule;

use vord_rules_engine::Rule;

/// Every rule in this ruleset, for composition roots.
pub fn all_rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(SqlInjectionConcatRule::new()),
        Box::new(WeakRandomTokenRule::new()),
        Box::new(ContextValueStringKeyRule::new()),
        Box::new(UncheckedTypeAssertionRule::new()),
        Box::new(DeferInLoopRule::new()),
        Box::new(GoroutineLoopVarCaptureRule::new()),
    ]
}
