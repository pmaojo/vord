//! Detections aimed squarely at AI-generated and AI-agent code.

mod llm_output_injection;
mod no_dynamic_reflection;
mod no_wildcard_reexports;

pub use llm_output_injection::LlmOutputInjectionRule;
pub use no_dynamic_reflection::NoDynamicReflectionRule;
pub use no_wildcard_reexports::NoWildcardReexportsRule;

use yunq_rules_engine::Rule;

/// Every rule in this ruleset, for composition roots.
pub fn all_rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(LlmOutputInjectionRule::new()),
        Box::new(NoDynamicReflectionRule::new()),
        Box::new(NoWildcardReexportsRule::new()),
    ]
}
