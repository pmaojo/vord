//! Rust-specific rules: idioms and anti-patterns that only make sense for
//! this language (`unsafe`, `mem::transmute`/`mem::forget`, abrupt process
//! termination). Language-neutral checks (unwrap/expect, complexity,
//! TODOs, …) that also apply to Rust live in `rulesets/code-smells`.

mod mem_forget;
mod mem_transmute;
mod process_exit;
mod unsafe_undocumented;

pub use mem_forget::MemForgetRule;
pub use mem_transmute::MemTransmuteRule;
pub use process_exit::ProcessExitRule;
pub use unsafe_undocumented::UnsafeUndocumentedRule;

use yunq_rules_engine::Rule;

/// Every rule in this ruleset, for composition roots.
pub fn all_rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(UnsafeUndocumentedRule::new()),
        Box::new(MemTransmuteRule::new()),
        Box::new(MemForgetRule::new()),
        Box::new(ProcessExitRule::new()),
    ]
}
