//! Rust-specific rules: idioms and anti-patterns that only make sense for
//! this language — `unsafe` (undocumented blocks, unchecked `Send`/`Sync`
//! impls, `mem::transmute`/`mem::forget`/`mem::uninitialized`/`mem::zeroed`,
//! `Box::leak`), unsynchronized global state (`static mut`), panic safety
//! (`Drop::drop`, where unwinding aborts the process), abrupt process
//! termination, and the `From`-over-`Into` conversion idiom. Language-neutral
//! checks (unwrap/expect, complexity, postponed-work comments, …) that also
//! apply to Rust live in `rulesets/code-smells`.

mod common;

mod box_leak;
mod dbg_macro;
mod from_over_into;
mod mem_forget;
mod mem_transmute;
mod mem_uninit_or_zeroed;
mod panic_in_drop;
mod process_exit;
mod static_mut;
mod unsafe_send_sync_impl;
mod unsafe_undocumented;

pub use box_leak::BoxLeakRule;
pub use dbg_macro::DbgMacroRule;
pub use from_over_into::FromOverIntoRule;
pub use mem_forget::MemForgetRule;
pub use mem_transmute::MemTransmuteRule;
pub use mem_uninit_or_zeroed::MemUninitOrZeroedRule;
pub use panic_in_drop::PanicInDropRule;
pub use process_exit::ProcessExitRule;
pub use static_mut::StaticMutRule;
pub use unsafe_send_sync_impl::UnsafeSendSyncImplRule;
pub use unsafe_undocumented::UnsafeUndocumentedRule;

use yunq_rules_engine::Rule;

/// Every rule in this ruleset, for composition roots.
pub fn all_rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(UnsafeUndocumentedRule::new()),
        Box::new(MemTransmuteRule::new()),
        Box::new(MemForgetRule::new()),
        Box::new(ProcessExitRule::new()),
        Box::new(StaticMutRule::new()),
        Box::new(MemUninitOrZeroedRule::new()),
        Box::new(BoxLeakRule::new()),
        Box::new(UnsafeSendSyncImplRule::new()),
        Box::new(PanicInDropRule::new()),
        Box::new(FromOverIntoRule::new()),
        Box::new(DbgMacroRule::new()),
    ]
}
