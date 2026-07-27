//! Rust-specific rules: idioms and anti-patterns that only make sense for
//! this language — `unsafe` (undocumented blocks, unchecked `Send`/`Sync`
//! impls, `mem::transmute`/`mem::forget`/`mem::uninitialized`/`mem::zeroed`,
//! `Box::leak`), unsynchronized global state (`static mut`), panic safety
//! (`Drop::drop`, where unwinding aborts the process), abrupt process
//! termination, the `From`-over-`Into` conversion idiom, `Hash`/`Eq`
//! contract violations, self-comparison and fragile float-literal
//! comparison bugs, no-op `drop` on a reference, and blocking a async
//! runtime's thread with `thread::sleep`. Language-neutral checks
//! (unwrap/expect, complexity, postponed-work comments, …) that also apply
//! to Rust live in `rulesets/code-smells`.

mod common;

mod blocking_sleep_in_async;
mod box_leak;
mod dbg_macro;
mod derive_hash_manual_partial_eq;
mod drop_on_reference;
mod float_literal_eq;
mod from_over_into;
mod mem_forget;
mod mem_transmute;
mod mem_uninit_or_zeroed;
mod panic_in_drop;
mod process_exit;
mod self_comparison;
mod static_mut;
mod unsafe_send_sync_impl;
mod unsafe_undocumented;

pub use blocking_sleep_in_async::BlockingSleepInAsyncRule;
pub use box_leak::BoxLeakRule;
pub use dbg_macro::DbgMacroRule;
pub use derive_hash_manual_partial_eq::DeriveHashManualPartialEqRule;
pub use drop_on_reference::DropOnReferenceRule;
pub use float_literal_eq::FloatLiteralEqRule;
pub use from_over_into::FromOverIntoRule;
pub use mem_forget::MemForgetRule;
pub use mem_transmute::MemTransmuteRule;
pub use mem_uninit_or_zeroed::MemUninitOrZeroedRule;
pub use panic_in_drop::PanicInDropRule;
pub use process_exit::ProcessExitRule;
pub use self_comparison::SelfComparisonRule;
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
        Box::new(DropOnReferenceRule::new()),
        Box::new(SelfComparisonRule::new()),
        Box::new(FloatLiteralEqRule::new()),
        Box::new(DeriveHashManualPartialEqRule::new()),
        Box::new(BlockingSleepInAsyncRule::new()),
    ]
}
