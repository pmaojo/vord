//! Rust-specific rules: idioms and anti-patterns that only make sense for
//! this language.

mod common;

mod absurd_extreme_comparison;
mod almost_swapped;
mod blocking_sleep_in_async;
mod box_leak;
mod dbg_macro;
mod derive_hash_manual_partial_eq;
mod disallow_panic_macros;
mod disallow_unwrap_expect;
mod drop_on_reference;
mod float_literal_eq;
mod from_over_into;
mod lock_held_across_await;
mod mem_forget;
mod mem_transmute;
mod mem_uninit_or_zeroed;
mod modulo_one;
mod mutex_atomic_candidate;
mod nll_borrow_check;
mod panic_in_drop;
mod process_exit;
mod rust_naming_convention;
mod self_comparison;
mod static_mut;
mod suspicious_arithmetic_impl;
mod unsafe_send_sync_impl;
mod unsafe_undocumented;

pub use absurd_extreme_comparison::AbsurdExtremeComparisonRule;
pub use almost_swapped::AlmostSwappedRule;
pub use blocking_sleep_in_async::BlockingSleepInAsyncRule;
pub use box_leak::BoxLeakRule;
pub use dbg_macro::DbgMacroRule;
pub use derive_hash_manual_partial_eq::DeriveHashManualPartialEqRule;
pub use disallow_panic_macros::DisallowPanicMacrosRule;
pub use disallow_unwrap_expect::DisallowUnwrapExpectRule;
pub use drop_on_reference::DropOnReferenceRule;
pub use float_literal_eq::FloatLiteralEqRule;
pub use from_over_into::FromOverIntoRule;
pub use lock_held_across_await::LockHeldAcrossAwaitRule;
pub use mem_forget::MemForgetRule;
pub use mem_transmute::MemTransmuteRule;
pub use mem_uninit_or_zeroed::MemUninitOrZeroedRule;
pub use modulo_one::ModuloOneRule;
pub use mutex_atomic_candidate::MutexAtomicCandidateRule;
pub use nll_borrow_check::NllBorrowCheckRule;
pub use panic_in_drop::PanicInDropRule;
pub use process_exit::ProcessExitRule;
pub use rust_naming_convention::RustNamingConventionRule;
pub use self_comparison::SelfComparisonRule;
pub use static_mut::StaticMutRule;
pub use suspicious_arithmetic_impl::SuspiciousArithmeticImplRule;
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
        Box::new(DeriveHashManualPartialEqRule::new()),
        Box::new(SelfComparisonRule::new()),
        Box::new(FloatLiteralEqRule::new()),
        Box::new(DropOnReferenceRule::new()),
        Box::new(BlockingSleepInAsyncRule::new()),
        Box::new(ModuloOneRule::new()),
        Box::new(AlmostSwappedRule::new()),
        Box::new(AbsurdExtremeComparisonRule::new()),
        Box::new(SuspiciousArithmeticImplRule::new()),
        Box::new(MutexAtomicCandidateRule::new()),
        Box::new(LockHeldAcrossAwaitRule::new()),
        Box::new(DbgMacroRule::new()),
        Box::new(NllBorrowCheckRule::new()),
        Box::new(DisallowUnwrapExpectRule::new()),
        Box::new(RustNamingConventionRule::new()),
        Box::new(DisallowPanicMacrosRule::new()),
    ]
}
