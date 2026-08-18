//! Rust-specific rules: idioms and anti-patterns that only make sense for
//! this language.

mod common;

mod absurd_extreme_comparison;
mod almost_swapped;
mod blocking_io_in_async;
mod blocking_sleep_in_async;
mod box_leak;
mod clippy_adapter;
mod dbg_macro;
mod derive_clone_on_large_struct;
mod derive_hash_manual_partial_eq;
mod disallow_panic_macros;
mod disallow_unwrap_expect;
mod drop_on_reference;
mod env_var_read_in_library_code;
mod float_literal_eq;
mod format_string_runtime_constructed;
mod from_over_into;
mod inconsistent_error_type;
mod lock_held_across_await;
mod mem_forget;
mod mem_transmute;
mod mem_uninit_or_zeroed;
mod missing_doc_on_public_item;
mod missing_result_handling;
mod modulo_one;
mod mutex_atomic_candidate;
mod mutex_locked_in_drop;
mod nll_borrow_check;
mod panic_in_drop;
mod process_exit;
mod rc_used_in_multithread_context;
mod route_without_test_coverage;
mod rust_naming_convention;
mod self_comparison;
mod static_mut;
mod suspicious_arithmetic_impl;
mod typeshare_dto_sync;
mod unchecked_convergence_bool;
mod unsafe_block_leaks_abstraction;
mod unsafe_send_sync_impl;
mod unsafe_undocumented;
mod unused_lifetime_parameter;

pub use absurd_extreme_comparison::AbsurdExtremeComparisonRule;
pub use almost_swapped::AlmostSwappedRule;
pub use blocking_io_in_async::BlockingIoInAsyncRule;
pub use blocking_sleep_in_async::BlockingSleepInAsyncRule;
pub use box_leak::BoxLeakRule;
pub use clippy_adapter::RustClippyAdapterRule;
pub use dbg_macro::DbgMacroRule;
pub use derive_clone_on_large_struct::DeriveCloneOnLargeStructRule;
pub use derive_hash_manual_partial_eq::DeriveHashManualPartialEqRule;
pub use disallow_panic_macros::DisallowPanicMacrosRule;
pub use disallow_unwrap_expect::DisallowUnwrapExpectRule;
pub use drop_on_reference::DropOnReferenceRule;
pub use env_var_read_in_library_code::EnvVarReadInLibraryCodeRule;
pub use float_literal_eq::FloatLiteralEqRule;
pub use format_string_runtime_constructed::FormatStringRuntimeConstructedRule;
pub use from_over_into::FromOverIntoRule;
pub use inconsistent_error_type::InconsistentErrorTypeRule;
pub use lock_held_across_await::LockHeldAcrossAwaitRule;
pub use mem_forget::MemForgetRule;
pub use mem_transmute::MemTransmuteRule;
pub use mem_uninit_or_zeroed::MemUninitOrZeroedRule;
pub use missing_doc_on_public_item::MissingDocOnPublicItemRule;
pub use missing_result_handling::MissingResultHandlingRule;
pub use modulo_one::ModuloOneRule;
pub use mutex_atomic_candidate::MutexAtomicCandidateRule;
pub use mutex_locked_in_drop::MutexLockedInDropRule;
pub use nll_borrow_check::NllBorrowCheckRule;
pub use panic_in_drop::PanicInDropRule;
pub use process_exit::ProcessExitRule;
pub use rc_used_in_multithread_context::RcUsedInMultithreadContextRule;
pub use route_without_test_coverage::RouteWithoutTestCoverageRule;
pub use rust_naming_convention::RustNamingConventionRule;
pub use self_comparison::SelfComparisonRule;
pub use static_mut::StaticMutRule;
pub use suspicious_arithmetic_impl::SuspiciousArithmeticImplRule;
pub use typeshare_dto_sync::TypeshareDtoSyncRule;
pub use unchecked_convergence_bool::UncheckedConvergenceBoolRule;
pub use unsafe_block_leaks_abstraction::UnsafeBlockLeaksAbstractionRule;
pub use unsafe_send_sync_impl::UnsafeSendSyncImplRule;
pub use unsafe_undocumented::UnsafeUndocumentedRule;
pub use unused_lifetime_parameter::UnusedLifetimeParameterRule;

use vord_rules_engine::{CrossFileRule, Rule};

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
        Box::new(RustClippyAdapterRule::new()),
        Box::new(TypeshareDtoSyncRule::new()),
        Box::new(UncheckedConvergenceBoolRule::new()),
        Box::new(BlockingIoInAsyncRule::new()),
        Box::new(MutexLockedInDropRule::new()),
        Box::new(RcUsedInMultithreadContextRule::new()),
        Box::new(DeriveCloneOnLargeStructRule::new()),
        Box::new(UnsafeBlockLeaksAbstractionRule::new()),
        Box::new(UnusedLifetimeParameterRule::new()),
        Box::new(FormatStringRuntimeConstructedRule::new()),
        Box::new(EnvVarReadInLibraryCodeRule::new()),
        Box::new(MissingDocOnPublicItemRule::new()),
        Box::new(InconsistentErrorTypeRule::new()),
        Box::new(MissingResultHandlingRule::new()),
    ]
}

/// Every cross-file rule in this ruleset, for composition roots.
pub fn all_cross_rules() -> Vec<Box<dyn CrossFileRule>> {
    vec![Box::new(RouteWithoutTestCoverageRule::new())]
}
