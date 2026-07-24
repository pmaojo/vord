//! Reactive-stream (RxJS-shaped) rules: syntactic patterns around
//! `.subscribe`/`.unsubscribe`/`Subject`/`.complete` that don't need symbol
//! resolution — just recognizing the same binding referenced as an
//! assignment target and later as a call receiver.

mod common;
mod missing_unsubscribe;
mod subject_never_completed;

pub use missing_unsubscribe::MissingUnsubscribeRule;
pub use subject_never_completed::SubjectNeverCompletedRule;

use yunq_rules_engine::Rule;

/// Every rule in this ruleset, for composition roots.
pub fn all_rules() -> Vec<Box<dyn Rule>> {
    vec![Box::new(MissingUnsubscribeRule::new()), Box::new(SubjectNeverCompletedRule::new())]
}
