//! Cost and termination (roadmap A4): the turn/token budget, and the
//! repeat guard that catches an agent rewriting the same bytes forever.
//!
//! A runtime that can burn an unbounded budget against the same wall is not
//! shippable, so exhaustion is a *verdict* here, not an error — the caller
//! must be able to tell "the analyzer disagreed" from "we ran out of money
//! before finding out", and both from "yunq itself broke".

use crate::session::TokenUsage;

/// The ceilings one `yunq agent` run may not cross.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Budget {
    pub max_turns: u32,
    pub max_tokens: u64,
}

impl Default for Budget {
    /// Enough turns for a real multi-file change, few enough that a stuck
    /// loop is caught in minutes rather than hours. The token ceiling is the
    /// backstop for the opposite failure: few turns, each enormous.
    fn default() -> Self {
        Self {
            max_turns: 40,
            max_tokens: 500_000,
        }
    }
}

/// Which ceiling was reached. Separate variants because the operator's next
/// move differs: more turns is usually a decomposition problem, more tokens
/// is usually a context problem.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Exhaustion {
    Turns { limit: u32 },
    Tokens { limit: u64, spent: u64 },
}

impl std::fmt::Display for Exhaustion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Turns { limit } => write!(f, "turn budget exhausted ({limit} turns)"),
            Self::Tokens { limit, spent } => {
                write!(f, "token budget exhausted ({spent}/{limit} tokens)")
            }
        }
    }
}

/// What the run has spent so far.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Ledger {
    turns: u32,
    tokens: u64,
}

impl Ledger {
    pub fn record_turn(&mut self, usage: TokenUsage) {
        self.turns = self.turns.saturating_add(1);
        self.tokens = self.tokens.saturating_add(usage.total());
    }

    pub fn turns(&self) -> u32 {
        self.turns
    }

    pub fn tokens(&self) -> u64 {
        self.tokens
    }

    /// Checked *before* each turn, so a run never issues the request that
    /// would take it past a ceiling. Turns are checked first: at the moment
    /// both are exhausted, the turn count is the one the operator can act on
    /// without re-reading the transcript.
    pub fn exhausted(&self, budget: &Budget) -> Option<Exhaustion> {
        if self.turns >= budget.max_turns {
            return Some(Exhaustion::Turns {
                limit: budget.max_turns,
            });
        }
        if self.tokens >= budget.max_tokens {
            return Some(Exhaustion::Tokens {
                limit: budget.max_tokens,
                spent: self.tokens,
            });
        }
        None
    }
}

/// Catches the loop the circuit breaker cannot see: a write that is *allowed*
/// every time and identical every time. The policy has no complaint about it,
/// the analyzer's verdict never changes, and the run would otherwise spend
/// its whole budget rewriting one file with the same bytes.
///
/// Session-scoped and in-memory, unlike `yunq hook`'s persisted loop guard:
/// a hook invocation is a fresh process and has to remember across them,
/// whereas a run is one process and its own history is right here.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RepeatGuard {
    last: Option<(String, String)>,
    streak: u32,
}

impl RepeatGuard {
    /// Three identical writes in a row, matching
    /// `CircuitBreakerState::TRIP_THRESHOLD` — the same "twice is a retry,
    /// three times is a loop" judgement, applied to the write instead of the
    /// denial.
    pub const TRIP_THRESHOLD: u32 = 3;

    /// Folds one accepted write in, returning `true` when the streak has just
    /// reached the threshold.
    pub fn record(&mut self, path: &str, content: &str) -> bool {
        let signature = (path.to_string(), content.to_string());
        match &self.last {
            Some(previous) if *previous == signature => self.streak = self.streak.saturating_add(1),
            _ => {
                self.last = Some(signature);
                self.streak = 1;
            }
        }
        self.streak >= Self::TRIP_THRESHOLD
    }

    pub fn streak(&self) -> u32 {
        self.streak
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn usage(total: u64) -> TokenUsage {
        TokenUsage {
            input: total,
            output: 0,
        }
    }

    #[test]
    fn a_fresh_ledger_is_within_any_budget() {
        assert_eq!(Ledger::default().exhausted(&Budget::default()), None);
    }

    #[test]
    fn the_turn_ceiling_is_reached_exactly_at_the_limit() {
        let budget = Budget {
            max_turns: 2,
            max_tokens: u64::MAX,
        };
        let mut ledger = Ledger::default();
        ledger.record_turn(usage(1));
        assert_eq!(
            ledger.exhausted(&budget),
            None,
            "one turn of a two-turn budget is not exhaustion"
        );
        ledger.record_turn(usage(1));
        assert_eq!(
            ledger.exhausted(&budget),
            Some(Exhaustion::Turns { limit: 2 })
        );
    }

    #[test]
    fn the_token_ceiling_reports_what_was_actually_spent() {
        let budget = Budget {
            max_turns: u32::MAX,
            max_tokens: 100,
        };
        let mut ledger = Ledger::default();
        ledger.record_turn(TokenUsage {
            input: 90,
            output: 30,
        });
        assert_eq!(
            ledger.exhausted(&budget),
            Some(Exhaustion::Tokens {
                limit: 100,
                spent: 120
            })
        );
        assert_eq!(ledger.tokens(), 120);
        assert_eq!(ledger.turns(), 1);
    }

    #[test]
    fn turns_are_reported_first_when_both_ceilings_are_reached() {
        let budget = Budget {
            max_turns: 1,
            max_tokens: 1,
        };
        let mut ledger = Ledger::default();
        ledger.record_turn(usage(50));
        assert_eq!(
            ledger.exhausted(&budget),
            Some(Exhaustion::Turns { limit: 1 })
        );
    }

    #[test]
    fn exhaustion_renders_the_numbers_an_operator_needs() {
        assert_eq!(
            Exhaustion::Turns { limit: 7 }.to_string(),
            "turn budget exhausted (7 turns)"
        );
        assert_eq!(
            Exhaustion::Tokens {
                limit: 10,
                spent: 12
            }
            .to_string(),
            "token budget exhausted (12/10 tokens)"
        );
    }

    #[test]
    fn the_repeat_guard_trips_on_the_third_identical_write() {
        let mut guard = RepeatGuard::default();
        assert!(!guard.record("a.rs", "x"));
        assert!(!guard.record("a.rs", "x"));
        assert!(guard.record("a.rs", "x"));
        assert_eq!(guard.streak(), 3);
    }

    #[test]
    fn a_different_write_resets_the_repeat_streak() {
        let mut guard = RepeatGuard::default();
        guard.record("a.rs", "x");
        guard.record("a.rs", "x");
        assert!(
            !guard.record("a.rs", "y"),
            "changed content is progress, not a loop"
        );
        assert_eq!(guard.streak(), 1);
    }

    #[test]
    fn the_same_content_at_a_different_path_is_not_a_repeat() {
        let mut guard = RepeatGuard::default();
        guard.record("a.rs", "x");
        guard.record("b.rs", "x");
        assert_eq!(guard.streak(), 1);
    }
}
