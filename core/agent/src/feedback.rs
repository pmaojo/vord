//! Late feedback is part of done (roadmap A5).
//!
//! [`completion`](crate::completion) defines "done" as the analyzer agreeing,
//! which is true right up until the agent opens a pull request — at which
//! point review bots and CI post minutes after the push, and a PR that looked
//! clean the instant it was pushed is not a PR that is finished. This module
//! is the discipline for waiting out that window:
//!
//! - a **backoff schedule**, so a fifteen-minute wait is not fifteen minutes
//!   of polling;
//! - a **settle window**, so one review batch arriving over thirty seconds is
//!   collected and reported as one batch rather than three;
//! - a **triage ledger**, so a re-run does not re-report what it already
//!   handled;
//! - and **four** terminal states, not two.
//!
//! That last point carries the weight. "We looked and saw nothing"
//! ([`FeedbackOutcome::Quiet`]) and "we could not look"
//! ([`FeedbackOutcome::Inconclusive`]) must never collapse into the same exit
//! code. Fail-open must not mean fail-blind — which is also why a poll that
//! errored *anywhere* in an otherwise-silent window downgrades the result to
//! inconclusive rather than reporting silence it never actually observed.
//!
//! Pure, like everything else in this crate: no clock and no HTTP. The caller
//! honours the [`Watch::WaitFor`] delays it is handed, and this module counts
//! them as elapsed time.

use std::collections::BTreeSet;
use std::time::Duration;

/// Where one piece of feedback came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FeedbackSource {
    ReviewComment,
    IssueComment,
    Review,
    CheckRun,
}

/// What the item says about the pull request's health, normalised across
/// sources by the adapter: a failing check, a changes-requested review and a
/// bot's "found 3 problems" are the same signal here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ItemVerdict {
    /// A green check, an approval — evidence the PR is fine.
    Clean,
    /// A failing check, a changes-requested review.
    NeedsWork,
    /// A plain comment: no verdict either way.
    Neutral,
}

/// One item of late feedback.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeedbackItem {
    /// Stable across polls and across runs — this is what the ledger
    /// remembers, so it must come from the API's own identifier, never from
    /// a hash of the body (an edited comment is the same comment).
    pub id: String,
    pub source: FeedbackSource,
    pub author: String,
    pub body: String,
    pub bot: bool,
    pub verdict: ItemVerdict,
}

impl FeedbackItem {
    /// Whether this item needs the agent to do something.
    ///
    /// Anything a human wrote counts, whatever its verdict — a human who took
    /// the time to comment is not noise. A bot only counts when it actually
    /// objects, which is what makes [`FeedbackOutcome::BotAllClear`]
    /// distinguishable from silence.
    pub fn is_actionable(&self) -> bool {
        self.verdict == ItemVerdict::NeedsWork || !self.bot
    }

    pub fn describe(&self) -> String {
        let kind = match self.source {
            FeedbackSource::ReviewComment => "review comment",
            FeedbackSource::IssueComment => "comment",
            FeedbackSource::Review => "review",
            FeedbackSource::CheckRun => "check",
        };
        format!("{kind} from {}: {}", self.author, self.body)
    }
}

/// What one poll of the ALM returned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Poll {
    /// The adapter looked and this is what was there — an empty `items` is a
    /// real observation of silence.
    Observed {
        items: Vec<FeedbackItem>,
        /// Reporters that have not reported yet: checks queued or running.
        /// Silence with a check still in flight is not silence, and a window
        /// that ends while one is outstanding settles as
        /// [`FeedbackOutcome::Inconclusive`] rather than
        /// [`FeedbackOutcome::Quiet`].
        outstanding: usize,
    },
    /// The adapter could not look: a network error, a rate-limit page, a 500.
    /// Deliberately not an empty `Observed`, because an unchecked error body
    /// arriving on the same channel as data is exactly how a rate-limit page
    /// gets reported as "no findings".
    Unavailable(String),
}

impl Poll {
    /// A complete observation: everything that was going to report has.
    pub fn observed(items: Vec<FeedbackItem>) -> Self {
        Self::Observed {
            items,
            outstanding: 0,
        }
    }
}

/// How the watch ends.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FeedbackOutcome {
    /// The window elapsed, every poll succeeded, and nothing arrived.
    Quiet,
    /// Something arrived that the agent has to act on.
    NewFeedback { items: Vec<FeedbackItem> },
    /// Bots reported and none of them objected. Distinct from `Quiet`: this
    /// is positive evidence the PR is fine, not merely the absence of
    /// evidence that it is not.
    BotAllClear { items: Vec<FeedbackItem> },
    /// We could not look. Never conflated with silence.
    Inconclusive { reason: String },
}

impl FeedbackOutcome {
    /// Exit codes in the same family as
    /// [`RunOutcome::exit_code`](crate::runtime::RunOutcome::exit_code), with
    /// `1` reserved for "yunq could not do its job".
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::Quiet | Self::BotAllClear { .. } => 0,
            Self::Inconclusive { .. } => 1,
            Self::NewFeedback { .. } => 3,
        }
    }

    pub fn describe(&self) -> String {
        match self {
            Self::Quiet => "quiet: the window elapsed with no feedback".to_string(),
            Self::BotAllClear { items } => {
                format!("bot all-clear: {} report(s), none objecting", items.len())
            }
            Self::NewFeedback { items } => {
                let lines: Vec<String> = items.iter().map(FeedbackItem::describe).collect();
                format!(
                    "{} new item(s) to triage:\n{}",
                    items.len(),
                    lines.join("\n")
                )
            }
            Self::Inconclusive { reason } => format!("inconclusive: {reason}"),
        }
    }
}

/// What the caller should do next.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Watch {
    /// Sleep this long, then poll again.
    WaitFor(Duration),
    Settled(FeedbackOutcome),
}

/// Items already reported by a previous run, so a re-run triages only what is
/// genuinely new. Persisted by the caller (`bin/cli` writes it alongside the
/// guardrail's other soft state); this type only knows how to fold.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TriageLedger {
    seen: BTreeSet<String>,
}

impl TriageLedger {
    pub fn from_ids(ids: impl IntoIterator<Item = String>) -> Self {
        Self {
            seen: ids.into_iter().collect(),
        }
    }

    pub fn contains(&self, id: &str) -> bool {
        self.seen.contains(id)
    }

    /// Records an item as triaged. Returns `true` when it was new.
    pub fn record(&mut self, id: &str) -> bool {
        self.seen.insert(id.to_string())
    }

    /// Sorted, for the caller to persist deterministically.
    pub fn ids(&self) -> impl Iterator<Item = &String> {
        self.seen.iter()
    }
}

/// The timings of one watch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WatchPolicy {
    /// Delay before the first re-poll; doubled each attempt up to `max_delay`.
    pub first_delay: Duration,
    pub max_delay: Duration,
    /// Total time to keep watching before calling it quiet.
    pub window: Duration,
    /// How long a batch must stay silent before it is considered complete.
    pub settle: Duration,
    /// Consecutive failed polls before the watch gives up as inconclusive.
    pub max_failures: u32,
}

impl Default for WatchPolicy {
    /// Tuned for the actual arrival pattern of PR feedback: CI and review
    /// bots report within a couple of minutes, humans within fifteen.
    fn default() -> Self {
        Self {
            first_delay: Duration::from_secs(30),
            max_delay: Duration::from_secs(300),
            window: Duration::from_secs(900),
            settle: Duration::from_secs(60),
            max_failures: 3,
        }
    }
}

impl WatchPolicy {
    /// Exponential, capped. `attempt` is zero-based.
    pub fn delay_for(&self, attempt: u32) -> Duration {
        let factor = 2u32.saturating_pow(attempt.min(16));
        self.first_delay.saturating_mul(factor).min(self.max_delay)
    }
}

/// The watch itself: fold in each [`Poll`], act on each [`Watch`].
#[derive(Clone, Debug)]
pub struct FeedbackWatch {
    policy: WatchPolicy,
    ledger: TriageLedger,
    attempt: u32,
    elapsed: Duration,
    pending: Vec<FeedbackItem>,
    consecutive_failures: u32,
    saw_failure: bool,
    last_error: Option<String>,
    outstanding: usize,
}

impl FeedbackWatch {
    pub fn new(policy: WatchPolicy, ledger: TriageLedger) -> Self {
        Self {
            policy,
            ledger,
            attempt: 0,
            elapsed: Duration::ZERO,
            pending: Vec::new(),
            consecutive_failures: 0,
            saw_failure: false,
            last_error: None,
            outstanding: 0,
        }
    }

    pub fn ledger(&self) -> &TriageLedger {
        &self.ledger
    }

    pub fn elapsed(&self) -> Duration {
        self.elapsed
    }

    /// Folds one poll's result in and says what to do next. The caller is
    /// expected to honour the returned delay before calling again; this type
    /// counts those delays as the elapsed window.
    pub fn observe(&mut self, poll: Poll) -> Watch {
        match poll {
            Poll::Unavailable(reason) => self.on_failure(reason),
            Poll::Observed { items, outstanding } => self.on_observation(items, outstanding),
        }
    }

    fn on_failure(&mut self, reason: String) -> Watch {
        self.consecutive_failures += 1;
        self.saw_failure = true;
        self.last_error = Some(reason.clone());
        if self.consecutive_failures >= self.policy.max_failures {
            return Watch::Settled(FeedbackOutcome::Inconclusive {
                reason: format!(
                    "{} consecutive failed polls, last: {reason}",
                    self.consecutive_failures
                ),
            });
        }
        self.backoff()
    }

    fn on_observation(&mut self, items: Vec<FeedbackItem>, outstanding: usize) -> Watch {
        self.consecutive_failures = 0;
        self.outstanding = outstanding;
        let new: Vec<FeedbackItem> = items
            .into_iter()
            .filter(|item| !self.ledger.contains(&item.id))
            .collect();
        if !new.is_empty() {
            for item in &new {
                self.ledger.record(&item.id);
            }
            self.pending.extend(new);
            // Wait out the settle window before reporting, so the rest of the
            // batch lands in the same report.
            self.elapsed = self.elapsed.saturating_add(self.policy.settle);
            return Watch::WaitFor(self.policy.settle);
        }
        if !self.pending.is_empty() {
            return Watch::Settled(classify(std::mem::take(&mut self.pending)));
        }
        if self.elapsed >= self.policy.window {
            return Watch::Settled(self.silent_outcome());
        }
        self.backoff()
    }

    /// Silence at the end of the window. Only [`FeedbackOutcome::Quiet`] if
    /// every poll in it actually succeeded *and* everything that was going to
    /// report had reported.
    fn silent_outcome(&self) -> FeedbackOutcome {
        if self.outstanding > 0 {
            return FeedbackOutcome::Inconclusive {
                reason: format!(
                    "the window elapsed with {} check(s) still running — nothing has objected yet, \
                     but not everything has reported",
                    self.outstanding
                ),
            };
        }
        if self.saw_failure {
            return FeedbackOutcome::Inconclusive {
                reason: format!(
                    "the window elapsed with no feedback, but at least one poll failed ({}) — \
                     silence here is unverified, not observed",
                    self.last_error.as_deref().unwrap_or("unknown error")
                ),
            };
        }
        FeedbackOutcome::Quiet
    }

    fn backoff(&mut self) -> Watch {
        let delay = self.policy.delay_for(self.attempt);
        self.attempt += 1;
        self.elapsed = self.elapsed.saturating_add(delay);
        Watch::WaitFor(delay)
    }
}

/// Turns a settled batch into a verdict.
fn classify(items: Vec<FeedbackItem>) -> FeedbackOutcome {
    if items.iter().any(FeedbackItem::is_actionable) {
        return FeedbackOutcome::NewFeedback { items };
    }
    FeedbackOutcome::BotAllClear { items }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(id: &str, bot: bool, verdict: ItemVerdict) -> FeedbackItem {
        FeedbackItem {
            id: id.to_string(),
            source: FeedbackSource::CheckRun,
            author: if bot {
                "ci[bot]".to_string()
            } else {
                "a-human".to_string()
            },
            body: "something".to_string(),
            bot,
            verdict,
        }
    }

    fn fast_policy() -> WatchPolicy {
        WatchPolicy {
            first_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(4),
            window: Duration::from_secs(3),
            settle: Duration::from_secs(1),
            max_failures: 2,
        }
    }

    fn watch() -> FeedbackWatch {
        FeedbackWatch::new(fast_policy(), TriageLedger::default())
    }

    #[test]
    fn the_backoff_doubles_and_then_caps() {
        let policy = fast_policy();
        assert_eq!(policy.delay_for(0), Duration::from_secs(1));
        assert_eq!(policy.delay_for(1), Duration::from_secs(2));
        assert_eq!(policy.delay_for(2), Duration::from_secs(4));
        assert_eq!(
            policy.delay_for(9),
            Duration::from_secs(4),
            "capped at max_delay"
        );
    }

    #[test]
    fn an_observed_silence_that_outlasts_the_window_is_quiet() {
        let mut watch = watch();
        assert_eq!(
            watch.observe(Poll::observed(vec![])),
            Watch::WaitFor(Duration::from_secs(1))
        );
        assert_eq!(
            watch.observe(Poll::observed(vec![])),
            Watch::WaitFor(Duration::from_secs(2))
        );
        assert_eq!(
            watch.observe(Poll::observed(vec![])),
            Watch::Settled(FeedbackOutcome::Quiet)
        );
    }

    #[test]
    fn silence_after_a_failed_poll_is_inconclusive_not_quiet() {
        let mut watch = watch();
        watch.observe(Poll::Unavailable("502 from the API".into()));
        watch.observe(Poll::observed(vec![]));
        let Watch::Settled(outcome) = watch.observe(Poll::observed(vec![])) else {
            panic!("the window should have elapsed");
        };
        let FeedbackOutcome::Inconclusive { reason } = &outcome else {
            panic!("unverified silence must not report as quiet, got {outcome:?}");
        };
        assert!(reason.contains("502"));
        assert_eq!(
            outcome.exit_code(),
            1,
            "inconclusive must not exit like a clean run"
        );
    }

    #[test]
    fn silence_with_a_check_still_running_is_inconclusive_not_quiet() {
        let mut watch = watch();
        watch.observe(Poll::Observed {
            items: vec![],
            outstanding: 1,
        });
        watch.observe(Poll::Observed {
            items: vec![],
            outstanding: 1,
        });
        let Watch::Settled(FeedbackOutcome::Inconclusive { reason }) =
            watch.observe(Poll::Observed {
                items: vec![],
                outstanding: 1,
            })
        else {
            panic!("a window that ends mid-CI has not observed silence");
        };
        assert!(reason.contains("still running"), "{reason}");
    }

    #[test]
    fn a_check_that_finishes_before_the_window_ends_restores_a_quiet_verdict() {
        let mut watch = watch();
        watch.observe(Poll::Observed {
            items: vec![],
            outstanding: 1,
        });
        watch.observe(Poll::observed(vec![]));
        assert_eq!(
            watch.observe(Poll::observed(vec![])),
            Watch::Settled(FeedbackOutcome::Quiet)
        );
    }

    #[test]
    fn quiet_and_inconclusive_do_not_share_an_exit_code() {
        assert_ne!(
            FeedbackOutcome::Quiet.exit_code(),
            FeedbackOutcome::Inconclusive { reason: "x".into() }.exit_code()
        );
    }

    #[test]
    fn consecutive_failures_give_up_as_inconclusive() {
        let mut watch = watch();
        assert!(matches!(
            watch.observe(Poll::Unavailable("timeout".into())),
            Watch::WaitFor(_)
        ));
        let Watch::Settled(FeedbackOutcome::Inconclusive { reason }) =
            watch.observe(Poll::Unavailable("timeout".into()))
        else {
            panic!("two failures with max_failures = 2 must give up");
        };
        assert!(reason.contains("timeout"));
    }

    #[test]
    fn a_successful_poll_resets_the_consecutive_failure_streak() {
        let mut watch = watch();
        watch.observe(Poll::Unavailable("timeout".into()));
        watch.observe(Poll::observed(vec![]));
        // Would be the second consecutive failure if the streak had not been
        // reset — and must not end the watch.
        assert!(matches!(
            watch.observe(Poll::Unavailable("timeout".into())),
            Watch::WaitFor(_)
        ));
    }

    #[test]
    fn a_batch_arriving_in_pieces_is_reported_once() {
        let mut watch = watch();
        assert_eq!(
            watch.observe(Poll::observed(vec![item("1", false, ItemVerdict::Neutral)])),
            Watch::WaitFor(Duration::from_secs(1)),
            "the first item opens the settle window rather than reporting immediately"
        );
        let second = watch.observe(Poll::observed(vec![
            item("1", false, ItemVerdict::Neutral),
            item("2", false, ItemVerdict::Neutral),
        ]));
        assert!(
            matches!(second, Watch::WaitFor(_)),
            "a second item extends the settle window"
        );
        let Watch::Settled(FeedbackOutcome::NewFeedback { items }) =
            watch.observe(Poll::observed(vec![
                item("1", false, ItemVerdict::Neutral),
                item("2", false, ItemVerdict::Neutral),
            ]))
        else {
            panic!("a settled batch must report");
        };
        assert_eq!(items.len(), 2, "one batch, one report");
    }

    #[test]
    fn an_item_already_in_the_ledger_is_not_re_reported() {
        let ledger = TriageLedger::from_ids(["1".to_string()]);
        let mut watch = FeedbackWatch::new(fast_policy(), ledger);
        assert_eq!(
            watch.observe(Poll::observed(vec![item("1", false, ItemVerdict::Neutral)])),
            Watch::WaitFor(Duration::from_secs(1)),
            "a previously-triaged item is silence, not news"
        );
    }

    #[test]
    fn the_ledger_records_what_the_watch_reported() {
        let mut watch = watch();
        watch.observe(Poll::observed(vec![item(
            "42",
            false,
            ItemVerdict::Neutral,
        )]));
        assert!(watch.ledger().contains("42"));
        assert_eq!(watch.ledger().ids().collect::<Vec<_>>(), vec!["42"]);
    }

    #[test]
    fn the_ledger_reports_whether_an_id_was_new() {
        let mut ledger = TriageLedger::default();
        assert!(ledger.record("1"));
        assert!(!ledger.record("1"));
    }

    #[test]
    fn only_clean_bot_reports_settle_as_an_all_clear() {
        let mut watch = watch();
        watch.observe(Poll::observed(vec![item("ci-1", true, ItemVerdict::Clean)]));
        let Watch::Settled(outcome) =
            watch.observe(Poll::observed(vec![item("ci-1", true, ItemVerdict::Clean)]))
        else {
            panic!("the settle window should have closed");
        };
        assert!(
            matches!(outcome, FeedbackOutcome::BotAllClear { .. }),
            "got {outcome:?}"
        );
        assert_eq!(outcome.exit_code(), 0);
    }

    #[test]
    fn a_failing_bot_check_is_new_feedback_not_an_all_clear() {
        let mut watch = watch();
        watch.observe(Poll::observed(vec![item(
            "ci-1",
            true,
            ItemVerdict::NeedsWork,
        )]));
        let Watch::Settled(outcome) = watch.observe(Poll::observed(vec![item(
            "ci-1",
            true,
            ItemVerdict::NeedsWork,
        )])) else {
            panic!("the settle window should have closed");
        };
        assert!(
            matches!(outcome, FeedbackOutcome::NewFeedback { .. }),
            "got {outcome:?}"
        );
        assert_eq!(outcome.exit_code(), 3);
    }

    #[test]
    fn a_human_comment_is_always_actionable_even_with_no_verdict() {
        assert!(item("1", false, ItemVerdict::Neutral).is_actionable());
        assert!(!item("1", true, ItemVerdict::Neutral).is_actionable());
        assert!(item("1", true, ItemVerdict::NeedsWork).is_actionable());
    }

    #[test]
    fn every_outcome_describes_itself() {
        let items = vec![item("1", false, ItemVerdict::Neutral)];
        assert!(FeedbackOutcome::Quiet.describe().contains("quiet"));
        assert!(
            FeedbackOutcome::BotAllClear {
                items: items.clone()
            }
            .describe()
            .contains("all-clear")
        );
        assert!(
            FeedbackOutcome::NewFeedback { items }
                .describe()
                .contains("a-human")
        );
        assert!(
            FeedbackOutcome::Inconclusive {
                reason: "boom".into()
            }
            .describe()
            .contains("boom")
        );
    }

    #[test]
    fn each_source_renders_its_own_kind() {
        for (source, expected) in [
            (FeedbackSource::ReviewComment, "review comment"),
            (FeedbackSource::IssueComment, "comment"),
            (FeedbackSource::Review, "review"),
            (FeedbackSource::CheckRun, "check"),
        ] {
            let rendered = FeedbackItem {
                source,
                ..item("1", false, ItemVerdict::Neutral)
            }
            .describe();
            assert!(
                rendered.starts_with(expected),
                "{rendered} should start with {expected}"
            );
        }
    }

    #[test]
    fn the_watch_counts_the_delays_it_handed_out() {
        let mut watch = watch();
        watch.observe(Poll::observed(vec![]));
        watch.observe(Poll::observed(vec![]));
        assert_eq!(watch.elapsed(), Duration::from_secs(3));
    }
}
