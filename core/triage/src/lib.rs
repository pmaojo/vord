//! The Issue Triage Factory's label state machine (roadmap C — see
//! `docs/design/issue-triage-factory.md`). Inspired by Cloudflare/Astro's
//! `triagebot-action`: a GitHub issue moves through reproduce → diagnose →
//! fix, one worker role per stage, a label naming the current stage.
//!
//! Where this differs from that inspiration — and the reason this state
//! machine exists as its own crate rather than living inline in
//! `infra/github` — is what is allowed to *drive* a transition.
//! [`TriageEvent`] never carries a model's opinion of its own work, only
//! facts a runtime can observe without asking an LLM: whether a regression
//! test failed, whether a diagnosis is grounded in a real `vord scan`
//! finding, whether `core/remediation`'s verify-before-suggest loop
//! accepted or rejected a fix. `core/agent/src/prompt.rs` states the same
//! rule for `vord agent`'s own completion; this is that rule applied to
//! issue triage.
//!
//! Pure by construction, like every other `core/` crate: no fetches, no
//! label writes, no clock. [`next_triage_state`] only computes what the
//! next label *should* be given the current one and an event; reading and
//! writing the label on the actual GitHub issue is I/O and belongs in
//! `infra/github`, the same split `core/swarm` draws for worktrees and
//! handoffs.
//!
//! The design doc's "how does Reproduce actually run a test suite" question
//! turned out not to need a new port at all: `vord_agent::runtime::Workspace`
//! (implemented by `infra/fs::RepoWorkspace`) already sandboxes a command
//! with a wall-clock timeout and reports back a `CommandOutput` — the exact
//! shape `vord agent`'s own `run` tool uses. Reproduce is a new *caller* of
//! that `run`, not a new adapter. [`repro_event_from_exit_code`] is the pure
//! sliver of judgement this crate needs to consume its result: this crate
//! stays free of a `vord-agent` dependency by taking the bare `Option<i32>`
//! rather than the `CommandOutput` type itself.

use std::fmt;

/// One stage of the triage pipeline, encoded as a GitHub label
/// (`as_label`/`from_label` round-trip it to and from the wire string
/// `infra/github` reads off the issue).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TriageLabel {
    /// Just opened; no worker has touched it yet.
    New,
    /// The Reproducer role is writing a regression test in a sandbox.
    Reproducing,
    /// The regression test fails — a real repro exists. Ready to diagnose.
    Reproduced,
    /// The regression test passed, or none could be written — the issue
    /// needs a human, not another worker.
    NeedsInfo,
    /// The Diagnostician role is mapping the repro to a root cause.
    Diagnosing,
    /// A diagnosis exists. Ready to fix.
    Diagnosed,
    /// The Fixer role is running `core/remediation`'s
    /// verify-before-suggest loop against the repro test.
    Fixing,
    /// The fix's regression test went green and the re-scan introduced no
    /// new or regressed findings. A PR is ready to open.
    FixReady,
    /// A fix attempt failed verification (test still red, or the re-scan
    /// or `core/agent-policy` rejected it). Eligible for another attempt —
    /// how many attempts is the caller's budget to enforce, not this
    /// crate's, the same split `core/agent::budget` draws for `vord agent`.
    GateRejected,
}

impl TriageLabel {
    pub const ALL: [TriageLabel; 9] = [
        TriageLabel::New,
        TriageLabel::Reproducing,
        TriageLabel::Reproduced,
        TriageLabel::NeedsInfo,
        TriageLabel::Diagnosing,
        TriageLabel::Diagnosed,
        TriageLabel::Fixing,
        TriageLabel::FixReady,
        TriageLabel::GateRejected,
    ];

    /// The GitHub label name this stage is written and read as.
    pub fn as_label(self) -> &'static str {
        match self {
            TriageLabel::New => "triage:new",
            TriageLabel::Reproducing => "triage:reproducing",
            TriageLabel::Reproduced => "triage:reproduced",
            TriageLabel::NeedsInfo => "triage:needs-info",
            TriageLabel::Diagnosing => "triage:diagnosing",
            TriageLabel::Diagnosed => "triage:diagnosed",
            TriageLabel::Fixing => "triage:fixing",
            TriageLabel::FixReady => "triage:fix-ready",
            TriageLabel::GateRejected => "triage:gate-rejected",
        }
    }

    /// Parses a GitHub label name back into a stage. `None` for any label
    /// that isn't one of this crate's own — an issue carries plenty of
    /// labels this state machine doesn't own, and it must ignore them
    /// rather than error on them.
    pub fn from_label(label: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|stage| stage.as_label() == label)
    }

    /// The `core/swarm` role name that runs during this stage, or `None`
    /// for a stage no worker is active in (waiting for `Start`, or
    /// terminal). Matches the `TRIAGE_PACK` topology role names —
    /// `docs/design/issue-triage-factory.md`'s `[Reproducer, Diagnostician,
    /// Fixer]` — without this crate depending on `vord-swarm` for it.
    pub fn active_role(self) -> Option<&'static str> {
        match self {
            TriageLabel::Reproducing => Some("reproducer"),
            TriageLabel::Diagnosing => Some("diagnostician"),
            TriageLabel::Fixing => Some("fixer"),
            _ => None,
        }
    }

    /// `true` once the pipeline has nothing left to do on its own — a
    /// human is needed ([`TriageLabel::NeedsInfo`]) or a PR is already
    /// open and waiting on ordinary PR review ([`TriageLabel::FixReady`]).
    pub fn is_terminal(self) -> bool {
        matches!(self, TriageLabel::NeedsInfo | TriageLabel::FixReady)
    }
}

impl fmt::Display for TriageLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_label())
    }
}

/// The outcome `core/remediation`'s verify-before-suggest loop reached for
/// one fix attempt. Deliberately not `vord_remediation::RemediationVerdict`
/// itself — this crate stays dependency-free of `core/remediation`, the
/// same reason `core/agent-policy::Finding` stays independent of
/// `vord_rules_engine::Issue`: a caller maps its own verdict type onto this
/// one at the boundary instead of this crate learning the engine's domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FixVerdict {
    Accepted,
    Rejected,
}

/// A fact a runtime observed, offered to the state machine as the reason to
/// advance. Every variant is something a re-scan, a test run, or the
/// remediation engine decided — never a model's self-report.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TriageEvent {
    /// The runner is beginning the stage that follows `current` — spinning
    /// up the next role's worktree. Carries no payload because starting a
    /// stage is a scheduling fact, not an observation about the issue.
    Start,
    /// The Reproducer's regression test finished running in the sandbox.
    /// `test_failed: true` is a real repro; `false` means the described
    /// bug did not reproduce.
    ReproAttempted { test_failed: bool },
    /// The Diagnostician finished. `grounded_in_finding` records whether
    /// the diagnosis matched an existing `vord scan` `Issue` on the
    /// touched span — informational for now (see the design doc's open
    /// question on turning an ungrounded diagnosis into a rule-candidate
    /// signal); it does not change which label comes next.
    DiagnosisAttempted { grounded_in_finding: bool },
    /// The Fixer's attempt went through `core/remediation`'s
    /// verify-before-suggest loop.
    FixAttempted { verdict: FixVerdict },
}

/// Classifies a sandboxed regression-test run into the
/// [`TriageEvent::ReproAttempted`] this crate accepts. `exit_code` is the
/// same `Option<i32>` `vord_agent::runtime::CommandOutput` carries: `Some(0)`
/// is a clean pass (no repro — the described bug did not happen), any other
/// `Some(code)` is a failing test (a real repro), and `None` — a process
/// killed by a signal rather than exiting — counts as a repro too: a crash
/// is still evidence the bug is real, not silence to read as a pass.
pub fn repro_event_from_exit_code(exit_code: Option<i32>) -> TriageEvent {
    let test_failed = exit_code != Some(0);
    TriageEvent::ReproAttempted { test_failed }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("no transition from {from} on {event:?}")]
pub struct InvalidTransition {
    from: TriageLabel,
    event: TriageEvent,
}

/// The one decision this crate exists to make: given the stage an issue is
/// currently labeled with and a fact a runtime observed, which stage should
/// it be labeled with next. An event that doesn't apply to `current` (a
/// `FixAttempted` arriving while the issue is still `Reproducing`, say) is
/// rejected rather than silently ignored or guessed at — the caller has a
/// bug if that happens, and this function is where it surfaces.
///
/// Delegates one match arm per event kind rather than one flat match over
/// every `(state, event)` pair — the flat version reads fine but its
/// cyclomatic complexity trips `smells:high-complexity` (vord judging its
/// own crate, as intended). Splitting by event keeps each helper below the
/// same threshold it must satisfy for anyone else's code.
pub fn next_triage_state(
    current: TriageLabel,
    event: TriageEvent,
) -> Result<TriageLabel, InvalidTransition> {
    let next = match event {
        TriageEvent::Start => start_next_stage(current),
        TriageEvent::ReproAttempted { test_failed } => repro_outcome(current, test_failed),
        TriageEvent::DiagnosisAttempted { .. } => diagnosis_outcome(current),
        TriageEvent::FixAttempted { verdict } => fix_outcome(current, verdict),
    };
    next.ok_or(InvalidTransition {
        from: current,
        event,
    })
}

/// `TriageEvent::Start`: the runner is beginning the stage that follows a
/// wait state. Every other stage is mid-flight, waiting on an outcome
/// event instead, so `Start` has no effect there.
fn start_next_stage(current: TriageLabel) -> Option<TriageLabel> {
    use TriageLabel::*;
    match current {
        New => Some(Reproducing),
        Reproduced => Some(Diagnosing),
        Diagnosed => Some(Fixing),
        // Eligible for another attempt — the caller's budget decides how
        // many, this crate just allows the retry.
        GateRejected => Some(Fixing),
        _ => None,
    }
}

fn repro_outcome(current: TriageLabel, test_failed: bool) -> Option<TriageLabel> {
    if current != TriageLabel::Reproducing {
        return None;
    }
    Some(if test_failed {
        TriageLabel::Reproduced
    } else {
        TriageLabel::NeedsInfo
    })
}

fn diagnosis_outcome(current: TriageLabel) -> Option<TriageLabel> {
    (current == TriageLabel::Diagnosing).then_some(TriageLabel::Diagnosed)
}

fn fix_outcome(current: TriageLabel, verdict: FixVerdict) -> Option<TriageLabel> {
    if current != TriageLabel::Fixing {
        return None;
    }
    Some(match verdict {
        FixVerdict::Accepted => TriageLabel::FixReady,
        FixVerdict::Rejected => TriageLabel::GateRejected,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_issue_starts_reproducing() {
        assert_eq!(
            next_triage_state(TriageLabel::New, TriageEvent::Start),
            Ok(TriageLabel::Reproducing)
        );
    }

    #[test]
    fn a_failing_regression_test_is_a_real_repro() {
        assert_eq!(
            next_triage_state(
                TriageLabel::Reproducing,
                TriageEvent::ReproAttempted { test_failed: true }
            ),
            Ok(TriageLabel::Reproduced)
        );
    }

    #[test]
    fn a_passing_regression_test_means_no_repro_and_routes_to_a_human() {
        assert_eq!(
            next_triage_state(
                TriageLabel::Reproducing,
                TriageEvent::ReproAttempted { test_failed: false }
            ),
            Ok(TriageLabel::NeedsInfo)
        );
    }

    #[test]
    fn reproduced_advances_to_diagnosing_on_start() {
        assert_eq!(
            next_triage_state(TriageLabel::Reproduced, TriageEvent::Start),
            Ok(TriageLabel::Diagnosing)
        );
    }

    #[test]
    fn diagnosing_advances_to_diagnosed_whether_or_not_it_is_grounded_in_a_finding() {
        assert_eq!(
            next_triage_state(
                TriageLabel::Diagnosing,
                TriageEvent::DiagnosisAttempted {
                    grounded_in_finding: true
                }
            ),
            Ok(TriageLabel::Diagnosed)
        );
        assert_eq!(
            next_triage_state(
                TriageLabel::Diagnosing,
                TriageEvent::DiagnosisAttempted {
                    grounded_in_finding: false
                }
            ),
            Ok(TriageLabel::Diagnosed)
        );
    }

    #[test]
    fn diagnosed_advances_to_fixing_on_start() {
        assert_eq!(
            next_triage_state(TriageLabel::Diagnosed, TriageEvent::Start),
            Ok(TriageLabel::Fixing)
        );
    }

    #[test]
    fn an_accepted_fix_is_ready_for_a_pr() {
        assert_eq!(
            next_triage_state(
                TriageLabel::Fixing,
                TriageEvent::FixAttempted {
                    verdict: FixVerdict::Accepted
                }
            ),
            Ok(TriageLabel::FixReady)
        );
    }

    #[test]
    fn a_rejected_fix_does_not_open_a_pr() {
        assert_eq!(
            next_triage_state(
                TriageLabel::Fixing,
                TriageEvent::FixAttempted {
                    verdict: FixVerdict::Rejected
                }
            ),
            Ok(TriageLabel::GateRejected)
        );
    }

    #[test]
    fn a_gate_rejected_fix_can_retry() {
        assert_eq!(
            next_triage_state(TriageLabel::GateRejected, TriageEvent::Start),
            Ok(TriageLabel::Fixing)
        );
    }

    #[test]
    fn terminal_states_accept_no_further_transition() {
        assert!(next_triage_state(TriageLabel::NeedsInfo, TriageEvent::Start).is_err());
        assert!(next_triage_state(TriageLabel::FixReady, TriageEvent::Start).is_err());
    }

    #[test]
    fn an_event_that_does_not_apply_to_the_current_stage_is_rejected_not_guessed_at() {
        let err = next_triage_state(
            TriageLabel::New,
            TriageEvent::FixAttempted {
                verdict: FixVerdict::Accepted,
            },
        )
        .unwrap_err();
        assert_eq!(err.from, TriageLabel::New);
    }

    #[test]
    fn every_label_round_trips_through_its_wire_string() {
        for stage in TriageLabel::ALL {
            assert_eq!(TriageLabel::from_label(stage.as_label()), Some(stage));
        }
    }

    #[test]
    fn a_label_this_crate_does_not_own_does_not_parse() {
        assert_eq!(TriageLabel::from_label("bug"), None);
        assert_eq!(TriageLabel::from_label("triage:unknown"), None);
    }

    #[test]
    fn only_the_three_worker_stages_have_an_active_role() {
        assert_eq!(TriageLabel::Reproducing.active_role(), Some("reproducer"));
        assert_eq!(TriageLabel::Diagnosing.active_role(), Some("diagnostician"));
        assert_eq!(TriageLabel::Fixing.active_role(), Some("fixer"));

        for stage in TriageLabel::ALL {
            if !matches!(
                stage,
                TriageLabel::Reproducing | TriageLabel::Diagnosing | TriageLabel::Fixing
            ) {
                assert_eq!(stage.active_role(), None, "{stage} should have no role");
            }
        }
    }

    #[test]
    fn only_needs_info_and_fix_ready_are_terminal() {
        for stage in TriageLabel::ALL {
            let expected = matches!(stage, TriageLabel::NeedsInfo | TriageLabel::FixReady);
            assert_eq!(stage.is_terminal(), expected, "{stage}");
        }
    }

    #[test]
    fn a_clean_exit_means_no_repro() {
        assert_eq!(
            repro_event_from_exit_code(Some(0)),
            TriageEvent::ReproAttempted { test_failed: false }
        );
    }

    #[test]
    fn a_nonzero_exit_is_a_real_repro() {
        assert_eq!(
            repro_event_from_exit_code(Some(1)),
            TriageEvent::ReproAttempted { test_failed: true }
        );
        assert_eq!(
            repro_event_from_exit_code(Some(101)),
            TriageEvent::ReproAttempted { test_failed: true }
        );
    }

    #[test]
    fn a_process_killed_by_a_signal_counts_as_a_repro_not_a_silent_pass() {
        assert_eq!(
            repro_event_from_exit_code(None),
            TriageEvent::ReproAttempted { test_failed: true }
        );
    }

    #[test]
    fn the_classified_event_feeds_reproducing_the_same_as_any_other_repro_attempt() {
        let event = repro_event_from_exit_code(Some(1));
        assert_eq!(
            next_triage_state(TriageLabel::Reproducing, event),
            Ok(TriageLabel::Reproduced)
        );
    }
}
