//! Policy as the referee, in-process (roadmap A2).
//!
//! `yunq hook` pays a process start per write because a third-party host has
//! no other way in. This runtime has no such excuse: the same
//! `AgentPolicy::evaluate` runs between the model proposing bytes and the
//! `write` syscall, in the same process, against the same
//! `yunq-policy.toml`. The evaluation itself is `yunq-agent-policy`'s job and
//! is not re-implemented here — what lives in this module is the *wording* of
//! the refusal handed back to the model, and the shape of the stop.
//!
//! The wording matters as much as the verdict. A model told "that didn't work"
//! retries the identical write; a model told "this write did not reach disk,
//! here is the rule, here is the line" fixes it or asks. Every line of the
//! text below is built from [`yunq_agent_policy::Violation::describe`], so the
//! agent reads exactly the sentences the guardrail already gives Claude Code
//! — one policy, one vocabulary.

use yunq_agent_policy::Evaluation;
use yunq_profiles::RuleId;

/// The refusal, as the agent reads it.
pub fn denial_feedback(path: &str, evaluation: &Evaluation) -> String {
    let mut out = format!(
        "yunq policy DENIED this write to `{path}`. Nothing was written — the file on disk is unchanged.\n\n"
    );
    for (index, violation) in evaluation.denials().enumerate() {
        out.push_str(&format!("  {}. {}\n", index + 1, violation.describe()));
    }
    out.push_str(
        "\nFix the cause and write again. Do not retry the identical content, and do not work \
         around the policy by moving the same code to another path.",
    );
    out
}

/// The note appended to an *allowed* write that still had something to say.
/// Empty when there is nothing — an advisory-only policy should not append a
/// blank section to every successful write.
pub fn advisory_note(evaluation: &Evaluation) -> String {
    let mut warnings = evaluation.warnings().peekable();
    if warnings.peek().is_none() {
        return String::new();
    }
    let mut out = String::from("\n\nyunq allowed this write with advisories:\n");
    for violation in warnings {
        out.push_str(&format!("  - {}\n", violation.describe()));
    }
    out
}

/// The message for a run that stopped because the circuit breaker tripped:
/// the same rule denied the agent three times running, so it is relitigating
/// something it cannot fix rather than making progress.
pub fn circuit_breaker_stop(rules: &[RuleId]) -> String {
    let names: Vec<String> = rules.iter().map(RuleId::to_string).collect();
    format!(
        "circuit breaker tripped on {} — the agent could not resolve it in {} consecutive attempts. \
         Review the denial, then clear the breaker before running again.",
        names.join(", "),
        yunq_agent_policy::CircuitBreakerState::TRIP_THRESHOLD
    )
}

#[cfg(test)]
mod tests {
    use yunq_agent_policy::{AgentPolicy, Finding};
    use yunq_profiles::Severity;

    use super::*;

    fn finding(rule_id: &str, severity: Severity) -> Finding {
        Finding {
            rule: RuleId::new(rule_id).expect("valid rule id"),
            severity,
            message: "shell out to /bin/sh".to_string(),
            line: 12,
        }
    }

    #[test]
    fn a_denial_states_plainly_that_nothing_was_written() {
        let policy = AgentPolicy::default();
        let evaluation = policy.evaluate("src/a.rs", &[finding("owasp:eval-usage", Severity::Info)]);
        let text = denial_feedback("src/a.rs", &evaluation);
        assert!(text.contains("DENIED"));
        assert!(text.contains("the file on disk is unchanged"));
        assert!(text.contains("owasp:eval-usage"));
        assert!(text.contains("line 12"));
    }

    #[test]
    fn a_denial_tells_the_agent_not_to_retry_the_same_bytes() {
        let policy = AgentPolicy::default();
        let evaluation = policy.evaluate("src/a.rs", &[finding("owasp:eval-usage", Severity::Info)]);
        assert!(denial_feedback("src/a.rs", &evaluation).contains("Do not retry the identical content"));
    }

    #[test]
    fn a_denial_enumerates_every_violation() {
        let policy = AgentPolicy::default();
        let evaluation = policy.evaluate(
            "src/a.rs",
            &[finding("owasp:eval-usage", Severity::Info), finding("owasp:command-execution", Severity::Info)],
        );
        let text = denial_feedback("src/a.rs", &evaluation);
        assert!(text.contains("  1. "));
        assert!(text.contains("  2. "));
    }

    #[test]
    fn a_clean_evaluation_produces_no_advisory_note() {
        assert_eq!(advisory_note(&Evaluation::default()), "");
    }

    #[test]
    fn an_advisory_violation_is_reported_without_denying() {
        let policy = AgentPolicy::parse("[agent]\nadvisory_rules = [\"owasp:eval-usage\"]\n").expect("parses");
        let evaluation = policy.evaluate("src/a.rs", &[finding("owasp:eval-usage", Severity::Blocker)]);
        assert!(!evaluation.is_denied());
        let note = advisory_note(&evaluation);
        assert!(note.contains("advisories"));
        assert!(note.contains("owasp:eval-usage"));
    }

    #[test]
    fn the_circuit_breaker_stop_names_the_rule_and_the_threshold() {
        let rules = vec![RuleId::new("owasp:xss").unwrap()];
        let text = circuit_breaker_stop(&rules);
        assert!(text.contains("owasp:xss"));
        assert!(text.contains('3'), "the operator needs the attempt count: {text}");
    }
}
