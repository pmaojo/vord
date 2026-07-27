//! Agent Permission Policy — the rules that decide whether an autonomous
//! coding agent is allowed to write a given file.
//!
//! This is deliberately *not* the quality gate. The gate answers "is this
//! project healthy enough to release?" over a whole analysis; this answers
//! "may this one write land?" over a single proposed file edit, in the
//! milliseconds an agent spends between deciding to write and writing. The
//! two disagree on purpose: a policy can hard-deny a rule the profile only
//! scores as `Major` (an agent touching auth code is categorically different
//! from a human doing it under review), and can deny on path alone with no
//! finding at all.
//!
//! Pure by construction: no file reads, no clock, no environment. The caller
//! supplies the already-parsed policy text, the target path and the findings;
//! everything here is a deterministic function of those three.

use std::collections::{HashMap, HashSet};

use globset::{Glob, GlobSet, GlobSetBuilder};
use serde::Deserialize;
use yunq_profiles::{RuleId, Severity};

/// A finding handed to the policy for judgement.
///
/// Intentionally not `yunq_rules_engine::Issue`: keeping this crate's
/// dependency surface at `yunq-profiles` alone means a policy can equally
/// judge findings that never came from the engine (an imported SARIF result,
/// a future remote-analysis response) without this crate learning about the
/// engine's whole domain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    pub rule: RuleId,
    pub severity: Severity,
    pub message: String,
    pub line: u32,
}

/// Why the policy denied (or flagged) a write.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Cause {
    /// The target path itself is off-limits to agents — no finding needed.
    ProtectedPath { pattern: String, reason: String },
    /// A rule listed in `blocking_rules`, whatever severity it carries.
    BlockingRule,
    /// A finding at or above `block_at_or_above`.
    SeverityThreshold { threshold: Severity },
}

/// Whether a violation stops the write or merely annotates it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Enforcement {
    Deny,
    Warn,
}

/// One reason the policy has something to say about a proposed write.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Violation {
    pub enforcement: Enforcement,
    pub cause: Cause,
    /// Absent for a `ProtectedPath` violation, which has no finding behind it.
    pub finding: Option<Finding>,
}

impl Violation {
    /// One agent-readable line. Kept here rather than in the caller because
    /// the wording is the policy's contract with the agent — the text an
    /// agent reads and acts on is as much a part of this crate's behaviour
    /// as the allow/deny bit, and is unit-tested as such.
    pub fn describe(&self) -> String {
        match (&self.cause, &self.finding) {
            (Cause::ProtectedPath { pattern, reason }, _) => {
                format!("protected path (matches `{pattern}`) — {reason}")
            }
            (Cause::BlockingRule, Some(f)) => {
                format!("{} at line {} — {} [hard-blocked for agents]", f.rule, f.line, f.message)
            }
            (Cause::SeverityThreshold { threshold }, Some(f)) => {
                format!("{} ({}) at line {} — {} [at/above {threshold}]", f.rule, f.severity, f.line, f.message)
            }
            // A rule/threshold cause always carries the finding that caused
            // it; this arm exists only to keep `describe` total.
            (_, None) => "policy violation".to_string(),
        }
    }
}

/// The verdict on one proposed write.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Evaluation {
    pub violations: Vec<Violation>,
}

impl Evaluation {
    pub fn is_denied(&self) -> bool {
        self.violations.iter().any(|v| v.enforcement == Enforcement::Deny)
    }

    pub fn denials(&self) -> impl Iterator<Item = &Violation> {
        self.violations.iter().filter(|v| v.enforcement == Enforcement::Deny)
    }

    pub fn warnings(&self) -> impl Iterator<Item = &Violation> {
        self.violations.iter().filter(|v| v.enforcement == Enforcement::Warn)
    }

    pub fn is_empty(&self) -> bool {
        self.violations.is_empty()
    }
}

/// How many times in a row the same rule has denied an agent's write.
///
/// Distinguishes a real, fixable finding — which usually clears within a retry or two — from an
/// agent stuck relitigating a false positive or a vulnerability it cannot resolve, which would
/// otherwise burn the agent's tokens (and the human's patience) indefinitely. Each `yunq hook`
/// invocation is a fresh process, so this type only knows how to fold one evaluation into a
/// running count; persisting that count between invocations is the caller's concern (see
/// `bin/cli`'s circuit-breaker store), which is why this stays as I/O-free as the rest of the crate.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CircuitBreakerState {
    consecutive_denials: HashMap<RuleId, u32>,
}

impl CircuitBreakerState {
    /// Denied three times in a row trips the breaker. Low enough to catch a stuck loop before it
    /// does real damage to the token budget, high enough that an agent correcting a genuine
    /// mistake on the second try never sees it.
    pub const TRIP_THRESHOLD: u32 = 3;

    /// Rebuilds state from a caller-supplied snapshot (e.g. deserialized from a state file). Not
    /// `Deserialize` itself: the wire format is the caller's DTO to own, per this crate's
    /// domain-types-stay-serde-free rule.
    pub fn from_counts(counts: impl IntoIterator<Item = (RuleId, u32)>) -> Self {
        Self { consecutive_denials: counts.into_iter().collect() }
    }

    /// Every rule with a nonzero streak, for the caller to persist.
    pub fn counts(&self) -> impl Iterator<Item = (&RuleId, u32)> {
        self.consecutive_denials.iter().map(|(rule, count)| (rule, *count))
    }

    pub fn count_for(&self, rule: &RuleId) -> u32 {
        self.consecutive_denials.get(rule).copied().unwrap_or(0)
    }

    pub fn is_tripped(&self, rule: &RuleId) -> bool {
        self.count_for(rule) >= Self::TRIP_THRESHOLD
    }

    /// Folds one write's outcome into the running counts and reports which rules just tripped
    /// (reached the threshold on this call).
    ///
    /// A rule not denied this round resets to zero rather than merely pausing — "consecutive"
    /// means uninterrupted, so a rule the agent stops triggering (whether by fixing it, or by
    /// moving on to something else entirely) stops counting. A `ProtectedPath` denial carries no
    /// rule and never participates: there is no finding a retry could fix, so there is nothing for
    /// a circuit breaker to track.
    pub fn record(&mut self, evaluation: &Evaluation) -> Vec<RuleId> {
        let denied_rules: HashSet<RuleId> =
            evaluation.denials().filter_map(|violation| violation.finding.as_ref().map(|f| f.rule.clone())).collect();

        self.consecutive_denials.retain(|rule, _| denied_rules.contains(rule));

        let mut tripped = Vec::new();
        for rule in &denied_rules {
            let count = self.consecutive_denials.entry(rule.clone()).or_insert(0);
            *count += 1;
            if *count >= Self::TRIP_THRESHOLD {
                tripped.push(rule.clone());
            }
        }
        tripped
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("invalid policy TOML: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("invalid severity {0:?} (info|minor|major|critical|blocker)")]
    Severity(String),
    #[error("invalid rule id {0:?}")]
    RuleId(String),
    #[error("invalid path glob {pattern:?}: {source}")]
    Glob {
        pattern: String,
        #[source]
        source: globset::Error,
    },
}

/// The wire shape of `yunq-policy.toml`. Every field defaults to the same
/// value [`AgentPolicy::default`] uses, so an empty `[agent]` table and a
/// missing file describe the same policy — a present key is always an
/// override, never a reset.
#[derive(Debug, Deserialize)]
struct PolicyFile {
    #[serde(default)]
    agent: AgentSection,
    #[serde(default, rename = "protected_path")]
    protected_paths: Vec<ProtectedPathSection>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentSection {
    #[serde(default = "default_enabled")]
    enabled: bool,
    #[serde(default = "default_block_at_or_above")]
    block_at_or_above: String,
    #[serde(default = "default_blocking_rules")]
    blocking_rules: Vec<String>,
    #[serde(default)]
    advisory_rules: Vec<String>,
}

impl Default for AgentSection {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            block_at_or_above: default_block_at_or_above(),
            blocking_rules: default_blocking_rules(),
            advisory_rules: Vec::new(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProtectedPathSection {
    pattern: String,
    reason: String,
}

fn default_enabled() -> bool {
    true
}

fn default_block_at_or_above() -> String {
    "critical".to_string()
}

/// Rules an agent may never introduce, regardless of the severity the
/// active quality profile gives them. These are the categories where the
/// blast radius of an unsupervised write is disproportionate to the
/// severity score: code the model itself chose to execute, credentials, and
/// shell/eval sinks.
fn default_blocking_rules() -> Vec<String> {
    [
        "ai:llm-output-injection",
        "owasp:command-execution",
        "owasp:eval-usage",
        "python:subprocess-shell-true",
        "php:eval-usage",
        "php:command-execution",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

/// A compiled, ready-to-evaluate policy.
#[derive(Debug)]
pub struct AgentPolicy {
    enabled: bool,
    block_at_or_above: Severity,
    blocking_rules: Vec<RuleId>,
    advisory_rules: Vec<RuleId>,
    protected: GlobSet,
    /// Parallel to `protected`'s glob indices: the (pattern, reason) pair
    /// behind each, so a match can name the rule it broke.
    protected_meta: Vec<(String, String)>,
}

impl Default for AgentPolicy {
    /// The policy in force when a repository has no `yunq-policy.toml`:
    /// deny critical-and-above findings and the hard-blocked rule list, with
    /// **no** protected paths.
    ///
    /// Shipping path protection off-by-default is deliberate. A tool that
    /// silently refuses an agent's legitimate edit the moment it is
    /// installed gets uninstalled; path rules are the one part of this
    /// policy with no finding to justify themselves to the agent, so they
    /// stay opt-in. `yunq hook install` writes a policy file with concrete
    /// examples enabled and visible in the repository, which is where that
    /// choice belongs — in the user's own file, not in a default they
    /// cannot see.
    fn default() -> Self {
        Self::parse("").expect("the built-in default policy is valid")
    }
}

impl AgentPolicy {
    /// Parses `yunq-policy.toml`. An empty string yields the default policy.
    pub fn parse(raw: &str) -> Result<Self, PolicyError> {
        let file: PolicyFile = toml::from_str(raw)?;

        let block_at_or_above = Severity::parse(&file.agent.block_at_or_above)
            .ok_or_else(|| PolicyError::Severity(file.agent.block_at_or_above.clone()))?;

        let parse_rules = |raw: &[String]| -> Result<Vec<RuleId>, PolicyError> {
            raw.iter()
                .map(|r| RuleId::new(r).map_err(|_| PolicyError::RuleId(r.clone())))
                .collect()
        };

        let mut builder = GlobSetBuilder::new();
        let mut protected_meta = Vec::new();
        for entry in &file.protected_paths {
            let glob = Glob::new(&entry.pattern)
                .map_err(|source| PolicyError::Glob { pattern: entry.pattern.clone(), source })?;
            builder.add(glob);
            protected_meta.push((entry.pattern.clone(), entry.reason.clone()));
        }
        let protected = builder
            .build()
            .map_err(|source| PolicyError::Glob { pattern: "<set>".to_string(), source })?;

        Ok(Self {
            enabled: file.agent.enabled,
            block_at_or_above,
            blocking_rules: parse_rules(&file.agent.blocking_rules)?,
            advisory_rules: parse_rules(&file.agent.advisory_rules)?,
            protected,
            protected_meta,
        })
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn block_at_or_above(&self) -> Severity {
        self.block_at_or_above
    }

    /// Judges one proposed write. `path` is repository-relative, using
    /// forward slashes (backslashes are normalised, so a Windows-shaped path
    /// matches the same globs).
    ///
    /// A disabled policy returns no violations at all rather than
    /// downgrading them to warnings: `enabled = false` means "yunq is not in
    /// this agent's loop", and emitting advisory noise would contradict that.
    pub fn evaluate(&self, path: &str, findings: &[Finding]) -> Evaluation {
        if !self.enabled {
            return Evaluation::default();
        }

        let mut violations = Vec::new();

        let normalised = path.replace('\\', "/");
        for index in self.protected.matches(&normalised) {
            let (pattern, reason) = &self.protected_meta[index];
            violations.push(Violation {
                enforcement: Enforcement::Deny,
                cause: Cause::ProtectedPath { pattern: pattern.clone(), reason: reason.clone() },
                finding: None,
            });
        }

        for finding in findings {
            // An advisory rule is never allowed to deny, whatever its
            // severity or blocking-list membership — it is the single
            // escape hatch for a rule that is noisy in this repository, and
            // it has to outrank both other paths to be usable as one.
            let advisory = self.advisory_rules.contains(&finding.rule);
            let blocking = self.blocking_rules.contains(&finding.rule);
            let over_threshold = finding.severity >= self.block_at_or_above;

            let (enforcement, cause) = match (advisory, blocking, over_threshold) {
                (true, true, _) | (true, _, true) => (Enforcement::Warn, Cause::BlockingRule),
                (true, false, false) => continue,
                (false, true, _) => (Enforcement::Deny, Cause::BlockingRule),
                (false, false, true) => {
                    (Enforcement::Deny, Cause::SeverityThreshold { threshold: self.block_at_or_above })
                }
                (false, false, false) => continue,
            };

            violations.push(Violation { enforcement, cause, finding: Some(finding.clone()) });
        }

        Evaluation { violations }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(raw: &str) -> RuleId {
        RuleId::new(raw).expect("valid rule id")
    }

    fn finding(rule_id: &str, severity: Severity) -> Finding {
        Finding { rule: rule(rule_id), severity, message: "boom".to_string(), line: 7 }
    }

    #[test]
    fn an_empty_policy_is_the_default_policy() {
        let policy = AgentPolicy::parse("").expect("parses");
        assert!(policy.enabled());
        assert_eq!(policy.block_at_or_above(), Severity::Critical);
        assert!(policy.blocking_rules.contains(&rule("ai:llm-output-injection")));
        assert!(policy.protected_meta.is_empty(), "path protection is opt-in");
    }

    #[test]
    fn a_finding_below_the_threshold_does_not_deny() {
        let policy = AgentPolicy::default();
        let evaluation = policy.evaluate("src/a.ts", &[finding("smells:long-method", Severity::Major)]);
        assert!(!evaluation.is_denied());
        assert!(evaluation.is_empty());
    }

    #[test]
    fn a_finding_at_the_threshold_denies() {
        let policy = AgentPolicy::default();
        let evaluation = policy.evaluate("src/a.ts", &[finding("owasp:xss", Severity::Critical)]);
        assert!(evaluation.is_denied());
        assert_eq!(evaluation.denials().count(), 1);
    }

    #[test]
    fn a_blocking_rule_denies_even_far_below_the_threshold() {
        let policy = AgentPolicy::default();
        // Info is as low as a severity goes — only the blocking list can
        // explain a denial here, which is the whole point of the list.
        let evaluation = policy.evaluate("src/a.ts", &[finding("owasp:eval-usage", Severity::Info)]);
        assert!(evaluation.is_denied());
        assert!(matches!(evaluation.violations[0].cause, Cause::BlockingRule));
    }

    #[test]
    fn an_advisory_rule_warns_instead_of_denying_even_when_blocking_listed() {
        let raw = r#"
[agent]
blocking_rules = ["owasp:eval-usage"]
advisory_rules = ["owasp:eval-usage"]
"#;
        let policy = AgentPolicy::parse(raw).expect("parses");
        let evaluation = policy.evaluate("src/a.ts", &[finding("owasp:eval-usage", Severity::Blocker)]);
        assert!(!evaluation.is_denied(), "advisory must outrank both blocking list and threshold");
        assert_eq!(evaluation.warnings().count(), 1);
    }

    #[test]
    fn a_protected_path_denies_with_no_findings_at_all() {
        let raw = r#"
[[protected_path]]
pattern = ".github/workflows/**"
reason = "CI changes need a human reviewer."
"#;
        let policy = AgentPolicy::parse(raw).expect("parses");
        let evaluation = policy.evaluate(".github/workflows/ci.yml", &[]);
        assert!(evaluation.is_denied());
        assert!(evaluation.violations[0].describe().contains("human reviewer"));
    }

    #[test]
    fn a_windows_shaped_path_matches_the_same_glob() {
        let raw = r#"
[[protected_path]]
pattern = "infra/**"
reason = "IAM."
"#;
        let policy = AgentPolicy::parse(raw).expect("parses");
        assert!(policy.evaluate("infra\\aws\\iam.tf", &[]).is_denied());
    }

    #[test]
    fn a_star_star_glob_also_matches_a_top_level_file() {
        // globset treats a leading `**/` as matching zero directories, so
        // `**/*.tf` covers `main.tf`. Asserted rather than assumed: the
        // whole path-protection feature is worthless if it silently misses
        // files at the repository root.
        let raw = r#"
[[protected_path]]
pattern = "**/*.tf"
reason = "Terraform."
"#;
        let policy = AgentPolicy::parse(raw).expect("parses");
        assert!(policy.evaluate("main.tf", &[]).is_denied(), "top-level");
        assert!(policy.evaluate("infra/aws/main.tf", &[]).is_denied(), "nested");
    }

    #[test]
    fn a_disabled_policy_never_denies_and_stays_silent() {
        let policy = AgentPolicy::parse("[agent]\nenabled = false\n").expect("parses");
        let evaluation = policy.evaluate("src/a.ts", &[finding("owasp:eval-usage", Severity::Blocker)]);
        assert!(!evaluation.is_denied());
        assert!(evaluation.is_empty(), "disabled means out of the loop, not merely non-blocking");
    }

    #[test]
    fn a_present_key_overrides_without_resetting_the_others() {
        let policy = AgentPolicy::parse("[agent]\nblock_at_or_above = \"blocker\"\n").expect("parses");
        assert_eq!(policy.block_at_or_above(), Severity::Blocker);
        assert!(
            policy.blocking_rules.contains(&rule("ai:llm-output-injection")),
            "an unrelated key must keep its default"
        );
    }

    #[test]
    fn an_unparseable_severity_is_an_error_not_a_silent_default() {
        let err = AgentPolicy::parse("[agent]\nblock_at_or_above = \"catastrophic\"\n").unwrap_err();
        assert!(matches!(err, PolicyError::Severity(_)));
    }

    #[test]
    fn an_unknown_key_is_rejected_rather_than_ignored() {
        // A typo in a security policy that silently does nothing is worse
        // than a startup error.
        let err = AgentPolicy::parse("[agent]\nblock_at_or_abov = \"blocker\"\n").unwrap_err();
        assert!(matches!(err, PolicyError::Toml(_)));
    }

    #[test]
    fn an_invalid_rule_id_is_an_error() {
        let err = AgentPolicy::parse("[agent]\nblocking_rules = [\"NotARule\"]\n").unwrap_err();
        assert!(matches!(err, PolicyError::RuleId(_)));
    }

    #[test]
    fn a_threshold_violation_describes_itself_with_rule_line_and_severity() {
        let policy = AgentPolicy::default();
        let evaluation = policy.evaluate("src/a.ts", &[finding("owasp:xss", Severity::Blocker)]);
        let described = evaluation.violations[0].describe();
        assert!(described.contains("owasp:xss"), "{described}");
        assert!(described.contains("line 7"), "{described}");
        assert!(described.contains("blocker"), "{described}");
    }

    fn denied_evaluation(rule_id: &str) -> Evaluation {
        AgentPolicy::default().evaluate("a.py", &[finding(rule_id, Severity::Blocker)])
    }

    #[test]
    fn a_fresh_breaker_has_no_counts() {
        let breaker = CircuitBreakerState::default();
        assert_eq!(breaker.count_for(&rule("owasp:eval-usage")), 0);
        assert!(!breaker.is_tripped(&rule("owasp:eval-usage")));
    }

    #[test]
    fn two_consecutive_denials_do_not_trip_the_breaker() {
        let mut breaker = CircuitBreakerState::default();
        assert!(breaker.record(&denied_evaluation("owasp:eval-usage")).is_empty());
        assert!(breaker.record(&denied_evaluation("owasp:eval-usage")).is_empty());
        assert_eq!(breaker.count_for(&rule("owasp:eval-usage")), 2);
    }

    #[test]
    fn three_consecutive_denials_of_the_same_rule_trip_the_breaker() {
        let mut breaker = CircuitBreakerState::default();
        breaker.record(&denied_evaluation("owasp:eval-usage"));
        breaker.record(&denied_evaluation("owasp:eval-usage"));
        let tripped = breaker.record(&denied_evaluation("owasp:eval-usage"));
        assert_eq!(tripped, vec![rule("owasp:eval-usage")]);
        assert!(breaker.is_tripped(&rule("owasp:eval-usage")));
    }

    #[test]
    fn a_rule_that_stops_being_denied_resets_its_streak() {
        let mut breaker = CircuitBreakerState::default();
        breaker.record(&denied_evaluation("owasp:eval-usage"));
        breaker.record(&denied_evaluation("owasp:eval-usage"));
        // A clean write (no denials at all) breaks the streak.
        breaker.record(&Evaluation::default());
        assert_eq!(breaker.count_for(&rule("owasp:eval-usage")), 0);

        breaker.record(&denied_evaluation("owasp:eval-usage"));
        breaker.record(&denied_evaluation("owasp:eval-usage"));
        assert_eq!(breaker.count_for(&rule("owasp:eval-usage")), 2, "not consecutive with the earlier pair");
    }

    #[test]
    fn distinct_rules_are_tracked_independently() {
        let policy = AgentPolicy::default();
        // One write attempt triggering both rules at once.
        let both = policy.evaluate(
            "a.py",
            &[finding("owasp:eval-usage", Severity::Blocker), finding("owasp:command-execution", Severity::Blocker)],
        );
        // A later attempt where `command-execution` no longer reproduces.
        let eval_usage_only = policy.evaluate("a.py", &[finding("owasp:eval-usage", Severity::Blocker)]);

        let mut breaker = CircuitBreakerState::default();
        breaker.record(&both);
        breaker.record(&both);
        let tripped = breaker.record(&eval_usage_only);

        assert_eq!(tripped, vec![rule("owasp:eval-usage")], "only the rule still failing trips");
        assert_eq!(
            breaker.count_for(&rule("owasp:command-execution")),
            0,
            "a rule that stops reproducing clears independently of its sibling's streak"
        );
    }

    #[test]
    fn a_protected_path_denial_never_participates_in_the_breaker() {
        let raw = r#"
[[protected_path]]
pattern = ".github/workflows/**"
reason = "CI changes need a human reviewer."
"#;
        let policy = AgentPolicy::parse(raw).expect("parses");
        let evaluation = policy.evaluate(".github/workflows/ci.yml", &[]);
        let mut breaker = CircuitBreakerState::default();
        for _ in 0..5 {
            assert!(breaker.record(&evaluation).is_empty());
        }
        assert!(breaker.counts().next().is_none(), "a path-only denial has no rule to track");
    }

    #[test]
    fn from_counts_and_counts_round_trip() {
        let breaker = CircuitBreakerState::from_counts([(rule("owasp:eval-usage"), 2)]);
        assert_eq!(breaker.count_for(&rule("owasp:eval-usage")), 2);
        let restored: Vec<_> = breaker.counts().map(|(r, c)| (r.clone(), c)).collect();
        assert_eq!(restored, vec![(rule("owasp:eval-usage"), 2)]);
    }
}
