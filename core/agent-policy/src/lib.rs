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
    /// A rule listed in `escalate_rules`: blocked until a human explicitly
    /// approves this exact write (see `yunq hook approve` in `bin/cli`,
    /// which owns the approval-token workflow this cause exists to drive —
    /// this crate only ever produces the verdict, never the approval).
    Escalation,
}

/// Whether a violation stops the write, merely annotates it, or blocks
/// pending an explicit human approval.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Enforcement {
    Deny,
    Warn,
    /// Blocks like `Deny`, but a caller that tracks approvals may lift it
    /// for one specific, already-reviewed write. Never lifted here — this
    /// crate is pure and knows nothing of approval state.
    Escalate,
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
            (Cause::Escalation, Some(f)) => {
                format!("{} at line {} — {} [requires human approval]", f.rule, f.line, f.message)
            }
            // A rule/threshold/escalation cause always carries the finding
            // that caused it; this arm exists only to keep `describe` total.
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
    /// True for a hard `Deny` and equally true for an unresolved `Escalate`
    /// — both block the write; the only difference is that an `Escalate`
    /// *can* be lifted by a caller-tracked approval, which is exactly why
    /// this crate (pure, no I/O, no approval state) treats them alike.
    pub fn is_denied(&self) -> bool {
        self.violations.iter().any(|v| matches!(v.enforcement, Enforcement::Deny | Enforcement::Escalate))
    }

    /// Every violation that currently blocks the write — `Deny` and
    /// `Escalate` alike, so a caller rendering "why is this blocked" text
    /// does not have to remember to query two iterators.
    pub fn denials(&self) -> impl Iterator<Item = &Violation> {
        self.violations.iter().filter(|v| matches!(v.enforcement, Enforcement::Deny | Enforcement::Escalate))
    }

    pub fn warnings(&self) -> impl Iterator<Item = &Violation> {
        self.violations.iter().filter(|v| v.enforcement == Enforcement::Warn)
    }

    /// Just the escalations, for a caller that needs to tell "blocked
    /// outright" apart from "blocked pending approval" (e.g. to compute an
    /// approval token, or to decide whether an approval could possibly
    /// apply — see `bin/cli`'s `judge`).
    pub fn escalations(&self) -> impl Iterator<Item = &Violation> {
        self.violations.iter().filter(|v| v.enforcement == Enforcement::Escalate)
    }

    pub fn is_empty(&self) -> bool {
        self.violations.is_empty()
    }
}

/// Whether a path is already known, from prior agent activity, to carry
/// AI-authored history.
///
/// This crate has no I/O, so it never determines this itself — the caller
/// (`bin/cli`'s per-repo touch ledger, keyed on every path a `yunq hook`
/// write has ever targeted) supplies it per evaluation, the same way it
/// supplies `Finding`s. This is the automatic, per-path analogue of the
/// "flag this project as AI-generated" setting incumbent tools require a
/// human to set by hand: once yunq has seen an agent write to a path, that
/// path carries the flag from then on with no configuration step.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Provenance {
    /// No recorded agent write has ever targeted this exact path before. The
    /// base policy applies.
    #[default]
    Unestablished,
    /// A prior agent write has already targeted this exact path — the
    /// stricter `[agent.ai_touched]` policy applies instead of the base one.
    AiTouched,
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
    #[serde(default)]
    ai_touched: AiTouchedSection,
    #[serde(default = "default_blocking_rules")]
    blocking_rules: Vec<String>,
    #[serde(default)]
    advisory_rules: Vec<String>,
    #[serde(default)]
    escalate_rules: Vec<String>,
}

impl Default for AgentSection {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            block_at_or_above: default_block_at_or_above(),
            ai_touched: AiTouchedSection::default(),
            blocking_rules: default_blocking_rules(),
            advisory_rules: Vec::new(),
            escalate_rules: Vec::new(),
        }
    }
}

/// The stricter policy applied once [`Provenance::AiTouched`] is asserted for
/// a path. The only field is a severity threshold, not a separate rule list:
/// `blocking_rules`/`escalate_rules`/`advisory_rules` stay identical
/// regardless of provenance, since a categorical ban (`eval`, a shell sink)
/// is exactly as dangerous whether or not the file has agent history — only
/// the severity bar legitimately tightens, mirroring the "stricter on
/// security, unchanged elsewhere" shape real AI-code quality gates ship.
///
/// Absent (or with `block_at_or_above` unset) means "same as the base
/// policy" — this section only ever tightens, and follows the same
/// opt-in-until-configured convention `protected_path` uses: a default that
/// silently denies more of an agent's writes the moment yunq is installed
/// gets yunq uninstalled. `yunq hook install`'s generated policy turns it on
/// with a concrete value, visible and editable like every other opinionated
/// default in that template.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct AiTouchedSection {
    block_at_or_above: Option<String>,
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
    ai_touched_block_at_or_above: Severity,
    blocking_rules: Vec<RuleId>,
    advisory_rules: Vec<RuleId>,
    escalate_rules: Vec<RuleId>,
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

        let ai_touched_block_at_or_above = match &file.agent.ai_touched.block_at_or_above {
            Some(raw) => Severity::parse(raw).ok_or_else(|| PolicyError::Severity(raw.clone()))?,
            None => block_at_or_above,
        };

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
            ai_touched_block_at_or_above,
            blocking_rules: parse_rules(&file.agent.blocking_rules)?,
            advisory_rules: parse_rules(&file.agent.advisory_rules)?,
            escalate_rules: parse_rules(&file.agent.escalate_rules)?,
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

    /// The severity threshold in force for a path with the given
    /// [`Provenance`] — the base `block_at_or_above` for
    /// [`Provenance::Unestablished`], or the (possibly stricter)
    /// `[agent.ai_touched]` value for [`Provenance::AiTouched`].
    pub fn block_at_or_above_for(&self, provenance: Provenance) -> Severity {
        match provenance {
            Provenance::AiTouched => self.ai_touched_block_at_or_above,
            Provenance::Unestablished => self.block_at_or_above,
        }
    }

    /// Judges one proposed write with no known AI-touch history — equivalent
    /// to [`Self::evaluate_with_provenance`] with [`Provenance::Unestablished`].
    /// `path` is repository-relative, using forward slashes (backslashes are
    /// normalised, so a Windows-shaped path matches the same globs).
    pub fn evaluate(&self, path: &str, findings: &[Finding]) -> Evaluation {
        self.evaluate_with_provenance(path, findings, Provenance::Unestablished)
    }

    /// Judges one proposed write, applying the stricter `[agent.ai_touched]`
    /// severity threshold instead of the base one when `provenance` is
    /// [`Provenance::AiTouched`]. Provenance affects only the threshold —
    /// `blocking_rules`/`escalate_rules`/`advisory_rules` apply identically
    /// either way (see [`AiTouchedSection`]'s doc comment for why).
    ///
    /// A disabled policy returns no violations at all rather than
    /// downgrading them to warnings: `enabled = false` means "yunq is not in
    /// this agent's loop", and emitting advisory noise would contradict that.
    pub fn evaluate_with_provenance(&self, path: &str, findings: &[Finding], provenance: Provenance) -> Evaluation {
        if !self.enabled {
            return Evaluation::default();
        }

        let threshold = self.block_at_or_above_for(provenance);
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
            let advisory = self.advisory_rules.contains(&finding.rule);
            let blocking = self.blocking_rules.contains(&finding.rule);
            let escalate = self.escalate_rules.contains(&finding.rule);
            let over_threshold = finding.severity >= threshold;

            // Nothing about this finding trips the policy at all: skip
            // rather than manufacture a violation with no enforcement path
            // behind it.
            if !(blocking || escalate || over_threshold) {
                continue;
            }

            // An advisory rule is never allowed to deny or escalate,
            // whatever its severity or list membership — it is the single
            // escape hatch for a rule that is noisy in this repository, and
            // it has to outrank every other path to be usable as one.
            let (enforcement, cause) = if advisory {
                (Enforcement::Warn, Cause::BlockingRule)
            } else if blocking {
                // The hard-blocked list has no override: a category the
                // repository decided is categorically too dangerous for an
                // agent to introduce does not become approvable just
                // because it is also listed under `escalate_rules`.
                (Enforcement::Deny, Cause::BlockingRule)
            } else if escalate {
                (Enforcement::Escalate, Cause::Escalation)
            } else {
                (Enforcement::Deny, Cause::SeverityThreshold { threshold })
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
    fn an_escalate_listed_rule_blocks_pending_approval_instead_of_denying_outright() {
        let raw = "[agent]\nescalate_rules = [\"smells:long-method\"]\n";
        let policy = AgentPolicy::parse(raw).expect("parses");
        let evaluation = policy.evaluate("src/a.ts", &[finding("smells:long-method", Severity::Minor)]);
        assert!(evaluation.is_denied(), "an unresolved escalation still blocks the write");
        assert_eq!(evaluation.escalations().count(), 1);
        assert_eq!(evaluation.denials().count(), 1, "denials() surfaces escalations too");
        assert!(matches!(evaluation.violations[0].enforcement, Enforcement::Escalate));
        assert!(matches!(evaluation.violations[0].cause, Cause::Escalation));
    }

    #[test]
    fn an_escalation_describes_itself_as_requiring_human_approval() {
        let raw = "[agent]\nescalate_rules = [\"smells:long-method\"]\n";
        let policy = AgentPolicy::parse(raw).expect("parses");
        let evaluation = policy.evaluate("src/a.ts", &[finding("smells:long-method", Severity::Minor)]);
        assert!(evaluation.violations[0].describe().contains("requires human approval"));
    }

    #[test]
    fn advisory_outranks_escalation_just_as_it_outranks_blocking() {
        let raw = r#"
[agent]
escalate_rules = ["smells:long-method"]
advisory_rules = ["smells:long-method"]
"#;
        let policy = AgentPolicy::parse(raw).expect("parses");
        let evaluation = policy.evaluate("src/a.ts", &[finding("smells:long-method", Severity::Minor)]);
        assert!(!evaluation.is_denied(), "advisory is the escape hatch and must win over escalation too");
        assert_eq!(evaluation.warnings().count(), 1);
    }

    #[test]
    fn blocking_outranks_escalation_when_a_rule_is_listed_in_both() {
        // The hard-blocked list is "no exceptions"; putting a rule in both
        // lists must not accidentally make it approvable.
        let raw = r#"
[agent]
blocking_rules = ["owasp:eval-usage"]
escalate_rules = ["owasp:eval-usage"]
"#;
        let policy = AgentPolicy::parse(raw).expect("parses");
        let evaluation = policy.evaluate("a.py", &[finding("owasp:eval-usage", Severity::Info)]);
        assert!(matches!(evaluation.violations[0].enforcement, Enforcement::Deny));
        assert!(matches!(evaluation.violations[0].cause, Cause::BlockingRule));
    }

    #[test]
    fn escalation_does_not_participate_in_the_severity_threshold_path() {
        // A rule only in escalate_rules, at a severity below the threshold,
        // still escalates — escalate_rules is its own opt-in list, not a
        // second severity gate.
        let raw = "[agent]\nescalate_rules = [\"smells:long-method\"]\nblock_at_or_above = \"blocker\"\n";
        let policy = AgentPolicy::parse(raw).expect("parses");
        let evaluation = policy.evaluate("src/a.ts", &[finding("smells:long-method", Severity::Info)]);
        assert!(matches!(evaluation.violations[0].enforcement, Enforcement::Escalate));
    }

    #[test]
    fn an_absent_ai_touched_section_uses_the_same_threshold_as_the_base_policy() {
        let policy = AgentPolicy::default();
        assert_eq!(policy.block_at_or_above_for(Provenance::Unestablished), Severity::Critical);
        assert_eq!(policy.block_at_or_above_for(Provenance::AiTouched), Severity::Critical);
    }

    #[test]
    fn evaluate_is_equivalent_to_evaluate_with_provenance_unestablished() {
        let policy = AgentPolicy::default();
        let f = [finding("owasp:xss", Severity::Critical)];
        assert_eq!(policy.evaluate("src/a.ts", &f), policy.evaluate_with_provenance("src/a.ts", &f, Provenance::Unestablished));
    }

    #[test]
    fn an_ai_touched_path_is_judged_against_the_stricter_threshold() {
        let raw = "[agent]\nblock_at_or_above = \"critical\"\n[agent.ai_touched]\nblock_at_or_above = \"major\"\n";
        let policy = AgentPolicy::parse(raw).expect("parses");
        let f = [finding("smells:long-method", Severity::Major)];

        let untouched = policy.evaluate_with_provenance("src/a.ts", &f, Provenance::Unestablished);
        assert!(!untouched.is_denied(), "major is below the base critical threshold");

        let touched = policy.evaluate_with_provenance("src/a.ts", &f, Provenance::AiTouched);
        assert!(touched.is_denied(), "major meets the stricter ai_touched threshold");
    }

    #[test]
    fn ai_touched_threshold_can_never_be_looser_than_configured_even_though_nothing_enforces_that() {
        // Not a hard invariant the type system enforces, but the shipped
        // template always sets ai_touched >= base — documented here so a
        // future change to the default doesn't silently invert it.
        let raw = "[agent.ai_touched]\nblock_at_or_above = \"blocker\"\n";
        let policy = AgentPolicy::parse(raw).expect("parses");
        assert_eq!(policy.block_at_or_above_for(Provenance::AiTouched), Severity::Blocker);
        assert_eq!(policy.block_at_or_above_for(Provenance::Unestablished), Severity::Critical);
    }

    #[test]
    fn provenance_never_changes_blocking_rule_or_escalation_behavior() {
        let raw = "[agent]\nblocking_rules = [\"owasp:eval-usage\"]\nescalate_rules = [\"smells:long-method\"]\n";
        let policy = AgentPolicy::parse(raw).expect("parses");

        let blocked = [finding("owasp:eval-usage", Severity::Info)];
        assert_eq!(
            policy.evaluate_with_provenance("a.py", &blocked, Provenance::Unestablished),
            policy.evaluate_with_provenance("a.py", &blocked, Provenance::AiTouched),
        );

        let escalated = [finding("smells:long-method", Severity::Minor)];
        assert_eq!(
            policy.evaluate_with_provenance("a.py", &escalated, Provenance::Unestablished),
            policy.evaluate_with_provenance("a.py", &escalated, Provenance::AiTouched),
        );
    }

    #[test]
    fn an_invalid_ai_touched_severity_is_an_error_not_a_silent_default() {
        let err = AgentPolicy::parse("[agent.ai_touched]\nblock_at_or_above = \"catastrophic\"\n").unwrap_err();
        assert!(matches!(err, PolicyError::Severity(_)));
    }

    #[test]
    fn an_unknown_key_in_ai_touched_is_rejected_rather_than_ignored() {
        let err = AgentPolicy::parse("[agent.ai_touched]\nblock_at_or_abov = \"major\"\n").unwrap_err();
        assert!(matches!(err, PolicyError::Toml(_)));
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
