//! The quality model: rule identities, severities, quality profiles (which
//! rules are active and at which severity), quality gates and ratings.
//! Pure domain.

mod backup;
mod builtin;
mod compare;
mod copy;
mod gate;
mod impact;
mod rating;

pub use backup::{backup, restore, ProfileBackup, RestoreError, RestorePolicy};
pub use builtin::{default_profile, default_profile_for_language, DEFAULT_PROFILE_NAME};
pub use compare::{compare, ProfileDiff, SeverityDifference};
pub use copy::copy_profile;
pub use gate::{
    ComparisonOperator, Condition, ConditionResult, ConditionStatus, GateEvaluation, GateStatus,
    InvalidMetricKeyError, MetricKey, QualityGate,
};
pub use impact::{default_impact, ImpactSeverity, SoftwareQuality, SoftwareQualityImpact};
pub use rating::{
    aggregate_remediation_effort, debt_ratio, reliability_and_security_ratings, DebtRatingGrid,
    IssueType, Rating, RemediationEffortSummary, ReliabilitySecurityRatings,
    DEFAULT_DEV_COST_MINUTES_PER_LINE,
};

use std::collections::HashMap;
use std::fmt;

/// A validated rule identifier in `namespace:code` form, e.g. `owasp:eval-usage`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RuleId(String);

#[derive(Debug, thiserror::Error)]
#[error("rule id must be `namespace:code` in lowercase kebab-case, got {0:?}")]
pub struct InvalidRuleIdError(String);

impl RuleId {
    pub fn new(raw: &str) -> Result<Self, InvalidRuleIdError> {
        let valid_part =
            |p: &str| !p.is_empty() && p.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
        match raw.split_once(':') {
            Some((ns, code)) if valid_part(ns) && valid_part(code) => Ok(Self(raw.to_string())),
            _ => Err(InvalidRuleIdError(raw.to_string())),
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RuleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Issue severity, ordered from least to most severe.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    Info,
    Minor,
    Major,
    Critical,
    Blocker,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Minor => "minor",
            Severity::Major => "major",
            Severity::Critical => "critical",
            Severity::Blocker => "blocker",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        match raw.to_ascii_lowercase().as_str() {
            "info" => Some(Severity::Info),
            "minor" => Some(Severity::Minor),
            "major" => Some(Severity::Major),
            "critical" => Some(Severity::Critical),
            "blocker" => Some(Severity::Blocker),
            _ => None,
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The set of active rules for an analysis, with per-rule severity.
/// A rule absent from the profile (and its inheritance chain) is inactive.
///
/// Profiles can inherit: a child profile's own activations override its
/// parent's; anything not overridden falls through the chain.
#[derive(Clone, Debug)]
pub struct QualityProfile {
    name: String,
    activations: HashMap<RuleId, Severity>,
    parent: Option<Box<QualityProfile>>,
}

impl QualityProfile {
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into(), activations: HashMap::new(), parent: None }
    }

    pub fn from_activations(
        name: impl Into<String>,
        activations: impl IntoIterator<Item = (RuleId, Severity)>,
    ) -> Self {
        Self {
            name: name.into(),
            activations: activations.into_iter().collect(),
            parent: None,
        }
    }

    /// Makes this profile inherit from `parent`; own activations win.
    pub fn with_parent(mut self, parent: QualityProfile) -> Self {
        self.parent = Some(Box::new(parent));
        self
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn parent(&self) -> Option<&QualityProfile> {
        self.parent.as_deref()
    }

    pub fn activate(&mut self, rule: RuleId, severity: Severity) {
        self.activations.insert(rule, severity);
    }

    pub fn is_active(&self, rule: &RuleId) -> bool {
        self.activations.contains_key(rule)
            || self.parent.as_ref().is_some_and(|p| p.is_active(rule))
    }

    pub fn severity_of(&self, rule: &RuleId) -> Option<Severity> {
        self.activations
            .get(rule)
            .copied()
            .or_else(|| self.parent.as_ref().and_then(|p| p.severity_of(rule)))
    }

    pub fn deactivate(&mut self, rule: &RuleId) {
        self.activations.remove(rule);
    }

    /// This profile's own activations (excluding inherited ones) — the data
    /// an adapter serializes for backup/restore.
    pub fn own_activations(&self) -> impl Iterator<Item = (&RuleId, Severity)> {
        self.activations.iter().map(|(rule, severity)| (rule, *severity))
    }

    /// Every rule active in this profile, own or inherited, with the
    /// severity that would actually apply — the flattened view `compare`
    /// and `copy_profile` operate on, and what an analyzer run really uses
    /// (mirrors `is_active`/`severity_of`'s fall-through, just materialized
    /// as a map instead of walked per-rule).
    pub fn effective_activations(&self) -> HashMap<RuleId, Severity> {
        let mut merged = match &self.parent {
            Some(parent) => parent.effective_activations(),
            None => HashMap::new(),
        };
        merged.extend(self.activations.iter().map(|(rule, severity)| (rule.clone(), *severity)));
        merged
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_rule_id_format() {
        assert!(RuleId::new("owasp:eval-usage").is_ok());
        assert!(RuleId::new("smells:todo").is_ok());
        assert!(RuleId::new("no-namespace").is_err());
        assert!(RuleId::new("Upper:case").is_err());
        assert!(RuleId::new(":empty").is_err());
    }

    #[test]
    fn severity_ordering() {
        assert!(Severity::Blocker > Severity::Critical);
        assert!(Severity::Info < Severity::Minor);
    }

    #[test]
    fn inherited_activations_fall_through_and_own_ones_win() {
        let base_rule = RuleId::new("owasp:eval-usage").unwrap();
        let tuned_rule = RuleId::new("smells:todo").unwrap();

        let mut parent = QualityProfile::new("company-way");
        parent.activate(base_rule.clone(), Severity::Critical);
        parent.activate(tuned_rule.clone(), Severity::Info);

        let mut child = QualityProfile::new("team-way").with_parent(parent);
        child.activate(tuned_rule.clone(), Severity::Major);

        // Inherited activation is visible…
        assert!(child.is_active(&base_rule));
        assert_eq!(child.severity_of(&base_rule), Some(Severity::Critical));
        // …but the child's own override wins.
        assert_eq!(child.severity_of(&tuned_rule), Some(Severity::Major));
        // Backup only serializes own activations.
        assert_eq!(child.own_activations().count(), 1);

        // effective_activations flattens the whole chain, own wins.
        let effective = child.effective_activations();
        assert_eq!(effective.len(), 2);
        assert_eq!(effective.get(&base_rule), Some(&Severity::Critical));
        assert_eq!(effective.get(&tuned_rule), Some(&Severity::Major));
    }

    #[test]
    fn profile_activation_and_override() {
        let id = RuleId::new("owasp:eval-usage").unwrap();
        let mut profile = QualityProfile::new("default");
        assert!(!profile.is_active(&id));
        profile.activate(id.clone(), Severity::Critical);
        assert_eq!(profile.severity_of(&id), Some(Severity::Critical));
    }
}
