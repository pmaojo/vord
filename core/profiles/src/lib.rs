//! The quality model: rule identities, severities, quality profiles (which
//! rules are active and at which severity), quality gates and ratings.
//! Pure domain.

mod gate;
mod rating;

pub use gate::{
    ComparisonOperator, Condition, ConditionResult, ConditionStatus, GateEvaluation, GateStatus,
    InvalidMetricKeyError, MetricKey, QualityGate,
};
pub use rating::Rating;

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
    pub fn as_str(&self) -> &str {
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
/// A rule absent from the profile is inactive.
#[derive(Clone, Debug)]
pub struct QualityProfile {
    name: String,
    activations: HashMap<RuleId, Severity>,
}

impl QualityProfile {
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into(), activations: HashMap::new() }
    }

    pub fn from_activations(
        name: impl Into<String>,
        activations: impl IntoIterator<Item = (RuleId, Severity)>,
    ) -> Self {
        Self { name: name.into(), activations: activations.into_iter().collect() }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn activate(&mut self, rule: RuleId, severity: Severity) {
        self.activations.insert(rule, severity);
    }

    pub fn is_active(&self, rule: &RuleId) -> bool {
        self.activations.contains_key(rule)
    }

    pub fn severity_of(&self, rule: &RuleId) -> Option<Severity> {
        self.activations.get(rule).copied()
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
    fn profile_activation_and_override() {
        let id = RuleId::new("owasp:eval-usage").unwrap();
        let mut profile = QualityProfile::new("default");
        assert!(!profile.is_active(&id));
        profile.activate(id.clone(), Severity::Critical);
        assert_eq!(profile.severity_of(&id), Some(Severity::Critical));
    }
}
