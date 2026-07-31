//! Quality Gates: named sets of conditions over analysis measures.
//! A gate is pure data + pure evaluation; where measures come from is the
//! caller's concern (the report, a database, a delta between analyses).

use std::fmt;

/// A validated measure identifier in lowercase snake_case,
/// e.g. `blocker_issues`, `lines_of_code`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct MetricKey(String);

#[derive(Debug, thiserror::Error)]
#[error("metric key must be lowercase snake_case, got {0:?}")]
pub struct InvalidMetricKeyError(String);

impl MetricKey {
    pub fn new(raw: &str) -> Result<Self, InvalidMetricKeyError> {
        let valid = !raw.is_empty()
            && raw
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
        if valid {
            Ok(Self(raw.to_string()))
        } else {
            Err(InvalidMetricKeyError(raw.to_string()))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for MetricKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ComparisonOperator {
    /// The condition fails when the measured value is greater than the threshold.
    GreaterThan,
    /// The condition fails when the measured value is less than the threshold.
    LessThan,
}

impl ComparisonOperator {
    pub fn symbol(&self) -> &'static str {
        match self {
            ComparisonOperator::GreaterThan => ">",
            ComparisonOperator::LessThan => "<",
        }
    }
}

/// One gate condition: "fail when `metric` `operator` `threshold`".
#[derive(Clone, Debug, PartialEq)]
pub struct Condition {
    metric: MetricKey,
    operator: ComparisonOperator,
    threshold: f64,
}

impl Condition {
    pub fn new(metric: MetricKey, operator: ComparisonOperator, threshold: f64) -> Self {
        Self {
            metric,
            operator,
            threshold,
        }
    }

    pub fn metric(&self) -> &MetricKey {
        &self.metric
    }

    pub fn operator(&self) -> ComparisonOperator {
        self.operator
    }

    pub fn threshold(&self) -> f64 {
        self.threshold
    }

    fn is_breached(&self, value: f64) -> bool {
        match self.operator {
            ComparisonOperator::GreaterThan => value > self.threshold,
            ComparisonOperator::LessThan => value < self.threshold,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConditionStatus {
    Passed,
    Failed,
    /// The measure was unavailable; the condition is ignored (fail-open).
    NoValue,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ConditionResult {
    pub condition: Condition,
    pub value: Option<f64>,
    pub status: ConditionStatus,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GateStatus {
    Passed,
    Failed,
}

impl fmt::Display for GateStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            GateStatus::Passed => "PASSED",
            GateStatus::Failed => "FAILED",
        })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct GateEvaluation {
    status: GateStatus,
    results: Vec<ConditionResult>,
}

impl GateEvaluation {
    pub fn status(&self) -> GateStatus {
        self.status
    }

    pub fn results(&self) -> &[ConditionResult] {
        &self.results
    }

    pub fn failed_conditions(&self) -> impl Iterator<Item = &ConditionResult> {
        self.results
            .iter()
            .filter(|r| r.status == ConditionStatus::Failed)
    }
}

/// A named, ordered set of conditions.
#[derive(Clone, Debug, PartialEq)]
pub struct QualityGate {
    name: String,
    conditions: Vec<Condition>,
}

impl QualityGate {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            conditions: Vec::new(),
        }
    }

    pub fn with_condition(mut self, condition: Condition) -> Self {
        self.conditions.push(condition);
        self
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn conditions(&self) -> &[Condition] {
        &self.conditions
    }

    /// Evaluates every condition against `measure`; the gate fails if any
    /// condition with an available value is breached.
    pub fn evaluate<F>(&self, measure: F) -> GateEvaluation
    where
        F: Fn(&MetricKey) -> Option<f64>,
    {
        let results: Vec<ConditionResult> = self
            .conditions
            .iter()
            .map(|condition| {
                let value = measure(&condition.metric);
                let status = match value {
                    None => ConditionStatus::NoValue,
                    Some(v) if condition.is_breached(v) => ConditionStatus::Failed,
                    Some(_) => ConditionStatus::Passed,
                };
                ConditionResult {
                    condition: condition.clone(),
                    value,
                    status,
                }
            })
            .collect();
        let status = if results.iter().any(|r| r.status == ConditionStatus::Failed) {
            GateStatus::Failed
        } else {
            GateStatus::Passed
        };
        GateEvaluation { status, results }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gate() -> QualityGate {
        QualityGate::new("test")
            .with_condition(Condition::new(
                MetricKey::new("blocker_issues").unwrap(),
                ComparisonOperator::GreaterThan,
                0.0,
            ))
            .with_condition(Condition::new(
                MetricKey::new("coverage").unwrap(),
                ComparisonOperator::LessThan,
                80.0,
            ))
    }

    #[test]
    fn fails_when_any_condition_is_breached() {
        let evaluation = gate().evaluate(|key| match key.as_str() {
            "blocker_issues" => Some(3.0),
            "coverage" => Some(92.5),
            _ => None,
        });
        assert_eq!(evaluation.status(), GateStatus::Failed);
        assert_eq!(evaluation.failed_conditions().count(), 1);
    }

    #[test]
    fn passes_when_all_conditions_hold() {
        let evaluation = gate().evaluate(|key| match key.as_str() {
            "blocker_issues" => Some(0.0),
            "coverage" => Some(85.0),
            _ => None,
        });
        assert_eq!(evaluation.status(), GateStatus::Passed);
    }

    #[test]
    fn missing_measures_are_ignored() {
        let evaluation = gate().evaluate(|key| match key.as_str() {
            "blocker_issues" => Some(0.0),
            _ => None,
        });
        assert_eq!(evaluation.status(), GateStatus::Passed);
        assert_eq!(evaluation.results()[1].status, ConditionStatus::NoValue);
    }

    #[test]
    fn metric_key_validation() {
        assert!(MetricKey::new("lines_of_code").is_ok());
        assert!(MetricKey::new("Lines").is_err());
        assert!(MetricKey::new("").is_err());
    }
}
