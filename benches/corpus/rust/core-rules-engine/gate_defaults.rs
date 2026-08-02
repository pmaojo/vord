//! The built-in quality gate every project falls back to until an admin
//! assigns one explicitly. Single source of truth for the conditions the
//! CLI (`vord_cli::default_quality_gate`) and the server (project → gate
//! assignment, badge status) both evaluate against, so the two front ends
//! never drift apart on what "the default gate" means.

use vord_profiles::{ComparisonOperator, Condition, MetricKey, QualityGate};

/// No blocker or critical issues, every file must parse, and (when a
/// coverage report was ingested) coverage stays at or above 80%.
pub fn default_gate() -> QualityGate {
    let metric = |raw: &str| MetricKey::new(raw).expect("valid metric key");
    QualityGate::new("vord-default")
        .with_condition(Condition::new(metric("blocker_issues"), ComparisonOperator::GreaterThan, 0.0))
        .with_condition(Condition::new(metric("critical_issues"), ComparisonOperator::GreaterThan, 0.0))
        .with_condition(Condition::new(metric("parse_failures"), ComparisonOperator::GreaterThan, 0.0))
        .with_condition(Condition::new(metric("coverage"), ComparisonOperator::LessThan, 80.0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{AnalysisReport, Metrics};

    #[test]
    fn default_gate_has_the_documented_conditions() {
        let gate = default_gate();
        assert_eq!(gate.name(), "vord-default");
        assert_eq!(gate.conditions().len(), 4);
    }

    #[test]
    fn default_gate_passes_a_clean_report_with_no_coverage_ingested() {
        let report = AnalysisReport::new(vec![], vec![], Metrics::new());
        let evaluation = default_gate().evaluate(|key| report.measure(key));
        assert_eq!(evaluation.status(), crate::GateStatus::Passed);
    }
}
