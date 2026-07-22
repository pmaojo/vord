//! New Code classification (Clean as You Code): given a baseline of issue
//! fingerprints from a previous analysis, split the current report's issues
//! into new vs. pre-existing, and expose `new_*` measures for quality gates.

use std::collections::HashSet;
use std::hash::{DefaultHasher, Hash, Hasher};

use yunq_profiles::{MetricKey, Severity};

use crate::domain::{AnalysisReport, Issue};

/// Clean as You Code period definition: specifies how pre-existing code is demarcated
/// from new/changed code across analyses.
#[allow(dead_code)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NewCodePeriod {
    /// Compare against the previous analysis version / commit
    PreviousVersion,
    /// Compare against analysis from N days ago
    NDays(u32),
    /// Compare against the target reference branch (e.g. "main" or "master")
    ReferenceBranch(String),
    /// Compare against a specific historical analysis ID / commit SHA
    SpecificAnalysis(String),
}

impl Default for NewCodePeriod {
    fn default() -> Self {
        Self::PreviousVersion
    }
}

/// Location-tolerant identity of an issue: rule + file + message. Moving
/// code within a file does not make its old issues "new".
pub fn issue_fingerprint(issue: &Issue) -> u64 {
    let mut hasher = DefaultHasher::new();
    issue.rule().as_str().hash(&mut hasher);
    issue.file().hash(&mut hasher);
    issue.message().hash(&mut hasher);
    hasher.finish()
}

/// The set of issue fingerprints from a previous analysis.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Baseline(HashSet<u64>);

impl Baseline {
    pub fn from_fingerprints(fingerprints: impl IntoIterator<Item = u64>) -> Self {
        Self(fingerprints.into_iter().collect())
    }

    pub fn from_report(report: &AnalysisReport) -> Self {
        Self(report.issues().iter().map(issue_fingerprint).collect())
    }

    pub fn contains(&self, issue: &Issue) -> bool {
        self.0.contains(&issue_fingerprint(issue))
    }

    pub fn fingerprints(&self) -> impl Iterator<Item = u64> + '_ {
        self.0.iter().copied()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// The report's issues split against a baseline.
#[derive(Clone, Debug)]
pub struct NewCodeAnalysis {
    new_issues: Vec<Issue>,
}

impl NewCodeAnalysis {
    pub fn classify(report: &AnalysisReport, baseline: &Baseline) -> Self {
        let new_issues =
            report.issues().iter().filter(|i| !baseline.contains(i)).cloned().collect();
        Self { new_issues }
    }

    pub fn new_issues(&self) -> &[Issue] {
        &self.new_issues
    }

    /// `new_*` measures for gate conditions on new code; other keys → None
    /// so this composes with the overall report measures.
    pub fn measure(&self, key: &MetricKey) -> Option<f64> {
        let count_at = |severity: Severity| {
            self.new_issues.iter().filter(|i| i.severity() == severity).count() as f64
        };
        match key.as_str() {
            "new_issue_total" => Some(self.new_issues.len() as f64),
            "new_blocker_issues" => Some(count_at(Severity::Blocker)),
            "new_critical_issues" => Some(count_at(Severity::Critical)),
            "new_major_issues" => Some(count_at(Severity::Major)),
            "new_minor_issues" => Some(count_at(Severity::Minor)),
            "new_info_issues" => Some(count_at(Severity::Info)),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use yunq_ast::Span;
    use yunq_profiles::RuleId;

    use crate::domain::Metrics;

    use super::*;

    fn issue(message: &str, severity: Severity) -> Issue {
        Issue::new(
            RuleId::new("test:rule").unwrap(),
            severity,
            message,
            "a.rs",
            Span::new(1, 1, 1, 2),
        )
    }

    #[test]
    fn splits_new_issues_against_baseline() {
        let old = issue("old problem", Severity::Major);
        let first = AnalysisReport::new(vec![old.clone()], vec![], Metrics::new());
        let baseline = Baseline::from_report(&first);

        // Same old issue on a different line is NOT new; a new message is.
        let moved = Issue::new(
            old.rule().clone(),
            old.severity(),
            old.message(),
            old.file(),
            Span::new(50, 1, 50, 2),
        );
        let fresh = issue("brand new problem", Severity::Blocker);
        let second =
            AnalysisReport::new(vec![moved, fresh.clone()], vec![], Metrics::new());

        let new_code = NewCodeAnalysis::classify(&second, &baseline);
        assert_eq!(new_code.new_issues(), &[fresh]);

        let key = |raw: &str| MetricKey::new(raw).unwrap();
        assert_eq!(new_code.measure(&key("new_issue_total")), Some(1.0));
        assert_eq!(new_code.measure(&key("new_blocker_issues")), Some(1.0));
        assert_eq!(new_code.measure(&key("new_major_issues")), Some(0.0));
        assert_eq!(new_code.measure(&key("blocker_issues")), None);
    }

    #[test]
    fn baseline_roundtrips_through_fingerprints() {
        let report = AnalysisReport::new(
            vec![issue("a", Severity::Minor), issue("b", Severity::Major)],
            vec![],
            Metrics::new(),
        );
        let baseline = Baseline::from_report(&report);
        let restored = Baseline::from_fingerprints(baseline.fingerprints());
        assert_eq!(baseline, restored);
        assert_eq!(restored.len(), 2);
    }
}
