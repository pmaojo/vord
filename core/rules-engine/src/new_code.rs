//! New Code classification (Clean as You Code): given a baseline of issue
//! fingerprints from a previous analysis, split the current report's issues
//! into new vs. pre-existing, and expose `new_*` measures for quality gates.

use std::hash::{DefaultHasher, Hash, Hasher};

use vord_profiles::{MetricKey, Severity};

use crate::domain::{AnalysisReport, Issue};

/// Clean as You Code period definition: specifies how pre-existing code is demarcated
/// from new/changed code across analyses.
#[allow(dead_code)]
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub enum NewCodePeriod {
    /// Compare against the previous analysis version / commit
    #[default]
    PreviousVersion,
    /// Compare against analysis from N days ago
    NDays(u32),
    /// Compare against the target reference branch (e.g. "main" or "master")
    ReferenceBranch(String),
    /// Compare against a specific historical analysis ID / commit SHA
    SpecificAnalysis(String),
}

/// Location-tolerant identity of an issue: rule + file + message. Moving
/// code within a file does not make its old issues "new". This is the
/// weakest signal in the tracking cascade below — a last resort — because
/// a message carrying a computed value (e.g.
/// "Cognitive Complexity of this function is 7, decrease it") changes text
/// on every trivial edit even though it is the same issue persisting.
pub fn issue_fingerprint(issue: &Issue) -> u64 {
    let mut hasher = DefaultHasher::new();
    issue.rule().as_str().hash(&mut hasher);
    issue.file().hash(&mut hasher);
    issue.message().hash(&mut hasher);
    hasher.finish()
}

/// Content hash of a source line, the primary signal in issue tracking:
/// two lines with the same rule and the same normalized content are the same
/// issue, regardless of what the rule's message says or which line number it
/// now sits on (covers both "untouched" and "line moved within the file").
/// Whitespace is stripped so reindentation/reformatting doesn't break a
/// match; any real edit to the line changes the hash.
pub fn line_hash(line: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    let normalized: String = line.chars().filter(|c| !c.is_whitespace()).collect();
    normalized.hash(&mut hasher);
    hasher.finish()
}

fn rule_file_key(issue: &Issue) -> u64 {
    let mut hasher = DefaultHasher::new();
    issue.rule().as_str().hash(&mut hasher);
    issue.file().hash(&mut hasher);
    hasher.finish()
}

/// One tracked occurrence from a previous analysis.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct BaselineEntry {
    rule_file: u64,
    fingerprint: u64,
    /// `None` for entries recovered from a legacy (fingerprint-only)
    /// baseline file, or captured without source access: such entries can
    /// only ever match via the fingerprint fallback.
    line_hash: Option<u64>,
}

/// The tracked issues from a previous analysis, matched against the current
/// one through the tracking cascade: content hash first (immune to message
/// text drift), (rule, file, message) fingerprint as the last-resort
/// fallback when no content hash is available on either side.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Baseline(Vec<BaselineEntry>);

impl Baseline {
    /// Rebuild from bare (rule, file, message) fingerprints with no content
    /// hash — every entry can only match through the fallback pass. Used to
    /// read old baseline files and by callers with no source-text access.
    pub fn from_fingerprints(fingerprints: impl IntoIterator<Item = u64>) -> Self {
        Self(
            fingerprints
                .into_iter()
                .map(|fingerprint| BaselineEntry {
                    rule_file: 0,
                    fingerprint,
                    line_hash: None,
                })
                .collect(),
        )
    }

    pub fn from_report(report: &AnalysisReport) -> Self {
        Self::from_report_with_source(report, |_, _| None)
    }

    /// `source` resolves an issue's (file, 1-based start line) to that
    /// line's content hash (`line_hash` over the real source text). Without
    /// it, tracking degrades to the fingerprint-only fallback.
    pub fn from_report_with_source(
        report: &AnalysisReport,
        source: impl Fn(&str, u32) -> Option<u64>,
    ) -> Self {
        Self(
            report
                .issues()
                .iter()
                .map(|issue| BaselineEntry {
                    rule_file: rule_file_key(issue),
                    fingerprint: issue_fingerprint(issue),
                    line_hash: source(issue.file(), issue.span().start_line),
                })
                .collect(),
        )
    }

    fn matches(&self, issue: &Issue, line_hash: Option<u64>) -> bool {
        if let Some(hash) = line_hash {
            let rule_file = rule_file_key(issue);
            let hash_match = self
                .0
                .iter()
                .any(|e| e.rule_file == rule_file && e.line_hash == Some(hash));
            if hash_match {
                return true;
            }
        }
        let fingerprint = issue_fingerprint(issue);
        self.0.iter().any(|e| e.fingerprint == fingerprint)
    }

    /// Fingerprint-only membership check (no content hash available).
    pub fn contains(&self, issue: &Issue) -> bool {
        self.matches(issue, None)
    }

    pub fn fingerprints(&self) -> impl Iterator<Item = u64> + '_ {
        self.0.iter().map(|e| e.fingerprint)
    }

    /// Raw `(rule_file, fingerprint, line_hash)` triples for persistence.
    /// Keeps this crate free of a serialization dependency: a storage
    /// adapter owns the on-disk schema and rebuilds via `from_entries`.
    pub fn entries(&self) -> impl Iterator<Item = (u64, u64, Option<u64>)> + '_ {
        self.0
            .iter()
            .map(|e| (e.rule_file, e.fingerprint, e.line_hash))
    }

    pub fn from_entries(entries: impl IntoIterator<Item = (u64, u64, Option<u64>)>) -> Self {
        Self(
            entries
                .into_iter()
                .map(|(rule_file, fingerprint, line_hash)| BaselineEntry {
                    rule_file,
                    fingerprint,
                    line_hash,
                })
                .collect(),
        )
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
        Self::classify_with_source(report, baseline, |_, _| None)
    }

    /// Like `classify`, but runs the content-hash pass of the tracking
    /// cascade too: `source` resolves an issue's (file, 1-based start line)
    /// to that line's content hash (see `line_hash`), letting an issue whose
    /// message text changed (e.g. a complexity count) still be recognized
    /// as pre-existing rather than reclassified as new.
    pub fn classify_with_source(
        report: &AnalysisReport,
        baseline: &Baseline,
        source: impl Fn(&str, u32) -> Option<u64>,
    ) -> Self {
        let new_issues = report
            .issues()
            .iter()
            .filter(|i| !baseline.matches(i, source(i.file(), i.span().start_line)))
            .cloned()
            .collect();
        Self { new_issues }
    }

    pub fn new_issues(&self) -> &[Issue] {
        &self.new_issues
    }

    /// `new_*` measures for gate conditions on new code; other keys → None
    /// so this composes with the overall report measures.
    pub fn measure(&self, key: &MetricKey) -> Option<f64> {
        let count_at = |severity: Severity| {
            self.new_issues
                .iter()
                .filter(|i| i.severity() == severity)
                .count() as f64
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

    /// Every `new_*` measure, keyed by metric key — the persisted
    /// counterpart to `AnalysisReport::all_measures()`, appended onto a
    /// completed analysis' measure set once a `Baseline` is available so
    /// measure history/component-tree queries see new-code counts too.
    pub fn all_measures(&self) -> Vec<(String, f64)> {
        const KEYS: [&str; 6] = [
            "new_issue_total",
            "new_blocker_issues",
            "new_critical_issues",
            "new_major_issues",
            "new_minor_issues",
            "new_info_issues",
        ];
        KEYS.iter()
            .map(|raw| {
                let key = MetricKey::new(raw)
                    .expect("all_measures keys are valid MetricKeys by construction");
                (
                    raw.to_string(),
                    self.measure(&key)
                        .expect("all_measures keys are all handled by measure()"),
                )
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use vord_ast::Span;
    use vord_profiles::RuleId;

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
        let second = AnalysisReport::new(vec![moved, fresh.clone()], vec![], Metrics::new());

        let new_code = NewCodeAnalysis::classify(&second, &baseline);
        assert_eq!(new_code.new_issues(), &[fresh]);

        let key = |raw: &str| MetricKey::new(raw).unwrap();
        assert_eq!(new_code.measure(&key("new_issue_total")), Some(1.0));
        assert_eq!(new_code.measure(&key("new_blocker_issues")), Some(1.0));
        assert_eq!(new_code.measure(&key("new_major_issues")), Some(0.0));
        assert_eq!(new_code.measure(&key("blocker_issues")), None);
    }

    #[test]
    fn all_measures_covers_every_new_severity_bucket() {
        let old = issue("old problem", Severity::Major);
        let baseline =
            Baseline::from_report(&AnalysisReport::new(vec![old], vec![], Metrics::new()));
        let fresh = issue("brand new problem", Severity::Blocker);
        let report = AnalysisReport::new(vec![fresh], vec![], Metrics::new());

        let new_code = NewCodeAnalysis::classify(&report, &baseline);
        let measures: std::collections::BTreeMap<String, f64> =
            new_code.all_measures().into_iter().collect();
        assert_eq!(measures.get("new_issue_total"), Some(&1.0));
        assert_eq!(measures.get("new_blocker_issues"), Some(&1.0));
        assert_eq!(measures.get("new_critical_issues"), Some(&0.0));
        assert_eq!(measures.get("new_major_issues"), Some(&0.0));
        assert_eq!(measures.get("new_minor_issues"), Some(&0.0));
        assert_eq!(measures.get("new_info_issues"), Some(&0.0));
        assert_eq!(measures.len(), 6);
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
        let mut original: Vec<u64> = baseline.fingerprints().collect();
        let mut round_tripped: Vec<u64> = restored.fingerprints().collect();
        original.sort_unstable();
        round_tripped.sort_unstable();
        assert_eq!(original, round_tripped);
        assert_eq!(restored.len(), 2);
    }

    /// Reproduces the confirmed gap: a rule whose message embeds a computed
    /// value (rule messages do this constantly, e.g. "Cognitive
    /// Complexity of this function is 7, decrease it") must not be
    /// reclassified as a brand-new issue just because a trivial, unrelated
    /// edit elsewhere in the function nudged that number — as long as the
    /// offending line's own content didn't change. The message-only
    /// fingerprint (the old behavior, still the fallback when no source is
    /// available) gets this wrong; the content-hash pass fixes it.
    #[test]
    fn content_hash_survives_message_drift_when_source_is_available() {
        let source_line = "    fn handler(a, b, c, d, e, f) {";
        let old = Issue::new(
            RuleId::new("test:complexity").unwrap(),
            Severity::Major,
            "Cognitive Complexity of this function is 7, decrease it",
            "a.rs",
            Span::new(10, 1, 10, 2),
        );
        let baseline_report = AnalysisReport::new(vec![old.clone()], vec![], Metrics::new());
        let baseline = Baseline::from_report_with_source(&baseline_report, |file, line| {
            (file == "a.rs" && line == 10).then(|| line_hash(source_line))
        });

        // Same rule, same line, same source line content — but the message
        // text changed because the computed complexity value went up by one.
        let drifted = Issue::new(
            old.rule().clone(),
            old.severity(),
            "Cognitive Complexity of this function is 8, decrease it",
            old.file(),
            old.span(),
        );
        let current_report = AnalysisReport::new(vec![drifted.clone()], vec![], Metrics::new());

        // With source access: the content-hash pass recognizes it as the
        // same, pre-existing issue.
        let tracked =
            NewCodeAnalysis::classify_with_source(&current_report, &baseline, |file, line| {
                (file == "a.rs" && line == 10).then(|| line_hash(source_line))
            });
        assert!(
            tracked.new_issues().is_empty(),
            "content hash should track through message drift"
        );

        // Without source access: falls back to the message fingerprint,
        // which legitimately can't tell these apart — matches prior behavior.
        let untracked = NewCodeAnalysis::classify(&current_report, &baseline);
        assert_eq!(untracked.new_issues(), &[drifted]);
    }

    #[test]
    fn content_hash_tracks_a_line_moved_within_the_file() {
        let source_line = "        eval(userInput);";
        let old = Issue::new(
            RuleId::new("test:eval").unwrap(),
            Severity::Blocker,
            "Do not call eval",
            "a.rs",
            Span::new(5, 1, 5, 2),
        );
        let baseline_report = AnalysisReport::new(vec![old.clone()], vec![], Metrics::new());
        let baseline = Baseline::from_report_with_source(&baseline_report, |_, _| {
            Some(line_hash(source_line))
        });

        // Same line content, but shifted down to line 20 by unrelated edits
        // above it; the message is untouched too, so both signals agree.
        let moved = Issue::new(
            old.rule().clone(),
            old.severity(),
            old.message(),
            old.file(),
            Span::new(20, 1, 20, 2),
        );
        let current_report = AnalysisReport::new(vec![moved], vec![], Metrics::new());

        let tracked = NewCodeAnalysis::classify_with_source(&current_report, &baseline, |_, _| {
            Some(line_hash(source_line))
        });
        assert!(tracked.new_issues().is_empty());
    }
}
