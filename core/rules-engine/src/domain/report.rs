use std::collections::BTreeMap;
use yunq_cpd::DuplicateBlock;
use yunq_profiles::{MetricKey, Rating, Severity};

use super::hotspot::{Hotspot, HotspotStatus};
use super::issue::Issue;

/// Aggregated counters for one analysis run.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Metrics {
    files_scanned: usize,
    files_skipped: usize,
    parse_failures: usize,
    cache_hits: usize,
    lines_of_code: usize,
    debt_minutes: usize,
    duplicated_lines: usize,
    duplicated_blocks: usize,
    by_severity: BTreeMap<Severity, usize>,
}

impl Metrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_file(&mut self, lines: usize) {
        self.files_scanned += 1;
        self.lines_of_code += lines;
    }

    pub fn add_skipped_file(&mut self) {
        self.files_skipped += 1;
    }

    pub fn add_parse_failure(&mut self) {
        self.parse_failures += 1;
    }

    pub fn add_cache_hit(&mut self) {
        self.cache_hits += 1;
    }

    pub fn add_debt(&mut self, minutes: usize) {
        self.debt_minutes += minutes;
    }

    pub fn set_duplication(&mut self, duplicated_lines: usize, duplicated_blocks: usize) {
        self.duplicated_lines = duplicated_lines;
        self.duplicated_blocks = duplicated_blocks;
    }

    pub fn count_issue(&mut self, severity: Severity) {
        *self.by_severity.entry(severity).or_default() += 1;
    }

    pub fn files_scanned(&self) -> usize {
        self.files_scanned
    }

    pub fn files_skipped(&self) -> usize {
        self.files_skipped
    }

    pub fn parse_failures(&self) -> usize {
        self.parse_failures
    }

    pub fn cache_hits(&self) -> usize {
        self.cache_hits
    }

    pub fn debt_minutes(&self) -> usize {
        self.debt_minutes
    }

    pub fn duplicated_lines(&self) -> usize {
        self.duplicated_lines
    }

    pub fn duplicated_blocks(&self) -> usize {
        self.duplicated_blocks
    }

    pub fn duplicated_lines_density(&self) -> f64 {
        if self.lines_of_code == 0 {
            0.0
        } else {
            self.duplicated_lines as f64 * 100.0 / self.lines_of_code as f64
        }
    }

    pub fn lines_of_code(&self) -> usize {
        self.lines_of_code
    }

    pub fn issues_by_severity(&self) -> &BTreeMap<Severity, usize> {
        &self.by_severity
    }

    pub fn issue_total(&self) -> usize {
        self.by_severity.values().sum()
    }
}

/// Line-coverage totals ingested from an external test-coverage report.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CoverageSummary {
    covered_lines: usize,
    coverable_lines: usize,
}

#[derive(Debug, thiserror::Error)]
#[error("covered lines ({covered}) cannot exceed coverable lines ({coverable})")]
pub struct InvalidCoverageError {
    pub covered: usize,
    pub coverable: usize,
}

impl CoverageSummary {
    pub fn new(covered_lines: usize, coverable_lines: usize) -> Result<Self, InvalidCoverageError> {
        if covered_lines > coverable_lines {
            return Err(InvalidCoverageError { covered: covered_lines, coverable: coverable_lines });
        }
        Ok(Self { covered_lines, coverable_lines })
    }

    pub fn add(&mut self, covered: usize, coverable: usize) -> Result<(), InvalidCoverageError> {
        if covered > coverable {
            return Err(InvalidCoverageError { covered, coverable });
        }
        self.covered_lines += covered;
        self.coverable_lines += coverable;
        Ok(())
    }

    pub fn covered_lines(&self) -> usize {
        self.covered_lines
    }

    pub fn coverable_lines(&self) -> usize {
        self.coverable_lines
    }

    pub fn percent(&self) -> Option<f64> {
        if self.coverable_lines == 0 {
            None
        } else {
            Some(self.covered_lines as f64 * 100.0 / self.coverable_lines as f64)
        }
    }
}

/// The complete output of one analysis run.
#[derive(Clone, Debug, PartialEq)]
pub struct AnalysisReport {
    issues: Vec<Issue>,
    hotspots: Vec<Hotspot>,
    coverage: Option<CoverageSummary>,
    duplications: Vec<DuplicateBlock>,
    metrics: Metrics,
}

impl AnalysisReport {
    pub fn new(issues: Vec<Issue>, hotspots: Vec<Hotspot>, metrics: Metrics) -> Self {
        Self { issues, hotspots, coverage: None, duplications: Vec::new(), metrics }
    }

    pub fn set_coverage(&mut self, coverage: CoverageSummary) {
        self.coverage = Some(coverage);
    }

    pub fn set_duplications(&mut self, duplications: Vec<DuplicateBlock>) {
        self.metrics.set_duplication(
            duplications.iter().map(|b| b.lines).sum(),
            duplications.len(),
        );
        self.duplications = duplications;
    }

    pub fn issues(&self) -> &[Issue] {
        &self.issues
    }

    pub fn hotspots(&self) -> &[Hotspot] {
        &self.hotspots
    }

    pub fn coverage(&self) -> Option<&CoverageSummary> {
        self.coverage.as_ref()
    }

    pub fn duplications(&self) -> &[DuplicateBlock] {
        &self.duplications
    }

    pub fn metrics(&self) -> &Metrics {
        &self.metrics
    }

    pub fn max_severity(&self) -> Option<Severity> {
        self.issues.iter().map(Issue::severity).max()
    }

    pub fn rating(&self) -> Rating {
        Rating::from_worst_severity(self.max_severity())
    }

    pub fn health_score(&self) -> u32 {
        let blocker = *self.metrics.issues_by_severity().get(&Severity::Blocker).unwrap_or(&0) as u32;
        let critical = *self.metrics.issues_by_severity().get(&Severity::Critical).unwrap_or(&0) as u32;
        let major = *self.metrics.issues_by_severity().get(&Severity::Major).unwrap_or(&0) as u32;
        let hotspots = self.hotspots.len() as u32;
        let dup_penalty = (self.metrics.duplicated_lines_density() * 0.5) as u32;

        let penalty = blocker * 10 + critical * 5 + major * 1 + hotspots * 2 + dup_penalty;
        100u32.saturating_sub(penalty)
    }

    pub fn measure(&self, key: &MetricKey) -> Option<f64> {
        let severity_count = |severity: Severity| {
            *self.metrics.issues_by_severity().get(&severity).unwrap_or(&0) as f64
        };
        match key.as_str() {
            "files_scanned" => Some(self.metrics.files_scanned() as f64),
            "lines_of_code" => Some(self.metrics.lines_of_code() as f64),
            "parse_failures" => Some(self.metrics.parse_failures() as f64),
            "issue_total" => Some(self.metrics.issue_total() as f64),
            "blocker_issues" => Some(severity_count(Severity::Blocker)),
            "critical_issues" => Some(severity_count(Severity::Critical)),
            "major_issues" => Some(severity_count(Severity::Major)),
            "minor_issues" => Some(severity_count(Severity::Minor)),
            "info_issues" => Some(severity_count(Severity::Info)),
            "hotspots" => Some(self.hotspots.len() as f64),
            "duplicated_lines" => Some(self.metrics.duplicated_lines() as f64),
            "duplicated_blocks" => Some(self.metrics.duplicated_blocks() as f64),
            "duplicated_lines_density" => Some(self.metrics.duplicated_lines_density()),
            "coverage" => self.coverage.and_then(|c| c.percent()),
            "hotspots_to_review" => Some(
                self.hotspots.iter().filter(|h| h.status() == HotspotStatus::ToReview).count()
                    as f64,
            ),
            "debt_minutes" => Some(self.metrics.debt_minutes() as f64),
            _ => None,
        }
    }
}
