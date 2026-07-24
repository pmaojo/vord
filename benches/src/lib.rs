//! Pure helpers for the performance report (`bin/perf_report.rs`): percentile
//! computation and the regression-gate comparison, kept independent of
//! criterion/tokio/filesystem I/O so they're unit-testable without spinning
//! up a real benchmark run.

use serde::{Deserialize, Serialize};

/// The p-th percentile (0.0..=100.0) of `values`, via the nearest-rank
/// method over a copy sorted ascending. Returns 0.0 for an empty slice.
pub fn percentile(values: &[f64], p: f64) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    let mut sorted = values.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).expect("benchmark durations are never NaN"));
    let rank = ((p / 100.0) * (sorted.len() as f64 - 1.0)).round() as usize;
    sorted[rank.min(sorted.len() - 1)]
}

/// A single performance run, serialized to JSON so two runs (e.g. a PR
/// branch and its merge base) can be diffed by separate CI steps without
/// re-running the benchmark.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerfReport {
    pub loc: u64,
    pub throughput_loc_per_sec: f64,
    pub p50_file_scan_ms: f64,
    pub p99_file_scan_ms: f64,
    /// Peak resident set size in kB, Linux-only (`/proc/self/status`'s
    /// `VmHWM`) — `None` on platforms without `/proc`.
    pub peak_rss_kb: Option<u64>,
}

/// Fraction of baseline throughput below which `current` counts as a
/// regression: `0.9` means a drop of more than 10%.
pub const REGRESSION_THRESHOLD: f64 = 0.9;

/// Whether `current` throughput has regressed more than 10% from
/// `baseline`. A non-positive baseline never flags a regression — there's
/// nothing meaningful to compare against.
pub fn is_regression(baseline_throughput: f64, current_throughput: f64) -> bool {
    baseline_throughput > 0.0 && current_throughput < baseline_throughput * REGRESSION_THRESHOLD
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentile_of_empty_is_zero() {
        assert_eq!(percentile(&[], 99.0), 0.0);
    }

    #[test]
    fn p50_of_odd_length_is_the_middle_value() {
        assert_eq!(percentile(&[1.0, 3.0, 2.0], 50.0), 2.0);
    }

    #[test]
    fn p99_is_near_the_top_of_a_large_sample() {
        let values: Vec<f64> = (1..=100).map(|n| n as f64).collect();
        assert_eq!(percentile(&values, 99.0), 99.0);
    }

    #[test]
    fn percentile_is_order_independent() {
        let ascending: Vec<f64> = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        let shuffled: Vec<f64> = vec![3.0, 1.0, 5.0, 2.0, 4.0];
        assert_eq!(percentile(&ascending, 50.0), percentile(&shuffled, 50.0));
    }

    #[test]
    fn no_regression_within_ten_percent() {
        assert!(!is_regression(100.0, 91.0));
    }

    #[test]
    fn regression_flagged_past_ten_percent_drop() {
        assert!(is_regression(100.0, 89.0));
    }

    #[test]
    fn improvement_is_never_a_regression() {
        assert!(!is_regression(100.0, 150.0));
    }

    #[test]
    fn zero_or_negative_baseline_never_flags_a_regression() {
        assert!(!is_regression(0.0, 5.0));
        assert!(!is_regression(-10.0, 5.0));
    }

    #[test]
    fn perf_report_round_trips_through_json() {
        let report = PerfReport {
            loc: 12_345,
            throughput_loc_per_sec: 67_600.0,
            p50_file_scan_ms: 1.2,
            p99_file_scan_ms: 9.8,
            peak_rss_kb: Some(123_456),
        };
        let json = serde_json::to_string(&report).unwrap();
        let parsed: PerfReport = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.loc, report.loc);
        assert_eq!(parsed.peak_rss_kb, report.peak_rss_kb);
    }
}
