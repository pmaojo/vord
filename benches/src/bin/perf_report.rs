//! Standalone performance report generator, independent of criterion (which
//! has no built-in CI-failing regression gate). Two modes:
//!
//! - `perf-report [--output <path>]`: scans the vendored corpus
//!   (`benches/corpus/rust/`) and reports aggregate throughput (LOC/s) plus
//!   per-file scan latency (p50/p99) and this process's peak RSS.
//! - `perf-report --compare <baseline.json> <current.json>`: loads two
//!   previously generated reports and exits non-zero if `current` regressed
//!   more than 10% in throughput versus `baseline` — used by
//!   `.github/workflows/ci.yml` to diff a PR's head against its merge base
//!   on the same runner, so the gate isn't skewed by comparing across
//!   different hardware.

use std::path::{Path, PathBuf};
use std::time::Instant;

use yunq_benchmarks::{PerfReport, is_regression, percentile};

fn corpus_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("corpus/rust")
}

fn rust_files_under(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return files;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            files.extend(rust_files_under(&path));
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            files.push(path);
        }
    }
    files
}

fn corpus_lines_of_code(files: &[PathBuf]) -> u64 {
    files
        .iter()
        .map(|path| {
            std::fs::read_to_string(path)
                .map(|c| c.lines().count() as u64)
                .unwrap_or(0)
        })
        .sum()
}

/// Linux-only: this process's peak resident set size so far, from
/// `/proc/self/status`'s `VmHWM` (high water mark), in kB.
fn peak_rss_kb() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    status
        .lines()
        .find_map(|line| line.strip_prefix("VmHWM:"))
        .and_then(|rest| rest.trim().trim_end_matches("kB").trim().parse().ok())
}

/// Repetitions per file for the p50/p99 sample — enough to smooth out
/// scheduler noise on a single small file without making CI slow.
const REPS_PER_FILE: usize = 3;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Some(pos) = args.iter().position(|a| a == "--compare") {
        let baseline_path = args
            .get(pos + 1)
            .expect("--compare needs <baseline.json> <current.json>");
        let current_path = args
            .get(pos + 2)
            .expect("--compare needs <baseline.json> <current.json>");
        compare(baseline_path, current_path);
        return;
    }

    let output_path = args
        .iter()
        .position(|a| a == "--output")
        .and_then(|i| args.get(i + 1))
        .cloned();
    let report = run_benchmark();
    let json = serde_json::to_string_pretty(&report).expect("PerfReport always serializes");
    println!("{json}");
    if let Some(path) = output_path {
        std::fs::write(&path, &json).unwrap_or_else(|e| panic!("failed to write {path}: {e}"));
    }
}

fn run_benchmark() -> PerfReport {
    let corpus = corpus_dir();
    let files = rust_files_under(&corpus);
    assert!(
        !files.is_empty(),
        "corpus at {corpus:?} is empty — check benches/corpus/rust/"
    );
    let loc = corpus_lines_of_code(&files);

    // Aggregate throughput: one whole-corpus scan, matching what the
    // criterion suite's `full_pipeline` benchmark measures, timed directly
    // so this binary needs no criterion dependency in its main path.
    let full_scan_start = Instant::now();
    futures::executor::block_on(yunq_cli::scan(&corpus)).expect("corpus scan succeeds");
    let full_scan_secs = full_scan_start.elapsed().as_secs_f64();
    let throughput_loc_per_sec = loc as f64 / full_scan_secs;

    // Per-file latency: each vendored file scanned independently and
    // repeatedly, so the sample is large enough for a meaningful p99.
    let mut per_file_ms = Vec::with_capacity(files.len() * REPS_PER_FILE);
    for file in &files {
        for _ in 0..REPS_PER_FILE {
            let start = Instant::now();
            futures::executor::block_on(yunq_cli::scan(file)).expect("file scan succeeds");
            per_file_ms.push(start.elapsed().as_secs_f64() * 1000.0);
        }
    }

    PerfReport {
        loc,
        throughput_loc_per_sec,
        p50_file_scan_ms: percentile(&per_file_ms, 50.0),
        p99_file_scan_ms: percentile(&per_file_ms, 99.0),
        peak_rss_kb: peak_rss_kb(),
    }
}

fn compare(baseline_path: &str, current_path: &str) {
    let baseline = load_report(baseline_path);
    let current = load_report(current_path);

    println!(
        "baseline throughput: {:.1} LOC/s",
        baseline.throughput_loc_per_sec
    );
    println!(
        "current throughput:  {:.1} LOC/s",
        current.throughput_loc_per_sec
    );
    println!(
        "baseline p50/p99 file scan: {:.2}ms / {:.2}ms",
        baseline.p50_file_scan_ms, baseline.p99_file_scan_ms
    );
    println!(
        "current  p50/p99 file scan: {:.2}ms / {:.2}ms",
        current.p50_file_scan_ms, current.p99_file_scan_ms
    );
    if let (Some(base_rss), Some(current_rss)) = (baseline.peak_rss_kb, current.peak_rss_kb) {
        println!("baseline peak RSS: {base_rss} kB");
        println!("current  peak RSS: {current_rss} kB");
    }

    if is_regression(
        baseline.throughput_loc_per_sec,
        current.throughput_loc_per_sec,
    ) {
        let drop_pct =
            100.0 * (1.0 - current.throughput_loc_per_sec / baseline.throughput_loc_per_sec);
        eprintln!(
            "REGRESSION: throughput dropped {drop_pct:.1}% versus baseline (> 10% threshold)"
        );
        std::process::exit(1);
    }
    println!("OK: within the 10% regression threshold");
}

fn load_report(path: &str) -> PerfReport {
    let contents =
        std::fs::read_to_string(path).unwrap_or_else(|e| panic!("failed to read {path}: {e}"));
    serde_json::from_str(&contents)
        .unwrap_or_else(|e| panic!("failed to parse {path} as a PerfReport: {e}"))
}
