//! Criterion benchmark suite for yunq static analysis performance
//! verification — the ULTRA-performance pillar's ground truth
//! (`ROADMAP.md`'s target: >=100k LOC/s per core, sub-second incremental
//! re-analysis).
//!
//! `bench_full_pipeline_corpus` is the one that matters: it drives
//! `yunq_cli::scan`, the exact entry point the real CLI uses (every
//! registered parser, every registered rule, CPD, cross-file taint), over
//! a vendored ~12k-line real-world corpus (`benches/corpus/rust/` — this
//! repo's own `core`/`rulesets` sources, chosen because they're real,
//! already in the repo, and license-free to vendor), and reports
//! throughput as LOC/s via Criterion's `Throughput::Elements` — not just
//! wall-clock time, which is what the roadmap's target is actually
//! measured in. `bench_rust_parser` is a much cheaper single-function
//! sanity check on raw parse latency, kept from the original suite.

use std::path::{Path, PathBuf};

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use yunq_ast::{LanguageIdentifier, SourceFile};
use yunq_parser_rust::RustParser;
use yunq_rules_engine::AstParser;

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

/// Independent of anything `yunq_cli::scan` counts internally — a plain
/// newline count over the vendored files, so the throughput denominator
/// can't drift with engine changes (e.g. a future exclusion rule skipping
/// a file would still show up as a throughput drop, not silently shrink
/// the denominator to match).
fn corpus_lines_of_code(dir: &Path) -> u64 {
    rust_files_under(dir)
        .iter()
        .map(|path| {
            std::fs::read_to_string(path)
                .map(|c| c.lines().count() as u64)
                .unwrap_or(0)
        })
        .sum()
}

fn bench_rust_parser(c: &mut Criterion) {
    let code = r#"
fn calculate_sum(numbers: &[i32]) -> i32 {
    let mut total = 0;
    for &num in numbers {
        if num % 2 == 0 {
            total += num;
        } else {
            total -= num;
        }
    }
    total
}
"#;
    let file = SourceFile::new("bench.rs", code, LanguageIdentifier::rust()).unwrap();
    let parser = RustParser::new();

    c.bench_function("parse_rust_ast", |b| {
        b.iter(|| {
            parser.parse(&file).unwrap();
        })
    });
}

fn bench_full_pipeline_corpus(c: &mut Criterion) {
    let corpus = corpus_dir();
    let loc = corpus_lines_of_code(&corpus);
    assert!(
        loc > 0,
        "corpus at {corpus:?} is empty — check benches/corpus/rust/"
    );

    let mut group = c.benchmark_group("full_pipeline");
    group.throughput(Throughput::Elements(loc));
    // The full pipeline (23 parsers + full rule catalog + CPD + cross-file
    // taint registered) takes noticeably longer per iteration than a bare
    // parse; a smaller sample count keeps the suite fast without losing
    // the statistical noise floor Criterion needs to flag regressions.
    group.sample_size(20);
    group.bench_function("scan_corpus_rust_only", |b| {
        b.iter(|| {
            futures::executor::block_on(yunq_cli::scan(&corpus)).expect("corpus scan succeeds");
        })
    });
    group.finish();
}

criterion_group!(benches, bench_rust_parser, bench_full_pipeline_corpus);
criterion_main!(benches);
