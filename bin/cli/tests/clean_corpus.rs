//! Negative regression: production-style clean code must not trigger spurious
//! language-rule findings. Uses `corpus/clean/` (paths under `app/src/`, not
//! `fixtures/`) so rules that skip test/fixture paths are exercised too.

use std::path::Path;

const CLEAN_SUFFIXES: &[&str] = &["clean.py", "clean.ts", "clean.rs"];

fn is_clean_file(path: &str) -> bool {
    CLEAN_SUFFIXES.iter().any(|suffix| path.ends_with(suffix))
}

fn is_language_rule(rule: &str) -> bool {
    rule.starts_with("python:")
        || rule.starts_with("typescript:")
        || rule.starts_with("rust:")
        || rule.starts_with("owasp:")
        || rule.starts_with("smells:")
}

#[test]
fn clean_corpus_has_no_spurious_language_issues() {
    let corpus = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../corpus/clean");
    let report = futures::executor::block_on(yunq_cli::scan(&corpus)).unwrap();

    assert_eq!(report.metrics().parse_failures(), 0);

    let spurious: Vec<String> = report
        .issues()
        .iter()
        .filter(|issue| is_clean_file(issue.file()) && is_language_rule(issue.rule().as_str()))
        .map(|issue| {
            format!(
                "{}:{} {} — {}",
                issue.file(),
                issue.span().start_line,
                issue.rule(),
                issue.message()
            )
        })
        .collect();

    assert!(
        spurious.is_empty(),
        "spurious findings on clean corpus:\n{}",
        spurious.join("\n")
    );
}

#[test]
fn clean_corpus_command_hotspot_is_review_only() {
    let corpus = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../corpus/clean");
    let report = futures::executor::block_on(yunq_cli::scan(&corpus)).unwrap();

    let command_hotspots: Vec<_> = report
        .hotspots()
        .iter()
        .filter(|h| is_clean_file(h.file()) && h.rule().as_str() == "owasp:command-execution")
        .collect();

    assert_eq!(
        command_hotspots.len(),
        1,
        "subprocess.run in clean.py should produce exactly one review hotspot"
    );
    assert!(command_hotspots[0].file().ends_with("clean.py"));
}
