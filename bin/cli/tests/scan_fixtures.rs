//! End-to-end vertical slice: real files → tree-sitter parsers → rules →
//! report, using the workspace `fixtures/` directory.

use std::collections::BTreeSet;
use std::path::Path;

#[test]
fn scans_fixtures_and_finds_every_rule_family() {
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures");
    let report = futures::executor::block_on(yunq_cli::scan(&fixtures)).unwrap();

    let fired: BTreeSet<String> =
        report.issues().iter().map(|i| i.rule().to_string()).collect();
    for expected in [
        "owasp:hardcoded-secret",
        "owasp:eval-usage",
        "owasp:injection",
        "owasp:cross-file-injection",
        "smells:todo-comment",
        "smells:long-function",
        "smells:unwrap-usage",
    ] {
        assert!(fired.contains(expected), "rule {expected} did not fire; fired: {fired:?}");
    }

    assert_eq!(report.metrics().files_scanned(), 5);
    assert_eq!(report.metrics().parse_failures(), 0);
    assert!(report.metrics().lines_of_code() > 50);
    assert!(report.metrics().debt_minutes() > 0);

    // The cross-file flow lands in caller.ts, tracing into lib_exec.ts.
    let cross = report
        .issues()
        .iter()
        .find(|i| i.rule().as_str() == "owasp:cross-file-injection")
        .expect("cross-file injection fires");
    assert!(cross.file().ends_with("caller.ts"));
    assert!(cross.message().contains("lib_exec.ts"));

    // OS-command hotspots fire as hotspots, not issues — Rust Command::new,
    // Python os.system, and the execSync inside lib_exec.ts.
    assert_eq!(report.hotspots().len(), 3);
    for hotspot in report.hotspots() {
        assert_eq!(hotspot.rule().as_str(), "owasp:command-execution");
    }

    // Python detections: eval issue and the hardcoded password.
    assert!(
        report
            .issues()
            .iter()
            .any(|i| i.file().ends_with("dirty.py") && i.rule().as_str() == "owasp:eval-usage")
    );
    assert!(
        report
            .issues()
            .iter()
            .any(|i| i.file().ends_with("dirty.py") && i.rule().as_str() == "owasp:hardcoded-secret")
    );

    // Every issue carries a real location inside the fixtures.
    for issue in report.issues() {
        assert!(issue.span().start_line >= 1);
        assert!(
            issue.file().ends_with(".ts")
                || issue.file().ends_with(".rs")
                || issue.file().ends_with(".py")
        );
    }
}
