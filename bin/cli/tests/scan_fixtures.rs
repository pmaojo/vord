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
        "smells:todo-comment",
        "smells:long-function",
        "smells:unwrap-usage",
    ] {
        assert!(fired.contains(expected), "rule {expected} did not fire; fired: {fired:?}");
    }

    assert_eq!(report.metrics().files_scanned(), 2);
    assert_eq!(report.metrics().parse_failures(), 0);
    assert!(report.metrics().lines_of_code() > 50);

    // Every issue carries a real location inside the fixtures.
    for issue in report.issues() {
        assert!(issue.span().start_line >= 1);
        assert!(issue.file().ends_with(".ts") || issue.file().ends_with(".rs"));
    }
}
