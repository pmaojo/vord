//! End-to-end vertical slice: real files → tree-sitter parsers → rules →
//! report, using the workspace `fixtures/` directory.

use std::collections::BTreeSet;
use std::path::Path;

#[test]
fn scans_fixtures_and_finds_every_rule_family() {
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures");
    let report = futures::executor::block_on(vord_cli::scan(&fixtures)).unwrap();

    let fired: BTreeSet<String> = report
        .issues()
        .iter()
        .map(|i| i.rule().to_string())
        .collect();
    for expected in [
        "owasp:hardcoded-secret",
        "owasp:eval-usage",
        "owasp:injection",
        "owasp:cross-file-injection",
        "smells:todo-comment",
        "smells:long-function",
        "smells:unwrap-usage",
        "react:rules-of-hooks-conditional",
        "react:hook-missing-deps-array",
        "react:direct-state-mutation",
        "react:array-index-key",
        "react:jsx-img-missing-alt",
        "react:unsafe-target-blank",
        "react:inline-prop-function-in-component",
        // The hexagon fixture: layering, purity and tactical-DDD families,
        // proving the whole pipeline (composition root -> vord way profile ->
        // rule) is wired for them, not just their unit tests.
        "architecture:hexagonal-layer-violation",
        "architecture:framework-in-domain",
        "ddd:anemic-domain-model",
        "ddd:public-entity-setter",
        "ddd:aggregate-exposes-internal-collection",
        "ddd:persistence-in-domain",
        "ddd:primitive-obsession",
        "smells:type-check-chain",
        "smells:service-locator",
        // The WordPress fixture: every wordpress:* rule, proving the
        // composition-root wiring (rules chain + "vord way" profile
        // activation in core/profiles) end to end, not just their unit tests.
        "wordpress:unescaped-superglobal-output",
        "wordpress:unsanitized-superglobal-input",
        "wordpress:unprepared-wpdb-query",
        "wordpress:i18n-missing-text-domain",
        "wordpress:discouraged-function",
        "wordpress:global-variable-override",
        "wordpress:unsafe-plugin-menu-slug",
        "wordpress:unversioned-enqueued-resource",
        "wordpress:discouraged-constant",
        "wordpress:assignment-in-condition",
    ] {
        assert!(
            fired.contains(expected),
            "rule {expected} did not fire; fired: {fired:?}"
        );
    }

    assert_eq!(report.metrics().files_scanned(), 25);
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
    // Python os.system, and the execSync inside lib_exec.ts — plus the
    // `dangerouslySetInnerHTML` hotspot in the React fixture, plus one
    // `wordpress:nonce-verification-missing` hotspot per function in
    // wordpress_vulnerable.php that reads request data without a nonce check
    // (save_settings, render_greeting, store_email, redirect_after_login,
    // admin_menu).
    assert_eq!(report.hotspots().len(), 9);
    for hotspot in report.hotspots() {
        assert!(matches!(
            hotspot.rule().as_str(),
            "owasp:command-execution"
                | "react:dangerously-set-inner-html"
                | "wordpress:nonce-verification-missing"
        ));
    }

    // Python detections: eval issue and the hardcoded password.
    assert!(report
        .issues()
        .iter()
        .any(|i| i.file().ends_with("dirty.py") && i.rule().as_str() == "owasp:eval-usage"));
    assert!(report
        .issues()
        .iter()
        .any(|i| i.file().ends_with("dirty.py") && i.rule().as_str() == "owasp:hardcoded-secret"));

    // WordPress fixtures: wordpress_vulnerable.php trips every wordpress:*
    // rule (checked above); wordpress_clean.php is the same plugin written
    // the WPCS-approved way and must trip none of them — proves the ruleset
    // isn't just permissive enough to never fire, it actually discriminates.
    assert!(
        report
            .issues()
            .iter()
            .all(|i| !i.file().ends_with("wordpress_clean.php")
                || !i.rule().as_str().starts_with("wordpress:")),
        "wordpress_clean.php should trip no wordpress:* issues"
    );
    assert!(
        report
            .hotspots()
            .iter()
            .all(|h| !h.file().ends_with("wordpress_clean.php")
                || !h.rule().as_str().starts_with("wordpress:")),
        "wordpress_clean.php should trip no wordpress:* hotspots"
    );
    let wordpress_vulnerable_rules: BTreeSet<&str> = report
        .issues()
        .iter()
        .filter(|i| {
            i.file().ends_with("wordpress_vulnerable.php")
                && i.rule().as_str().starts_with("wordpress:")
        })
        .map(|i| i.rule().as_str())
        .collect();
    assert_eq!(
        wordpress_vulnerable_rules,
        BTreeSet::from([
            "wordpress:unescaped-superglobal-output",
            "wordpress:unsanitized-superglobal-input",
            "wordpress:unprepared-wpdb-query",
            "wordpress:i18n-missing-text-domain",
            "wordpress:discouraged-function",
            "wordpress:global-variable-override",
            "wordpress:unsafe-plugin-menu-slug",
            "wordpress:unversioned-enqueued-resource",
            "wordpress:discouraged-constant",
            "wordpress:assignment-in-condition",
        ])
    );

    // Go rides the same rules through its own grammar: a struct with receiver
    // methods, a `New<Type>` constructor function, `interface` ports, and
    // `import` paths resolved by package directory.
    let go_findings: Vec<&str> = report
        .issues()
        .iter()
        .filter(|i| i.file().ends_with(".go"))
        .map(|i| i.rule().as_str())
        .collect();
    for expected in [
        "architecture:framework-in-domain",
        "architecture:hexagonal-layer-violation",
        "ddd:public-entity-setter",
        "ddd:persistence-in-domain",
        "ddd:primitive-obsession",
    ] {
        assert!(
            go_findings.contains(&expected),
            "Go rule {expected} did not fire; got {go_findings:?}"
        );
    }

    // Rust rides the same rules through its own grammar:
    let rs_findings: Vec<&str> = report
        .issues()
        .iter()
        .filter(|i| i.file().ends_with("domain/order.rs"))
        .map(|i| i.rule().as_str())
        .collect();
    for expected in [
        "architecture:framework-in-domain",
        "architecture:hexagonal-layer-violation",
        "ddd:public-entity-setter",
        "ddd:persistence-in-domain",
        "ddd:primitive-obsession",
        "ddd:anemic-domain-model",
        "ddd:aggregate-exposes-internal-collection",
    ] {
        assert!(
            rs_findings.contains(&expected),
            "Rust rule {expected} did not fire on domain/order.rs; got {rs_findings:?}"
        );
    }

    // The layering finding points at the importing domain file and names the
    // infrastructure module it reaches into — the hexagon's direction, read off
    // path topology with no `[architecture]` config anywhere in the fixtures.
    let layering = report
        .issues()
        .iter()
        .find(|i| {
            i.rule().as_str() == "architecture:hexagonal-layer-violation"
                && i.file().ends_with(".ts")
        })
        .expect("hexagonal layering rule fires");
    assert!(
        layering.file().ends_with("domain/order.ts"),
        "got {}",
        layering.file()
    );
    assert!(
        layering.message().contains("infrastructure"),
        "got {}",
        layering.message()
    );

    // Every issue carries a real location inside the fixtures.
    for issue in report.issues() {
        assert!(issue.span().start_line >= 1);
        assert!(
            issue.file().ends_with(".ts")
                || issue.file().ends_with(".tsx")
                || issue.file().ends_with(".rs")
                || issue.file().ends_with(".py")
                || issue.file().ends_with(".go")
                || issue.file().ends_with(".tf")
                || issue.file().ends_with(".html")
                || issue.file().ends_with(".php")
        );
    }
}
