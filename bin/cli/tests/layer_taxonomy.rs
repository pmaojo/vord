//! End-to-end: a declared `[[architecture.layer]]` taxonomy lets
//! `architecture:hexagonal-layer-violation` and `ddd:persistence-in-domain`
//! recognize a project-specific directory name (`checkout/`) as domain code,
//! with no change to the fixture's file layout — only to `vord.toml`.

use std::collections::BTreeSet;
use std::path::Path;

use vord_infra_fs::{ArchitectureSettings, LayerConfig};

fn fixture() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/layer-taxonomy")
}

fn fired_rules(architecture: &ArchitectureSettings) -> BTreeSet<String> {
    let report = futures::executor::block_on(vord_cli::scan_with_project_config(
        &fixture(),
        None,
        &[],
        &[],
        &[],
        &Default::default(),
        architecture,
    ))
    .unwrap();
    report
        .issues()
        .iter()
        .map(|i| i.rule().to_string())
        .collect()
}

#[test]
fn without_a_declared_taxonomy_the_custom_directory_name_is_invisible() {
    let fired = fired_rules(&ArchitectureSettings::default());
    assert!(
        !fired.contains("architecture:hexagonal-layer-violation"),
        "fired: {fired:?}"
    );
    assert!(
        !fired.contains("ddd:persistence-in-domain"),
        "fired: {fired:?}"
    );
}

#[test]
fn a_declared_taxonomy_makes_the_custom_directory_domain_code() {
    let architecture = ArchitectureSettings {
        layer: vec![LayerConfig {
            name: "checkout-domain".to_string(),
            is_a: "domain".to_string(),
            patterns: vec!["**/checkout/**".to_string()],
        }],
        ..Default::default()
    };
    let fired = fired_rules(&architecture);
    assert!(
        fired.contains("architecture:hexagonal-layer-violation"),
        "fired: {fired:?}"
    );
    assert!(
        fired.contains("ddd:persistence-in-domain"),
        "fired: {fired:?}"
    );
}

#[test]
fn an_unknown_parent_ring_fails_the_scan_instead_of_silently_classifying_nothing() {
    let architecture = ArchitectureSettings {
        layer: vec![LayerConfig {
            name: "checkout-domain".to_string(),
            is_a: "not-a-real-ring".to_string(),
            patterns: vec!["**/checkout/**".to_string()],
        }],
        ..Default::default()
    };
    let result = futures::executor::block_on(vord_cli::scan_with_project_config(
        &fixture(),
        None,
        &[],
        &[],
        &[],
        &Default::default(),
        &architecture,
    ));
    assert!(result.is_err());
}
