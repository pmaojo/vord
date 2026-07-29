//! Discovers Rust crates under a scanned root by reading each `Cargo.toml`'s
//! `[package] name` — the piece `core/import-graph`'s Rust `use`-edge
//! resolution needs that TypeScript/Python's relative-import resolution
//! doesn't. A relative specifier (`./foo`) names its target file directly;
//! a Rust `use other_crate::Thing;` names a *crate identifier*
//! (hyphens replaced with underscores), which has no fixed relationship to
//! that crate's directory — `rulesets/architecture`'s package is
//! `yunq-rules-architecture`, not `yunq-rulesets-architecture`. Reading
//! manifests to recover that mapping is I/O, so it lives here, not in the
//! pure `core/import-graph` crate — the same split `discover_projects`
//! draws for `yunq.toml`.

use std::collections::HashMap;
use std::path::Path;

use ignore::WalkBuilder;

/// Rust identifier (crate name, hyphens replaced with underscores — the
/// form every `use`/path expression writes it in, e.g. `"yunq_infra_fs"`)
/// -> that crate's directory relative to `root` (empty string for a
/// `Cargo.toml` at `root` itself). Only manifests with a `[package]` table
/// count: a workspace root's own manifest is typically `[workspace]`-only
/// and is correctly skipped, same as any other non-package `Cargo.toml`.
/// Honors `.gitignore` like [`crate::collect_sources`], so a vendored
/// dependency checked into the tree doesn't get indexed as a workspace
/// member.
pub fn discover_rust_crates(root: &Path) -> HashMap<String, String> {
    let mut crates = HashMap::new();
    for entry in WalkBuilder::new(root).build().flatten() {
        if entry.file_name() != "Cargo.toml" {
            continue;
        }
        let Ok(content) = std::fs::read_to_string(entry.path()) else { continue };
        let Some(name) = package_name(&content) else { continue };
        let dir = entry.path().parent().unwrap_or(root);
        let relative = dir.strip_prefix(root).unwrap_or(dir).to_string_lossy().to_string();
        crates.insert(name.replace('-', "_"), relative);
    }
    crates
}

fn package_name(toml_content: &str) -> Option<String> {
    let value: toml::Value = toml::from_str(toml_content).ok()?;
    value.get("package")?.get("name")?.as_str().map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(path: &Path, contents: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, contents).unwrap();
    }

    fn scratch_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("yunq-rust-crates-test-{name}-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn indexes_a_nested_crate_by_its_underscored_package_name() {
        let root = scratch_dir("nested");
        write(
            &root.join("core/rules-engine/Cargo.toml"),
            "[package]\nname = \"yunq-rules-engine\"\nversion = \"0.1.0\"\n",
        );

        let crates = discover_rust_crates(&root);
        assert_eq!(crates.get("yunq_rules_engine").map(String::as_str), Some("core/rules-engine"));
    }

    #[test]
    fn skips_a_virtual_workspace_manifest_with_no_package_table() {
        let root = scratch_dir("virtual");
        write(&root.join("Cargo.toml"), "[workspace]\nmembers = [\"core/rules-engine\"]\n");
        write(
            &root.join("core/rules-engine/Cargo.toml"),
            "[package]\nname = \"yunq-rules-engine\"\nversion = \"0.1.0\"\n",
        );

        let crates = discover_rust_crates(&root);
        assert_eq!(crates.len(), 1);
        assert!(crates.contains_key("yunq_rules_engine"));
    }

    #[test]
    fn skips_an_unparseable_manifest() {
        let root = scratch_dir("broken");
        write(&root.join("broken/Cargo.toml"), "not valid toml {{{");

        assert!(discover_rust_crates(&root).is_empty());
    }
}
