//! Monorepo (multi-project) discovery: finds every independent
//! vord-configured project under a scan root, so the CLI's `--monorepo`
//! mode can scan each one separately and attribute results per project
//! instead of flattening a whole tree of unrelated projects into one report.
//!
//! A project boundary is a directory containing a `vord.toml` — explicit
//! config, not the looser `.vord.toml`/`sonar-project.properties` forms
//! [`crate::VordConfig::load_from_dir`] also accepts, since a monorepo
//! layout should say so on purpose.

use std::path::{Path, PathBuf};

use ignore::WalkBuilder;

/// Every directory at or under `root` (root included) that contains a
/// `vord.toml`, sorted for deterministic output. Honors `.gitignore` like
/// [`crate::collect_sources`] does, so vendored/ignored subtrees (e.g. a
/// checked-out dependency that happens to carry its own `vord.toml`) aren't
/// picked up as projects.
pub fn discover_projects(root: &Path) -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = WalkBuilder::new(root)
        .build()
        .flatten()
        .filter(|entry| entry.file_type().is_some_and(|ft| ft.is_dir()))
        .map(|entry| entry.into_path())
        .filter(|dir| dir.join("vord.toml").is_file())
        .collect();
    found.sort();
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(path: &Path, contents: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, contents).unwrap();
    }

    fn scratch_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("vord-monorepo-test-{name}-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn discovers_every_vord_toml_under_the_root() {
        let root = scratch_dir("multi");
        write(
            &root.join("services/api/vord.toml"),
            "[project]\nkey = \"api\"\n",
        );
        write(
            &root.join("services/worker/vord.toml"),
            "[project]\nkey = \"worker\"\n",
        );
        write(&root.join("services/worker/src/main.rs"), "fn main() {}\n");

        let projects = discover_projects(&root);
        assert_eq!(
            projects,
            vec![root.join("services/api"), root.join("services/worker")]
        );

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn includes_the_root_itself_when_it_has_a_vord_toml() {
        let root = scratch_dir("root-project");
        write(&root.join("vord.toml"), "[project]\nkey = \"root\"\n");
        write(
            &root.join("nested/vord.toml"),
            "[project]\nkey = \"nested\"\n",
        );

        let projects = discover_projects(&root);
        assert_eq!(projects, vec![root.clone(), root.join("nested")]);

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn returns_empty_when_no_project_has_a_vord_toml() {
        let root = scratch_dir("none");
        write(&root.join("src/main.rs"), "fn main() {}\n");

        assert_eq!(discover_projects(&root), Vec::<PathBuf>::new());

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn does_not_descend_into_gitignored_subtrees() {
        let root = scratch_dir("gitignored");
        // `.gitignore` is only honored inside an actual git repo by default
        // (same walker configuration `collect_sources_scoped` uses) — a
        // bare `.git` directory is enough to satisfy that.
        std::fs::create_dir_all(root.join(".git")).unwrap();
        write(&root.join(".gitignore"), "vendor/\n");
        write(
            &root.join("vendor/dep/vord.toml"),
            "[project]\nkey = \"dep\"\n",
        );
        write(&root.join("app/vord.toml"), "[project]\nkey = \"app\"\n");

        assert_eq!(discover_projects(&root), vec![root.join("app")]);

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn ignores_the_looser_dot_vord_toml_and_sonar_properties_forms() {
        let root = scratch_dir("loose-config");
        write(
            &root.join("legacy/.vord.toml"),
            "[project]\nkey = \"legacy\"\n",
        );
        write(
            &root.join("legacy-sonar/sonar-project.properties"),
            "sonar.projectKey=old\n",
        );
        write(
            &root.join("explicit/vord.toml"),
            "[project]\nkey = \"explicit\"\n",
        );

        assert_eq!(discover_projects(&root), vec![root.join("explicit")]);

        std::fs::remove_dir_all(&root).ok();
    }
}
