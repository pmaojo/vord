//! `vord prune`: the sanctioned way to remove generated files nobody needs
//! (a duplicate frontend, an engine's bundled templates). The write gate
//! refuses hand deletion of generated code because the next regeneration
//! would bring it back unnoticed; pruning records the decision and drops the
//! files from the manifest, so the gate stops guarding what no longer exists.

use std::path::Path;

use vord_cli::generated::Manifest;
use vord_agent_policy::generated::hole_count;

pub const PRUNED_FILE: &str = ".vord/pruned.json";

/// Removes `targets` (files or directories, relative to `root`). Refuses a
/// target that would take filled holes (hand-written code) with it unless
/// `force`. Returns the removed paths.
pub fn prune(root: &Path, targets: &[String], force: bool) -> anyhow::Result<Vec<String>> {
    let mut manifest = Manifest::load(root);
    let pending = vord_cli::holes::scan(root, ".");
    let mut removed = Vec::new();
    for target in targets {
        let relative = target.trim_start_matches("./").trim_end_matches('/');
        if relative.is_empty() || relative.starts_with("..") || Path::new(relative).is_absolute() {
            anyhow::bail!("{target:?} is not a path inside the project");
        }
        if relative == ".vord" || relative.starts_with(".vord/") {
            anyhow::bail!("{relative} is vord's own state; it is not pruned");
        }
        let path = root.join(relative);
        if !path.exists() {
            anyhow::bail!("{relative} does not exist");
        }
        let under = |file: &str| file == relative || file.starts_with(&format!("{relative}/"));
        let covered: Vec<String> = manifest.files.keys().filter(|f| under(f)).cloned().collect();
        if covered.is_empty() {
            anyhow::bail!("{relative} holds nothing recorded in .vord/generated.json; delete it normally");
        }
        if !force {
            for file in &covered {
                let Ok(content) = std::fs::read_to_string(root.join(file)) else { continue };
                let total = hole_count(&content);
                let open = pending.iter().filter(|h| &h.file == file).count();
                if total > open {
                    anyhow::bail!(
                        "{file} has {} filled hole(s): hand-written code that pruning would delete. Move it first, or pass --force",
                        total - open
                    );
                }
            }
        }
        if path.is_dir() {
            std::fs::remove_dir_all(&path)?;
        } else {
            std::fs::remove_file(&path)?;
        }
        for file in &covered {
            manifest.files.remove(file);
        }
        removed.push(relative.to_string());
    }
    manifest.save(root)?;
    let mut log: Vec<String> = std::fs::read_to_string(root.join(PRUNED_FILE))
        .ok()
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .unwrap_or_default();
    for path in &removed {
        if !log.contains(path) {
            log.push(path.clone());
        }
    }
    std::fs::write(root.join(PRUNED_FILE), serde_json::to_string_pretty(&log)? + "\n")?;
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use vord_cli::generated::GeneratedFile;

    fn project(tag: &str) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!("vord-prune-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("backend/frontend")).unwrap();
        std::fs::write(root.join("backend/frontend/a.tsx"), "// Code generated. DO NOT EDIT\n").unwrap();
        std::fs::write(
            root.join("backend/h.rs"),
            "// vord:hole x\nlet a = 1;\n// vord:end-hole\n",
        )
        .unwrap();
        let mut manifest = Manifest::default();
        for f in ["backend/frontend/a.tsx", "backend/h.rs"] {
            manifest.files.insert(f.to_string(), GeneratedFile { engine: "ferrum".into(), ..Default::default() });
        }
        manifest.save(&root).unwrap();
        root
    }

    #[test]
    fn prunes_a_generated_directory_and_forgets_it() {
        let root = project("dir");
        let removed = prune(&root, &["backend/frontend".to_string()], false).unwrap();
        assert_eq!(removed, ["backend/frontend"]);
        assert!(!root.join("backend/frontend").exists());
        let manifest = Manifest::load(&root);
        assert!(!manifest.files.contains_key("backend/frontend/a.tsx"));
        assert!(manifest.files.contains_key("backend/h.rs"));
        assert!(std::fs::read_to_string(root.join(PRUNED_FILE)).unwrap().contains("backend/frontend"));
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn refuses_filled_holes_and_foreign_paths() {
        let root = project("guard");
        let err = prune(&root, &["backend/h.rs".to_string()], false).unwrap_err().to_string();
        assert!(err.contains("filled hole"), "{err}");
        assert!(prune(&root, &["backend/h.rs".to_string()], true).is_ok(), "--force overrides");
        assert!(prune(&root, &["../x".to_string()], false).is_err());
        assert!(prune(&root, &[".vord/generated.json".to_string()], false).is_err());
        assert!(prune(&root, &["nothing".to_string()], false).is_err());
        std::fs::remove_dir_all(&root).ok();
    }
}
