//! Defects in generated code that no edit to the project can fix: the
//! engine's template or the blueprint is wrong. An agent that meets one
//! reports it here instead of patching around it, and `vord agent done`
//! stays "not done" until each is fixed upstream and resolved, or the user
//! accepts it.

use std::path::Path;
#[cfg(test)]
use std::path::PathBuf;

pub const DEFECTS_FILE: &str = ".vord/generator-defects.json";

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Defect {
    pub id: u32,
    pub engine: String,
    pub file: String,
    pub reason: String,
    /// `open`, `resolved` or `accepted`.
    pub status: String,
}

#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
struct Store {
    defects: Vec<Defect>,
}

fn load(root: &Path) -> Store {
    std::fs::read_to_string(root.join(DEFECTS_FILE))
        .ok()
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .unwrap_or_default()
}

fn save(root: &Path, store: &Store) -> anyhow::Result<()> {
    let path = root.join(DEFECTS_FILE);
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(path, serde_json::to_string_pretty(store)? + "\n")?;
    Ok(())
}

pub fn list(root: &Path) -> Vec<Defect> {
    load(root).defects
}

pub fn open(root: &Path) -> Vec<Defect> {
    list(root).into_iter().filter(|d| d.status == "open").collect()
}

/// Records a defect; an open one for the same engine, file and reason is
/// returned instead of duplicated.
pub fn report(root: &Path, engine: &str, file: &str, reason: &str) -> anyhow::Result<Defect> {
    if reason.trim().is_empty() {
        anyhow::bail!("say what is wrong with the generated code");
    }
    let mut store = load(root);
    if let Some(existing) = store
        .defects
        .iter()
        .find(|d| d.status == "open" && d.engine == engine && d.file == file && d.reason == reason)
    {
        return Ok(existing.clone());
    }
    let id = store.defects.iter().map(|d| d.id).max().unwrap_or(0) + 1;
    let defect = Defect {
        id,
        engine: engine.to_string(),
        file: file.to_string(),
        reason: reason.to_string(),
        status: "open".to_string(),
    };
    store.defects.push(defect.clone());
    save(root, &store)?;
    Ok(defect)
}

/// Marks a defect `resolved` (fixed in the engine, project regenerated) or
/// `accepted` (the user decided to live with it).
pub fn close(root: &Path, id: u32, status: &str) -> anyhow::Result<()> {
    let mut store = load(root);
    let defect = store
        .defects
        .iter_mut()
        .find(|d| d.id == id)
        .ok_or_else(|| anyhow::anyhow!("no defect #{id} in {}", DEFECTS_FILE))?;
    defect.status = status.to_string();
    save(root, &store)
}

/// Why the task cannot be done while defects are open.
pub fn blocking_reason(root: &Path) -> Option<String> {
    let open = open(root);
    if open.is_empty() {
        return None;
    }
    let lines: Vec<String> = open
        .iter()
        .map(|d| format!("#{} {} ({}): {}", d.id, d.file, d.engine, d.reason))
        .collect();
    Some(format!(
        "{} generator defect(s) still open ({}): fix the blueprint or the engine's template and regenerate, then `vord defects resolve <id>`; or have the user `vord defects accept <id>`",
        open.len(),
        lines.join("; ")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("vord-defects-{}-{}", std::process::id(), line!()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn open_defects_block_until_resolved_or_accepted() {
        let root = scratch();
        assert!(blocking_reason(&root).is_none());
        let first = report(&root, "ferrum", "backend/handlers/todos.rs", "imports Usuario").unwrap();
        let again = report(&root, "ferrum", "backend/handlers/todos.rs", "imports Usuario").unwrap();
        assert_eq!(first.id, again.id, "the same open defect is not duplicated");
        let second = report(&root, "ferrum", "backend/src/db/models.rs", "model has no id").unwrap();
        assert!(blocking_reason(&root).unwrap().contains("2 generator defect"));
        close(&root, first.id, "resolved").unwrap();
        close(&root, second.id, "accepted").unwrap();
        assert!(blocking_reason(&root).is_none());
        assert!(close(&root, 99, "resolved").is_err());
        assert!(report(&root, "x", "f", "  ").is_err());
        std::fs::remove_dir_all(&root).ok();
    }
}
