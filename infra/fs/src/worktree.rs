use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use yunq_remediation::{FixProposal, RemediationError, Sandbox};

/// Filesystem adapter for a pre-created Git worktree. It never follows a
/// proposal path outside `root` and remembers original contents for rollback.
pub struct WorktreeSandbox {
    root: PathBuf,
    originals: Mutex<HashMap<PathBuf, String>>,
}

impl WorktreeSandbox {
    pub fn new(root: impl AsRef<Path>) -> Result<Self, RemediationError> {
        let root = root
            .as_ref()
            .canonicalize()
            .map_err(|error| RemediationError::SandboxError(error.to_string()))?;
        if !root.join(".git").exists() {
            return Err(RemediationError::SandboxError(
                "sandbox root must be a Git worktree".to_string(),
            ));
        }
        Ok(Self { root, originals: Mutex::new(HashMap::new()) })
    }

    fn resolve(&self, file_path: &Path) -> Result<PathBuf, RemediationError> {
        let candidate = if file_path.is_absolute() {
            file_path.to_path_buf()
        } else {
            self.root.join(file_path)
        };
        let canonical = candidate
            .canonicalize()
            .map_err(|error| RemediationError::SandboxError(error.to_string()))?;
        if canonical.starts_with(&self.root) {
            Ok(canonical)
        } else {
            Err(RemediationError::SandboxError(
                "proposal path escapes the sandbox worktree".to_string(),
            ))
        }
    }
}

impl Sandbox for WorktreeSandbox {
    fn apply_proposal(&self, proposal: &FixProposal) -> Result<(), RemediationError> {
        if proposal.original_snippet.is_empty() {
            return Err(RemediationError::SandboxError(
                "proposal snippet must not be empty".to_string(),
            ));
        }
        let target = self.resolve(&proposal.file_path)?;
        let source = std::fs::read_to_string(&target)
            .map_err(|error| RemediationError::SandboxError(error.to_string()))?;
        let occurrences = source.matches(&proposal.original_snippet).count();
        if occurrences != 1 {
            return Err(RemediationError::SandboxError(format!(
                "proposal snippet must match exactly once, matched {occurrences} times"
            )));
        }
        let updated = source.replacen(&proposal.original_snippet, &proposal.replacement_snippet, 1);
        self.originals
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .entry(target.clone())
            .or_insert(source);
        std::fs::write(target, updated).map_err(|error| RemediationError::SandboxError(error.to_string()))
    }

    fn read_source(&self, file_path: &Path) -> Result<String, RemediationError> {
        let target = self.resolve(file_path)?;
        std::fs::read_to_string(target).map_err(|error| RemediationError::SandboxError(error.to_string()))
    }

    fn rollback(&self) -> Result<(), RemediationError> {
        let originals = std::mem::take(
            &mut *self
                .originals
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
        );
        for (path, source) in originals {
            std::fs::write(path, source).map_err(|error| RemediationError::SandboxError(error.to_string()))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    #[test]
    fn applies_reads_and_rolls_back_inside_the_worktree() {
        let root = std::env::temp_dir().join(format!(
            "yunq-worktree-sandbox-{}",
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(root.join(".git")).unwrap();
        let source = root.join("src.rs");
        std::fs::write(&source, "let value = 1;\n").unwrap();
        let sandbox = WorktreeSandbox::new(&root).unwrap();
        let proposal = FixProposal {
            file_path: source.clone(),
            explanation: "test".to_string(),
            original_snippet: "1".to_string(),
            replacement_snippet: "2".to_string(),
        };

        sandbox.apply_proposal(&proposal).unwrap();
        assert_eq!(sandbox.read_source(&source).unwrap(), "let value = 2;\n");
        sandbox.rollback().unwrap();
        assert_eq!(std::fs::read_to_string(&source).unwrap(), "let value = 1;\n");

        std::fs::remove_dir_all(root).unwrap();
    }
}
