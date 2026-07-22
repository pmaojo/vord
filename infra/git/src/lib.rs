//! Git Worktree Sandbox implementation for isolated remediation verification.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use yunq_remediation::{FixProposal, RemediationError, Sandbox};

pub struct GitWorktreeSandbox {
    root: PathBuf,
    backup: Mutex<Option<(PathBuf, String)>>,
}

impl GitWorktreeSandbox {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            backup: Mutex::new(None),
        }
    }
}

impl Sandbox for GitWorktreeSandbox {
    fn apply_proposal(&self, proposal: &FixProposal) -> Result<(), RemediationError> {
        let full_path = if proposal.file_path.is_absolute() {
            proposal.file_path.clone()
        } else {
            self.root.join(&proposal.file_path)
        };

        let current_content = fs::read_to_string(&full_path)
            .map_err(|e| RemediationError::SandboxError(format!("failed to read original file {}: {e}", full_path.display())))?;

        *self.backup.lock().unwrap() = Some((full_path.clone(), current_content.clone()));

        let new_content = current_content.replace(&proposal.original_snippet, &proposal.replacement_snippet);
        fs::write(&full_path, new_content)
            .map_err(|e| RemediationError::SandboxError(format!("failed to write proposal to {}: {e}", full_path.display())))?;

        Ok(())
    }

    fn read_source(&self, file_path: &Path) -> Result<String, RemediationError> {
        let full_path = if file_path.is_absolute() {
            file_path.to_path_buf()
        } else {
            self.root.join(file_path)
        };

        fs::read_to_string(&full_path)
            .map_err(|e| RemediationError::SandboxError(format!("failed to read modified source {}: {e}", full_path.display())))
    }

    fn rollback(&self) -> Result<(), RemediationError> {
        if let Some((path, content)) = self.backup.lock().unwrap().take() {
            fs::write(&path, content)
                .map_err(|e| RemediationError::SandboxError(format!("failed to rollback {}: {e}", path.display())))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn applies_proposal_and_rolls_back() {
        let temp_dir = std::env::temp_dir().join(format!("yunq_test_{}", rand::random::<u64>()));
        fs::create_dir_all(&temp_dir).unwrap();
        let file = temp_dir.join("test.txt");
        fs::write(&file, "foo bar baz").unwrap();

        let sandbox = GitWorktreeSandbox::new(&temp_dir);
        let proposal = FixProposal {
            file_path: file.clone(),
            explanation: "replace bar with fixed".to_string(),
            original_snippet: "bar".to_string(),
            replacement_snippet: "fixed".to_string(),
        };

        sandbox.apply_proposal(&proposal).unwrap();
        assert_eq!(sandbox.read_source(&file).unwrap(), "foo fixed baz");

        sandbox.rollback().unwrap();
        assert_eq!(sandbox.read_source(&file).unwrap(), "foo bar baz");

        let _ = fs::remove_dir_all(temp_dir);
    }
}
