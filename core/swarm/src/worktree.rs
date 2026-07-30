//! Pure worktree-plan computation for `yunq swarm` (roadmap B1). No I/O:
//! this module decides *where* a role's worktree and branch belong; the git
//! shelling-out lives in `infra/fs::swarm_worktree`, mirroring the split
//! `infra/fs::WorktreeSandbox` already draws between "a worktree exists" and
//! "what happens inside one".

use std::path::{Path, PathBuf};

/// Directory (repository-relative) worktrees are created under when
/// `[swarm] worktree_root` is unset in `yunq.toml`.
pub const DEFAULT_WORKTREE_ROOT: &str = ".yunq/worktrees";

/// One `[[swarm.role]]` entry's worktree-relevant fields — a narrower type
/// than `infra/fs::RoleSettings` (which also carries the policy-scope
/// fields), so this crate never has to depend on `infra/fs`'s serde shape or
/// its I/O.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RoleWorktreeConfig {
    pub name: String,
    /// Worktree directory for this role, relative to the worktree root.
    /// Defaults to the role's own `name` when unset.
    pub worktree: Option<String>,
    /// Branch the worktree runs on. Defaults to `yunq/swarm/<name>` when
    /// unset.
    pub branch: Option<String>,
}

/// A role's resolved worktree isolation: an absolute directory and a branch
/// name, ready to hand to `git worktree add -b <branch> <path> <base>` with
/// no further joining.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorktreePlan {
    pub role: String,
    pub path: PathBuf,
    pub branch: String,
}

/// Computes where a role's worktree lives and what branch it runs on.
/// `repo_root` anchors the returned path — every caller wants an absolute
/// (or at least root-anchored) path to pass straight to `git`, not one it
/// has to join itself and risk getting wrong.
pub fn plan_worktree(repo_root: &Path, worktree_root: Option<&str>, role: &RoleWorktreeConfig) -> WorktreePlan {
    let root = worktree_root.unwrap_or(DEFAULT_WORKTREE_ROOT);
    let dir = role.worktree.as_deref().unwrap_or(role.name.as_str());
    let path = repo_root.join(root).join(dir);
    let branch = role.branch.clone().unwrap_or_else(|| format!("yunq/swarm/{}", role.name));
    WorktreePlan { role: role.name.clone(), path, branch }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn role(name: &str) -> RoleWorktreeConfig {
        RoleWorktreeConfig { name: name.to_string(), worktree: None, branch: None }
    }

    #[test]
    fn an_unconfigured_role_gets_the_default_root_and_branch_naming() {
        let plan = plan_worktree(Path::new("/repo"), None, &role("coder"));
        assert_eq!(plan.role, "coder");
        assert_eq!(plan.path, Path::new("/repo/.yunq/worktrees/coder"));
        assert_eq!(plan.branch, "yunq/swarm/coder");
    }

    #[test]
    fn a_configured_worktree_root_overrides_the_default() {
        let plan = plan_worktree(Path::new("/repo"), Some("tmp/agents"), &role("qa"));
        assert_eq!(plan.path, Path::new("/repo/tmp/agents/qa"));
    }

    #[test]
    fn a_role_can_override_its_own_worktree_directory_and_branch() {
        let mut cfg = role("qa");
        cfg.worktree = Some("quality".to_string());
        cfg.branch = Some("qa/custom-branch".to_string());
        let plan = plan_worktree(Path::new("/repo"), None, &cfg);
        assert_eq!(plan.path, Path::new("/repo/.yunq/worktrees/quality"));
        assert_eq!(plan.branch, "qa/custom-branch");
    }

    #[test]
    fn two_roles_never_collide_on_the_default_naming() {
        let coder = plan_worktree(Path::new("/repo"), None, &role("coder"));
        let architect = plan_worktree(Path::new("/repo"), None, &role("architect"));
        assert_ne!(coder.path, architect.path);
        assert_ne!(coder.branch, architect.branch);
    }
}
