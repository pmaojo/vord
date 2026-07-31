//! Git worktree lifecycle for `yunq swarm` (roadmap B1) — the I/O half of
//! `yunq_swarm::worktree`, which only computes *where* a role's worktree and
//! branch belong. Shells out to `git worktree`, the same primitive
//! `infra/fs::WorktreeSandbox` already assumes exists once a worktree is
//! created; this module is what creates and tears one down.

use std::path::Path;
use std::process::Command;

use yunq_swarm::WorktreePlan;

#[derive(Debug, thiserror::Error)]
pub enum SwarmWorktreeError {
    #[error("failed to run `git {0}`: {1}")]
    Spawn(String, std::io::Error),
    #[error("git worktree add failed for role `{role}`: {stderr}")]
    Add { role: String, stderr: String },
    #[error("git worktree remove failed for role `{role}`: {stderr}")]
    Remove { role: String, stderr: String },
    #[error("git worktree list failed: {0}")]
    List(String),
}

fn run(repo_root: &Path, args: &[&str]) -> Result<std::process::Output, SwarmWorktreeError> {
    Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .args(args)
        .output()
        .map_err(|e| SwarmWorktreeError::Spawn(args.join(" "), e))
}

/// Creates the worktree `plan` describes, branching from `base_ref` (e.g.
/// `HEAD` or the repository's default branch). Idempotent in the one way
/// that matters for a swarm restarting after a crash: if `plan.branch`
/// already exists (a prior run created it), this attaches a new worktree to
/// the existing branch instead of failing, rather than demanding the caller
/// track which roles already have one.
pub fn create_worktree(
    repo_root: &Path,
    plan: &WorktreePlan,
    base_ref: &str,
) -> Result<(), SwarmWorktreeError> {
    if let Some(parent) = plan.path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let path = plan.path.to_string_lossy().into_owned();
    let output = run(
        repo_root,
        &["worktree", "add", "-b", &plan.branch, &path, base_ref],
    )?;
    if output.status.success() {
        return Ok(());
    }
    // The new-branch form failed — most likely because `plan.branch` already
    // exists from a prior run. Retry attaching to it directly; only report
    // the second failure, since the first message ("branch already exists")
    // would otherwise obscure whatever actually went wrong this time.
    let retry = run(repo_root, &["worktree", "add", &path, &plan.branch])?;
    if retry.status.success() {
        return Ok(());
    }
    Err(SwarmWorktreeError::Add {
        role: plan.role.clone(),
        stderr: String::from_utf8_lossy(&retry.stderr).into_owned(),
    })
}

/// Removes a role's worktree. `force` matches `git worktree remove --force`:
/// needed when the worktree has uncommitted changes a caller has already
/// decided are disposable (e.g. an abandoned or denied task).
pub fn remove_worktree(
    repo_root: &Path,
    plan: &WorktreePlan,
    force: bool,
) -> Result<(), SwarmWorktreeError> {
    let path = plan.path.to_string_lossy().into_owned();
    let mut args = vec!["worktree", "remove"];
    if force {
        args.push("--force");
    }
    args.push(&path);
    let output = run(repo_root, &args)?;
    if output.status.success() {
        return Ok(());
    }
    Err(SwarmWorktreeError::Remove {
        role: plan.role.clone(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    })
}

/// One entry from `git worktree list --porcelain`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorktreeStatus {
    pub path: String,
    pub branch: Option<String>,
}

/// Every worktree currently registered against this repository — not scoped
/// to swarm roles alone, since `git worktree list` has no concept of one; a
/// caller matches entries back to [`WorktreePlan`]s by `path`.
pub fn list_worktrees(repo_root: &Path) -> Result<Vec<WorktreeStatus>, SwarmWorktreeError> {
    let output = run(repo_root, &["worktree", "list", "--porcelain"])?;
    if !output.status.success() {
        return Err(SwarmWorktreeError::List(
            String::from_utf8_lossy(&output.stderr).into_owned(),
        ));
    }
    Ok(parse_worktree_list(&String::from_utf8_lossy(
        &output.stdout,
    )))
}

/// `git worktree list --porcelain` emits one blank-line-separated record per
/// worktree, each a run of `key value` lines (`worktree`, `HEAD`, `branch`,
/// or a bare `bare`/`detached` flag).
fn parse_worktree_list(raw: &str) -> Vec<WorktreeStatus> {
    let mut statuses = Vec::new();
    let mut path = None;
    let mut branch = None;
    for line in raw.lines() {
        if line.is_empty() {
            if let Some(p) = path.take() {
                statuses.push(WorktreeStatus {
                    path: p,
                    branch: branch.take(),
                });
            }
            continue;
        }
        if let Some(value) = line.strip_prefix("worktree ") {
            path = Some(value.to_string());
        } else if let Some(value) = line.strip_prefix("branch ") {
            branch = Some(value.trim_start_matches("refs/heads/").to_string());
        }
    }
    if let Some(p) = path {
        statuses.push(WorktreeStatus { path: p, branch });
    }
    statuses
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn init_repo() -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!(
            "yunq-swarm-worktree-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let git = |args: &[&str]| {
            let status = Command::new("git")
                .arg("-C")
                .arg(&root)
                .args(args)
                .status()
                .unwrap();
            assert!(status.success(), "git {args:?} failed");
        };
        git(&["init", "-q", "-b", "main"]);
        git(&["config", "user.email", "swarm@yunq.test"]);
        git(&["config", "user.name", "yunq swarm test"]);
        std::fs::write(root.join("README.md"), "hi\n").unwrap();
        git(&["add", "README.md"]);
        git(&["commit", "-q", "-m", "init"]);
        root.canonicalize().unwrap_or(root)
    }

    #[test]
    fn creates_lists_and_removes_a_role_worktree() {
        let root = init_repo();
        let plan = WorktreePlan {
            role: "coder".to_string(),
            path: root.join(".yunq/worktrees/coder"),
            branch: "yunq/swarm/coder".to_string(),
        };

        create_worktree(&root, &plan, "main").expect("create succeeds");
        assert!(
            plan.path.join("README.md").exists(),
            "the worktree should have the repo's files"
        );

        let listed = list_worktrees(&root).expect("list succeeds");
        assert!(
            listed.iter().any(|w| w.path == plan.path.to_string_lossy()
                && w.branch.as_deref() == Some("yunq/swarm/coder")),
            "expected the created worktree in {listed:?}"
        );

        remove_worktree(&root, &plan, false).expect("remove succeeds");
        assert!(!plan.path.exists(), "the worktree directory should be gone");

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn creating_the_same_role_twice_attaches_to_the_existing_branch_instead_of_failing() {
        let root = init_repo();
        let plan = WorktreePlan {
            role: "qa".to_string(),
            path: root.join(".yunq/worktrees/qa"),
            branch: "yunq/swarm/qa".to_string(),
        };

        create_worktree(&root, &plan, "main").expect("first create succeeds");
        remove_worktree(&root, &plan, false).expect("remove succeeds");

        // The branch `yunq/swarm/qa` still exists even though the worktree
        // directory is gone — recreating it must not fail as "branch already
        // exists" the way a naive `git worktree add -b` would.
        create_worktree(&root, &plan, "main")
            .expect("second create attaches to the existing branch");
        assert!(plan.path.exists());

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn parses_porcelain_output_with_multiple_entries() {
        let raw = "worktree /repo\nHEAD abc123\nbranch refs/heads/main\n\nworktree /repo/.yunq/worktrees/coder\nHEAD def456\nbranch refs/heads/yunq/swarm/coder\n\n";
        let parsed = parse_worktree_list(raw);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].path, "/repo");
        assert_eq!(parsed[0].branch.as_deref(), Some("main"));
        assert_eq!(parsed[1].branch.as_deref(), Some("yunq/swarm/coder"));
    }
}
