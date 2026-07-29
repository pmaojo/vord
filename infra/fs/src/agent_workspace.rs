//! Filesystem and process adapter for `yunq_agent::Workspace`: the tree the
//! agent actually edits.
//!
//! Two properties matter more here than anywhere else in this crate.
//!
//! **Nothing escapes the root.** Every path from the model is resolved
//! lexically against the repository root and rejected if it lands outside —
//! before the file is opened, because a `..`-traversal that only fails when
//! the target happens not to exist is not a control. `yunq-policy.toml`'s
//! `protected_path` globs are written against repository-relative paths, so a
//! write that escapes the root escapes the policy with it.
//!
//! **A command cannot hang the run.** `run` enforces a wall-clock timeout and
//! kills the child rather than blocking a session forever on a test suite
//! that deadlocked.

use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use yunq_agent::runtime::{CommandOutput, Workspace, WorkspaceError};

/// How long a `run` command may take before it is killed.
const DEFAULT_COMMAND_TIMEOUT: Duration = Duration::from_secs(300);
/// How often the watchdog checks on the child. Short enough to be responsive,
/// long enough not to spin a core.
const POLL_INTERVAL: Duration = Duration::from_millis(50);
/// Most matching lines one `search` returns. An unbounded grep over a large
/// repository would spend the agent's whole token budget in one tool call.
const MAX_SEARCH_HITS: usize = 200;

pub struct RepoWorkspace {
    root: PathBuf,
    timeout: Duration,
}

impl RepoWorkspace {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into(), timeout: DEFAULT_COMMAND_TIMEOUT }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Resolves a model-supplied path against the root, refusing anything
    /// that is absolute or that climbs out. Lexical on purpose: it has to
    /// work for a file that does not exist yet, which is most `write`s.
    fn resolve(&self, path: &str) -> Result<PathBuf, WorkspaceError> {
        let candidate = Path::new(path);
        if candidate.is_absolute() {
            return Err(WorkspaceError(format!(
                "`{path}` is absolute — paths must be relative to the repository root"
            )));
        }
        let mut resolved = self.root.clone();
        for component in candidate.components() {
            match component {
                Component::Normal(part) => resolved.push(part),
                Component::CurDir => {}
                Component::ParentDir => {
                    if !resolved.pop() || !resolved.starts_with(&self.root) {
                        return Err(escape(path));
                    }
                }
                Component::RootDir | Component::Prefix(_) => return Err(escape(path)),
            }
        }
        if !resolved.starts_with(&self.root) {
            return Err(escape(path));
        }
        Ok(resolved)
    }
}

fn escape(path: &str) -> WorkspaceError {
    WorkspaceError(format!("`{path}` resolves outside the repository root — refused"))
}

impl Workspace for RepoWorkspace {
    fn read(&self, path: &str) -> Result<String, WorkspaceError> {
        let target = self.resolve(path)?;
        std::fs::read_to_string(&target).map_err(|e| WorkspaceError(format!("cannot read `{path}`: {e}")))
    }

    fn write(&self, path: &str, content: &str) -> Result<(), WorkspaceError> {
        let target = self.resolve(path)?;
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| WorkspaceError(format!("cannot create `{}`: {e}", parent.display())))?;
        }
        std::fs::write(&target, content).map_err(|e| WorkspaceError(format!("cannot write `{path}`: {e}")))
    }

    fn search(&self, pattern: &str, path: Option<&str>) -> Result<String, WorkspaceError> {
        let regex = regex::Regex::new(pattern)
            .map_err(|e| WorkspaceError(format!("`{pattern}` is not a valid regular expression: {e}")))?;
        let scope = match path {
            Some(path) => self.resolve(path)?,
            None => self.root.clone(),
        };
        let hits = search_tree(&regex, &scope, &self.root);
        if hits.is_empty() {
            return Ok(format!("no matches for `{pattern}`"));
        }
        Ok(hits.join("\n"))
    }

    fn run(&self, program: &str, args: &[String]) -> Result<CommandOutput, WorkspaceError> {
        let child = Command::new(program)
            .args(args)
            .current_dir(&self.root)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| WorkspaceError(format!("cannot run `{program}`: {e}")))?;
        wait_with_timeout(child, self.timeout, program)
    }
}

/// Waits for `child`, killing it if it outlives `timeout`. A killed child is
/// reported as a `run` failure rather than an empty success — a test suite
/// that hung is not a test suite that passed.
fn wait_with_timeout(
    mut child: std::process::Child,
    timeout: Duration,
    program: &str,
) -> Result<CommandOutput, WorkspaceError> {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {}
            Err(e) => return Err(WorkspaceError(format!("cannot wait on `{program}`: {e}"))),
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(WorkspaceError(format!(
                "`{program}` exceeded the {}s command timeout and was killed",
                timeout.as_secs()
            )));
        }
        std::thread::sleep(POLL_INTERVAL);
    }
    let output = child
        .wait_with_output()
        .map_err(|e| WorkspaceError(format!("cannot collect `{program}` output: {e}")))?;
    Ok(CommandOutput {
        exit_code: output.status.code(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    })
}

/// `file:line: text` for every matching line, honouring `.gitignore` — the
/// agent should not be reading `target/` back into its own context.
fn search_tree(regex: &regex::Regex, scope: &Path, root: &Path) -> Vec<String> {
    let mut hits = Vec::new();
    for entry in ignore::WalkBuilder::new(scope).build().flatten() {
        if !entry.file_type().is_some_and(|kind| kind.is_file()) {
            continue;
        }
        let Ok(content) = std::fs::read_to_string(entry.path()) else { continue };
        let relative = entry.path().strip_prefix(root).unwrap_or(entry.path()).display().to_string();
        for (index, line) in content.lines().enumerate() {
            if hits.len() >= MAX_SEARCH_HITS {
                hits.push(format!("… truncated at {MAX_SEARCH_HITS} matches"));
                return hits;
            }
            if regex.is_match(line) {
                hits.push(format!("{relative}:{}: {}", index + 1, line.trim_end()));
            }
        }
    }
    hits
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_root(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!("yunq-agent-workspace-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("temp root");
        root
    }

    #[test]
    fn a_write_lands_and_reads_back() {
        let root = temp_root("roundtrip");
        let workspace = RepoWorkspace::new(&root);
        workspace.write("src/a.rs", "fn a() {}").unwrap();
        assert_eq!(workspace.read("src/a.rs").unwrap(), "fn a() {}");
        assert!(root.join("src/a.rs").exists(), "parent directories are created");
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn a_traversal_out_of_the_root_is_refused_before_touching_the_disk() {
        let root = temp_root("traversal");
        let workspace = RepoWorkspace::new(&root);
        let error = workspace.write("../escaped.rs", "x").unwrap_err();
        assert!(error.to_string().contains("outside the repository root"), "{error}");
        assert!(!root.parent().unwrap().join("escaped.rs").exists());
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn an_absolute_path_is_refused() {
        let workspace = RepoWorkspace::new(temp_root("absolute"));
        let error = workspace.write("/etc/passwd", "x").unwrap_err();
        assert!(error.to_string().contains("absolute"), "{error}");
        std::fs::remove_dir_all(workspace.root()).ok();
    }

    #[test]
    fn a_traversal_that_returns_inside_the_root_is_allowed() {
        let root = temp_root("returns-inside");
        let workspace = RepoWorkspace::new(&root);
        workspace.write("src/../a.rs", "x").unwrap();
        assert!(root.join("a.rs").exists());
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn search_reports_the_file_and_line_of_each_match() {
        let root = temp_root("search");
        let workspace = RepoWorkspace::new(&root);
        workspace.write("src/a.rs", "fn a() {}\nfn target() {}\n").unwrap();
        let hits = workspace.search("fn target", None).unwrap();
        assert!(hits.contains("src/a.rs:2"), "{hits}");
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn search_says_so_when_there_is_nothing_rather_than_returning_empty() {
        let root = temp_root("search-empty");
        let workspace = RepoWorkspace::new(&root);
        workspace.write("src/a.rs", "fn a() {}").unwrap();
        assert!(workspace.search("nowhere", None).unwrap().contains("no matches"));
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn an_invalid_regex_is_an_error_the_agent_can_read() {
        let workspace = RepoWorkspace::new(temp_root("bad-regex"));
        let error = workspace.search("[unclosed", None).unwrap_err();
        assert!(error.to_string().contains("not a valid regular expression"), "{error}");
        std::fs::remove_dir_all(workspace.root()).ok();
    }

    #[test]
    fn a_command_runs_in_the_root_and_reports_its_exit_code() {
        let root = temp_root("run");
        let workspace = RepoWorkspace::new(&root);
        let output = workspace.run("true", &[]).unwrap();
        assert_eq!(output.exit_code, Some(0));
        let failed = workspace.run("false", &[]).unwrap();
        assert_eq!(failed.exit_code, Some(1));
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn a_command_that_outlives_its_timeout_is_killed_and_reported() {
        let root = temp_root("timeout");
        let workspace = RepoWorkspace::new(&root).with_timeout(Duration::from_millis(100));
        let error = workspace.run("sleep", &["30".to_string()]).unwrap_err();
        assert!(error.to_string().contains("timeout"), "{error}");
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn a_missing_program_is_an_error_not_a_panic() {
        let root = temp_root("missing-program");
        let workspace = RepoWorkspace::new(&root);
        assert!(workspace.run("definitely-not-a-real-program", &[]).is_err());
        std::fs::remove_dir_all(&root).ok();
    }
}
