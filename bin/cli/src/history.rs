//! Version-control history as a quality signal: per-file churn and
//! co-change counts for `vord refactor plan`.
//!
//! [`parse_numstat`] is a pure function over `git log --numstat` text, like
//! `blame::parse_porcelain_blame` is over blame porcelain — no
//! subprocess, unit-testable against fixture text. [`read_history`] is the
//! thin adapter that shells out to `git`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::Command;

use vord_agent::plan::FileHistory;

/// Marks a commit boundary in the `--format` we ask git for.
const COMMIT_MARKER: &str = "@@commit ";

/// A commit touching more files than this is a sweep (a reformat, a
/// rename-everything, a vendored drop): it still counts as churn for each
/// file, but pairing every file with every other would bury real coupling.
pub const MAX_FILES_FOR_CO_CHANGE: usize = 30;

/// Churn and co-change, keyed by repository-relative path.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct History {
    pub files: BTreeMap<String, FileHistory>,
    pub co_changes: BTreeMap<(String, String), u32>,
}

/// Parses `git log --no-merges --numstat --format=@@commit %H`. Renames
/// (`old => new` entries) are skipped — their line counts belong to a move,
/// not to either file's history of change. Binary files (`-` counts) count as
/// a commit with no line churn.
pub fn parse_numstat(text: &str) -> History {
    let mut history = History::default();
    let mut commit: BTreeSet<String> = BTreeSet::new();
    for line in text.lines() {
        if line.starts_with(COMMIT_MARKER) {
            flush(&mut history, &mut commit);
            continue;
        }
        let mut fields = line.splitn(3, '\t');
        let (Some(added), Some(deleted), Some(path)) =
            (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        if path.contains("=>") {
            continue;
        }
        let lines = added.parse::<u64>().unwrap_or(0) + deleted.parse::<u64>().unwrap_or(0);
        let entry = history.files.entry(path.to_string()).or_default();
        entry.churn += lines;
        commit.insert(path.to_string());
    }
    flush(&mut history, &mut commit);
    history
}

fn flush(history: &mut History, commit: &mut BTreeSet<String>) {
    for path in commit.iter() {
        if let Some(entry) = history.files.get_mut(path) {
            entry.commits += 1;
        }
    }
    if commit.len() <= MAX_FILES_FOR_CO_CHANGE {
        let paths: Vec<&String> = commit.iter().collect();
        for (i, a) in paths.iter().enumerate() {
            for b in &paths[i + 1..] {
                *history
                    .co_changes
                    .entry(((*a).clone(), (*b).clone()))
                    .or_insert(0) += 1;
            }
        }
    }
    commit.clear();
}

/// The last `since_days` of history under `root`. Not a git repository (or
/// no `git` on PATH) is an error: a plan without history would silently rank
/// by complexity alone, which is a different question.
pub fn read_history(root: &Path, since_days: u32) -> anyhow::Result<History> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args([
            "log",
            "--no-merges",
            "--numstat",
            &format!("--format={COMMIT_MARKER}%H"),
            &format!("--since={since_days}.days"),
        ])
        .output()
        .map_err(|e| anyhow::anyhow!("cannot run git: {e}"))?;
    if !output.status.success() {
        anyhow::bail!(
            "git log failed in {}: {}",
            root.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(parse_numstat(&String::from_utf8_lossy(&output.stdout)))
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOG: &str = "\
@@commit aaa
3\t1\tsrc/api.rs
2\t0\tdb/schema.sql

@@commit bbb
10\t5\tsrc/api.rs
-\t-\tassets/logo.png

@@commit ccc
1\t1\tsrc/{old.rs => new.rs}
4\t4\tsrc/api.rs
1\t0\tdb/schema.sql
";

    #[test]
    fn counts_commits_and_churn_per_file() {
        let history = parse_numstat(LOG);
        assert_eq!(
            history.files["src/api.rs"],
            FileHistory {
                commits: 3,
                churn: 4 + 15 + 8
            }
        );
        assert_eq!(history.files["assets/logo.png"].commits, 1);
        assert_eq!(history.files["assets/logo.png"].churn, 0);
    }

    #[test]
    fn skips_renames() {
        assert!(!parse_numstat(LOG).files.keys().any(|p| p.contains("=>")));
    }

    #[test]
    fn counts_co_changes_per_sorted_pair() {
        let history = parse_numstat(LOG);
        let pair = ("db/schema.sql".to_string(), "src/api.rs".to_string());
        assert_eq!(history.co_changes[&pair], 2);
    }

    #[test]
    fn a_sweeping_commit_adds_churn_but_no_co_changes() {
        let mut log = String::from("@@commit sweep\n");
        for i in 0..=MAX_FILES_FOR_CO_CHANGE {
            log.push_str(&format!("1\t0\tf{i}.rs\n"));
        }
        let history = parse_numstat(&log);
        assert_eq!(history.files.len(), MAX_FILES_FOR_CO_CHANGE + 1);
        assert!(history.co_changes.is_empty());
    }
}
