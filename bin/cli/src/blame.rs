//! SCM blame capture: per-line author/commit attribution for files touched
//! by a scan, made available via `--blame-output` in a shape a later
//! consumer (e.g. issue #26's sources endpoint) can render alongside an
//! issue ("who introduced this line").
//!
//! [`parse_porcelain_blame`] is a pure function over `git blame --porcelain`
//! text — no subprocess, no filesystem — so it's unit-testable against
//! fixture text. [`blame_file`]/[`blame_files`] are the thin adapter that
//! actually shells out to `git`; no new dependency (`git2`, etc.) needed for
//! this — the repo has none in its dependency tree and the porcelain format
//! is simple enough to parse directly.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::process::Command;

/// One source line's blame: which commit last touched it and who authored
/// that commit.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct BlameLine {
    /// 1-based line number in the file's current content.
    pub line: u32,
    pub commit: String,
    pub author: String,
    pub author_mail: String,
    /// Unix timestamp (seconds) from the commit's `author-time`.
    pub author_time: i64,
    pub summary: String,
}

#[derive(Default, Clone)]
struct CommitMeta {
    author: String,
    author_mail: String,
    author_time: i64,
    summary: String,
}

/// A blame header line: `<40-hex-sha> <orig-line> <final-line> [<count>]`.
/// Distinguishes a new commit group from a repeated one (which omits the
/// `author`/`summary`/etc. detail lines and reuses the first group's).
struct Header {
    sha: String,
    final_line: u32,
}

fn parse_header_line(line: &str) -> Option<Header> {
    let mut parts = line.split(' ');
    let sha = parts.next()?;
    if sha.len() != 40 || !sha.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let _orig_line = parts.next()?;
    let final_line: u32 = parts.next()?.parse().ok()?;
    Some(Header {
        sha: sha.to_string(),
        final_line,
    })
}

/// Strips the surrounding quotes `git blame --porcelain` puts around
/// `author-mail` (`<user@example.com>`), keeping just the address.
fn strip_angle_brackets(raw: &str) -> String {
    raw.trim()
        .trim_start_matches('<')
        .trim_end_matches('>')
        .to_string()
}

/// Parses `git blame --porcelain <file>` output into one [`BlameLine`] per
/// line of the file, in file order. Lines that don't fit the expected shape
/// are skipped rather than treated as fatal — blame is best-effort metadata,
/// never something a scan should fail over.
pub fn parse_porcelain_blame(porcelain: &str) -> Vec<BlameLine> {
    let mut commits: HashMap<String, CommitMeta> = HashMap::new();
    let mut result = Vec::new();
    let mut current: Option<Header> = None;

    for line in porcelain.lines() {
        if let Some(content) = line.strip_prefix('\t') {
            let _ = content; // line content itself isn't needed by the DTO.
            if let Some(header) = &current {
                let meta = commits.get(&header.sha).cloned().unwrap_or_default();
                result.push(BlameLine {
                    line: header.final_line,
                    commit: header.sha.clone(),
                    author: meta.author,
                    author_mail: meta.author_mail,
                    author_time: meta.author_time,
                    summary: meta.summary,
                });
            }
            continue;
        }

        if let Some(header) = parse_header_line(line) {
            commits.entry(header.sha.clone()).or_default();
            current = Some(header);
            continue;
        }

        let Some(sha) = current.as_ref().map(|h| h.sha.clone()) else {
            continue;
        };
        let meta = commits.entry(sha).or_default();
        if let Some(rest) = line.strip_prefix("author-mail ") {
            meta.author_mail = strip_angle_brackets(rest);
        } else if let Some(rest) = line.strip_prefix("author-time ") {
            meta.author_time = rest.trim().parse().unwrap_or(0);
        } else if let Some(rest) = line.strip_prefix("author ") {
            meta.author = rest.trim().to_string();
        } else if let Some(rest) = line.strip_prefix("summary ") {
            meta.summary = rest.trim().to_string();
        }
    }

    result
}

/// Runs `git blame --porcelain` on one file (relative to `repo_root`) and
/// parses the result. `None` on any failure (not a git repo, file not
/// tracked, binary file, git missing, ...) — blame is supplementary, so
/// callers should warn and continue rather than fail the scan.
pub fn blame_file(repo_root: &Path, file: &str) -> Option<Vec<BlameLine>> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .arg("blame")
        .arg("--porcelain")
        .arg(file)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?;
    Some(parse_porcelain_blame(&text))
}

/// Blames every file in `files` (each relative to `repo_root`), skipping any
/// file blame fails for. Returned as a map (ordered by file path, so JSON
/// output is deterministic) so serialization keeps the per-file attribution
/// the sources endpoint (issue #26) needs rather than flattening everything
/// into one undifferentiated line list.
pub fn blame_files(repo_root: &Path, files: &[String]) -> BTreeMap<String, Vec<BlameLine>> {
    files
        .iter()
        .filter_map(|file| blame_file(repo_root, file).map(|lines| (file.clone(), lines)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_single_commit_group() {
        let porcelain = "\
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 1 1 2
author Jane Doe
author-mail <jane@example.com>
author-time 1700000000
author-tz +0000
committer Jane Doe
committer-mail <jane@example.com>
committer-time 1700000000
committer-tz +0000
summary Initial commit
filename src/lib.rs
\tfn main() {}
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 2 2
\t}
";
        let lines = parse_porcelain_blame(porcelain);
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].line, 1);
        assert_eq!(lines[0].commit, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        assert_eq!(lines[0].author, "Jane Doe");
        assert_eq!(lines[0].author_mail, "jane@example.com");
        assert_eq!(lines[0].author_time, 1700000000);
        assert_eq!(lines[0].summary, "Initial commit");
        // Second line reuses the same commit's metadata via the abbreviated header.
        assert_eq!(lines[1].line, 2);
        assert_eq!(lines[1].author, "Jane Doe");
    }

    #[test]
    fn parses_multiple_commits_without_mixing_up_metadata() {
        let porcelain = "\
1111111111111111111111111111111111111111 1 1 1
author Alice
author-mail <alice@example.com>
author-time 1000
summary First
filename f.rs
\tline one
2222222222222222222222222222222222222222 2 2 1
author Bob
author-mail <bob@example.com>
author-time 2000
summary Second
filename f.rs
\tline two
";
        let lines = parse_porcelain_blame(porcelain);
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].author, "Alice");
        assert_eq!(lines[0].author_mail, "alice@example.com");
        assert_eq!(lines[1].author, "Bob");
        assert_eq!(lines[1].author_mail, "bob@example.com");
    }

    #[test]
    fn ignores_malformed_input_without_panicking() {
        assert_eq!(parse_porcelain_blame(""), Vec::new());
        assert_eq!(
            parse_porcelain_blame("not a valid porcelain blob\nrandom text"),
            Vec::new()
        );
    }

    #[test]
    fn header_parser_rejects_non_sha_first_token() {
        assert!(parse_header_line("author Jane Doe").is_none());
        assert!(parse_header_line("short 1 1").is_none());
    }

    #[test]
    fn blame_file_returns_none_outside_a_git_repo() {
        let dir =
            std::env::temp_dir().join(format!("vord-blame-not-a-repo-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("f.txt"), "hello\n").unwrap();
        assert!(blame_file(&dir, "f.txt").is_none());
        std::fs::remove_dir_all(&dir).ok();
    }
}
