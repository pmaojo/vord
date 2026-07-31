//! Minimal unified-diff parsing (inbound adapter): extracts the set of
//! added/modified line numbers per file, on the "new" side of the diff.
//! Used to restrict coverage to "new" (changed) lines for the
//! coverage-on-new-code measure — the caller supplies the diff text (e.g.
//! the output of `git diff <reference>...HEAD --unified=0`); this module
//! does not invoke git itself, keeping it a pure, easily-tested parser.

use std::collections::{BTreeMap, BTreeSet};

/// Parses unified diff text into `path -> {changed line numbers}` (1-based,
/// on the new/"+" side). Deleted files (`+++ /dev/null`) contribute no
/// lines. Malformed or unrecognized lines are skipped rather than erroring —
/// diff parsing here is best-effort support for an optional feature, not a
/// strict format the tool controls.
/// Applies one hunk-body line for `path` to `result`/`new_line`. Returns
/// whether the hunk is still trustworthy afterward — `false` if this line
/// doesn't match any recognized hunk-body shape, ending the hunk early.
fn apply_hunk_line(
    line: &str,
    path: &str,
    result: &mut BTreeMap<String, BTreeSet<u32>>,
    new_line: &mut u32,
) -> bool {
    if line.strip_prefix('+').is_some() {
        result
            .entry(path.to_string())
            .or_default()
            .insert(*new_line);
        *new_line += 1;
    } else if line.starts_with('-') {
        // Removed from the old file; does not exist on the new side.
    } else if line.starts_with(' ') || line.is_empty() {
        *new_line += 1;
    } else if line.starts_with('\\') {
        // "\ No newline at end of file" — not a content line.
    } else {
        // Anything else ends the hunk body unexpectedly; stop trusting
        // `new_line` until the next `@@`.
        return false;
    }
    true
}

pub fn changed_lines_from_unified_diff(diff: &str) -> BTreeMap<String, BTreeSet<u32>> {
    let mut result: BTreeMap<String, BTreeSet<u32>> = BTreeMap::new();
    let mut current_file: Option<String> = None;
    let mut new_line: u32 = 0;
    let mut in_hunk = false;

    for line in diff.lines() {
        if let Some(rest) = line.strip_prefix("+++ ") {
            in_hunk = false;
            current_file = parse_diff_path(rest);
        } else if line.starts_with("--- ") {
            in_hunk = false;
            // Old-file header; the file identity comes from `+++`.
        } else if let Some(rest) = line.strip_prefix("@@ ") {
            if let Some(new_start) = parse_hunk_new_start(rest) {
                new_line = new_start;
                in_hunk = true;
            } else {
                in_hunk = false;
            }
        } else if in_hunk {
            if let Some(path) = &current_file {
                in_hunk = apply_hunk_line(line, path, &mut result, &mut new_line);
            }
        }
    }

    result
}

/// `+++ b/src/foo.rs` -> `Some("src/foo.rs")`; `+++ /dev/null` -> `None`.
fn parse_diff_path(rest: &str) -> Option<String> {
    let path = rest.split('\t').next().unwrap_or(rest).trim();
    if path == "/dev/null" {
        return None;
    }
    let stripped = path
        .strip_prefix("b/")
        .or_else(|| path.strip_prefix("a/"))
        .unwrap_or(path);
    Some(stripped.to_string())
}

/// `-10,3 +12,4 @@ ...` -> `Some(12)` (the new-file hunk start line).
fn parse_hunk_new_start(rest: &str) -> Option<u32> {
    let plus_part = rest.split_whitespace().find(|s| s.starts_with('+'))?;
    let numbers = plus_part.trim_start_matches('+');
    let start = numbers.split(',').next()?;
    start.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_added_lines_from_a_single_hunk() {
        let diff = "\
diff --git a/src/foo.rs b/src/foo.rs
index abc..def 100644
--- a/src/foo.rs
+++ b/src/foo.rs
@@ -10,0 +11,2 @@ fn foo() {
+    let x = 1;
+    let y = 2;
";
        let changed = changed_lines_from_unified_diff(diff);
        let lines = changed.get("src/foo.rs").unwrap();
        assert_eq!(lines, &[11u32, 12].into_iter().collect());
    }

    #[test]
    fn context_and_removed_lines_advance_or_dont_advance_the_cursor() {
        let diff = "\
--- a/src/foo.rs
+++ b/src/foo.rs
@@ -1,4 +1,4 @@
 unchanged before
-old line
+new line
 unchanged after
";
        let changed = changed_lines_from_unified_diff(diff);
        let lines = changed.get("src/foo.rs").unwrap();
        // line 1 = unchanged before, line 2 = new line (replaces old line),
        // line 3 = unchanged after — only line 2 is "changed".
        assert_eq!(lines, &[2u32].into_iter().collect());
    }

    #[test]
    fn deleted_files_contribute_no_lines() {
        let diff = "\
--- a/src/gone.rs
+++ /dev/null
@@ -1,2 +0,0 @@
-bye
-bye again
";
        let changed = changed_lines_from_unified_diff(diff);
        assert!(changed.is_empty());
    }

    #[test]
    fn tracks_multiple_files_and_hunks() {
        let diff = "\
--- a/src/a.rs
+++ b/src/a.rs
@@ -1,1 +1,2 @@
 unchanged
+added in a
--- a/src/b.rs
+++ b/src/b.rs
@@ -5,1 +5,1 @@
-old in b
+new in b
";
        let changed = changed_lines_from_unified_diff(diff);
        assert_eq!(
            changed.get("src/a.rs").unwrap(),
            &[2u32].into_iter().collect()
        );
        assert_eq!(
            changed.get("src/b.rs").unwrap(),
            &[5u32].into_iter().collect()
        );
    }

    #[test]
    fn empty_diff_yields_no_changes() {
        assert!(changed_lines_from_unified_diff("").is_empty());
    }
}
