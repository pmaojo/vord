//! Generated code is regenerated, not hand-edited.
//!
//! A scaffolding engine (Kthulu, Ferrum, Wasp, `vord kickoff`'s own
//! templates) produces most of a file deterministically from a blueprint.
//! An agent that edits that structure by hand does work a generator already
//! does, and the next regeneration silently throws it away. What the agent
//! *should* write is the residue the blueprint cannot express — and a
//! generator marks where that goes with a **hole**:
//!
//! ```text
//! // vord:hole checkout-rules
//!     ... hand-written business logic ...
//! // vord:end-hole
//! ```
//!
//! The markers are matched as substrings of a line, so they work under any
//! comment syntax (`//`, `#`, `--`, `<!-- -->`). Everything outside a hole —
//! the marker lines included, so a hole cannot be widened or deleted — is
//! the file's **skeleton**. A write to a generated file is acceptable only
//! if it leaves the skeleton byte-for-byte unchanged. A generated file with
//! no holes is therefore entirely the generator's.
//!
//! Pure: no I/O. The caller decides which files are generated (vord keeps a
//! manifest) and what to compare against.

/// Opens a hand-editable region in a generated file.
pub const HOLE_OPEN: &str = "vord:hole";
/// Closes the region [`HOLE_OPEN`] opened.
pub const HOLE_CLOSE: &str = "vord:end-hole";

/// The lines of `content` outside every hole, with their 1-based line
/// numbers. Marker lines belong to the skeleton. An unclosed hole runs to
/// the end of the file, which the caller can still detect as a skeleton
/// change if the generator's output closed it.
pub fn skeleton(content: &str) -> Vec<(u32, &str)> {
    let mut out = Vec::new();
    let mut in_hole = false;
    for (index, line) in content.lines().enumerate() {
        let number = u32::try_from(index + 1).unwrap_or(u32::MAX);
        if in_hole {
            if line.contains(HOLE_CLOSE) {
                in_hole = false;
                out.push((number, line));
            }
            continue;
        }
        // Checked in this order so a line that names the close marker is
        // never mistaken for an opener (`vord:end-hole` does not contain
        // `vord:hole`, but stay explicit).
        if line.contains(HOLE_OPEN) && !line.contains(HOLE_CLOSE) {
            in_hole = true;
        }
        out.push((number, line));
    }
    out
}

/// Where a proposed write first departs from the generated skeleton, if it
/// does: the 1-based line in `proposed` (or the line just past its end, when
/// `proposed` drops skeleton lines). `None` means only hole contents
/// changed, which is the edit a generated file permits.
pub fn first_skeleton_change(current: &str, proposed: &str) -> Option<u32> {
    let before = skeleton(current);
    let after = skeleton(proposed);
    for (index, (_, line)) in before.iter().enumerate() {
        match after.get(index) {
            Some((_, proposed_line)) if proposed_line == line => {}
            Some((number, _)) => return Some(*number),
            None => {
                let past_end = proposed.lines().count() + 1;
                return Some(u32::try_from(past_end).unwrap_or(u32::MAX));
            }
        }
    }
    after.get(before.len()).map(|(number, _)| *number)
}

/// How many holes `content` declares — zero means a hand edit anywhere is a
/// skeleton change.
pub fn hole_count(content: &str) -> usize {
    content
        .lines()
        .filter(|line| line.contains(HOLE_OPEN) && !line.contains(HOLE_CLOSE))
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;

    const GENERATED: &str = "\
pub fn checkout(cart: &Cart) -> Total {
    let subtotal = cart.subtotal();
    // vord:hole checkout-rules
    // vord:end-hole
    Total::new(subtotal)
}
";

    #[test]
    fn filling_a_hole_leaves_the_skeleton_intact() {
        let filled = GENERATED.replace(
            "    // vord:hole checkout-rules\n",
            "    // vord:hole checkout-rules\n    if cart.is_empty() { return Total::zero(); }\n",
        );
        assert_eq!(first_skeleton_change(GENERATED, &filled), None);
    }

    #[test]
    fn rewriting_generated_lines_is_a_skeleton_change() {
        let edited = GENERATED.replace("Total::new(subtotal)", "Total::new(subtotal * 2)");
        assert_eq!(first_skeleton_change(GENERATED, &edited), Some(5));
    }

    #[test]
    fn deleting_or_moving_a_hole_marker_is_a_skeleton_change() {
        let widened = GENERATED.replace("    // vord:end-hole\n", "");
        assert!(first_skeleton_change(GENERATED, &widened).is_some());
    }

    #[test]
    fn adding_lines_outside_any_hole_is_a_skeleton_change() {
        let appended = format!("{GENERATED}fn helper() {{}}\n");
        assert_eq!(first_skeleton_change(GENERATED, &appended), Some(7));
    }

    #[test]
    fn truncating_the_file_is_a_skeleton_change() {
        let truncated: String = GENERATED.lines().take(2).collect::<Vec<_>>().join("\n");
        assert_eq!(first_skeleton_change(GENERATED, &truncated), Some(3));
    }

    #[test]
    fn a_file_without_holes_admits_no_hand_edit() {
        let plain = "a\nb\n";
        assert_eq!(hole_count(plain), 0);
        assert_eq!(first_skeleton_change(plain, "a\nb\n"), None);
        assert_eq!(first_skeleton_change(plain, "a\nc\n"), Some(2));
    }

    #[test]
    fn markers_work_under_any_comment_syntax() {
        let python = "def f():\n    # vord:hole body\n    pass\n    # vord:end-hole\n";
        assert_eq!(hole_count(python), 1);
        let filled = python.replace("    pass\n", "    return 42\n");
        assert_eq!(first_skeleton_change(python, &filled), None);
    }
}
