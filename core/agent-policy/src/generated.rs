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

/// What a line is to the hole grammar.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Marker {
    Open(String),
    Close,
}

/// Comment openers a marker may follow. `{/*` is JSX's.
const MARKER_COMMENTS: [&str; 8] = ["//", "#", "--", "/*", "{/*", "<!--", ";", "*"];

/// The marker on `line`, if it is one. A marker is a comment whose text
/// *starts* with [`HOLE_OPEN`] or [`HOLE_CLOSE`]: a string literal, a doc
/// comment or prose that merely mentions the marker is not one, so code and
/// documentation about holes are never mistaken for generated files.
fn marker(line: &str) -> Option<Marker> {
    let trimmed = line.trim_start();
    let text = MARKER_COMMENTS
        .iter()
        .filter_map(|opener| trimmed.strip_prefix(opener))
        .map(str::trim_start)
        .find(|text| text.starts_with(HOLE_OPEN) || text.starts_with(HOLE_CLOSE))?;
    if text.starts_with(HOLE_CLOSE) {
        return Some(Marker::Close);
    }
    let name = text[HOLE_OPEN.len()..]
        .split_whitespace()
        .next()
        .filter(|word| !matches!(*word, "-->" | "*/" | "*/}"))
        .unwrap_or("");
    Some(Marker::Open(name.to_string()))
}

/// Every line of `content` with its 1-based number and the marker it
/// carries. Lines inside a Markdown code fence carry none: an example of a
/// hole in documentation is not a hole.
fn marked_lines(content: &str) -> impl Iterator<Item = (u32, &str, Option<Marker>)> {
    let mut fenced = false;
    content.lines().enumerate().map(move |(index, line)| {
        let number = u32::try_from(index + 1).unwrap_or(u32::MAX);
        if line.trim_start().starts_with("```") {
            fenced = !fenced;
            return (number, line, None);
        }
        (number, line, if fenced { None } else { marker(line) })
    })
}

/// The lines of `content` outside every hole, with their 1-based line
/// numbers. Marker lines belong to the skeleton. An unclosed hole runs to
/// the end of the file, which the caller can still detect as a skeleton
/// change if the generator's output closed it.
pub fn skeleton(content: &str) -> Vec<(u32, &str)> {
    let mut out = Vec::new();
    let mut in_hole = false;
    for (number, line, marker) in marked_lines(content) {
        match marker {
            Some(Marker::Close) if in_hole => in_hole = false,
            Some(Marker::Open(_)) if !in_hole => in_hole = true,
            _ if in_hole => continue,
            _ => {}
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
    marked_lines(content)
        .filter(|(_, _, marker)| matches!(marker, Some(Marker::Open(_))))
        .count()
}

/// One hand-editable region of a generated file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hole {
    /// The name after [`HOLE_OPEN`] (`checkout-rules`); empty when the
    /// generator gave none.
    pub name: String,
    /// 1-based line of the opening marker.
    pub open_line: u32,
    /// 1-based line of the closing marker, or the last line when the hole
    /// is never closed.
    pub close_line: u32,
    /// The lines between the markers.
    pub body: String,
}

impl Hole {
    /// Whether the hole still waits for hand-written code: nothing but
    /// blanks, comments and the placeholders generators leave behind
    /// (`TODO`, `not implemented`, `AI_FILL`, `todo!()`…). A hole holding
    /// any other code line counts as filled — unless a placeholder is still
    /// there too: erring towards "pending" only costs another look, while
    /// the opposite would skip real work.
    pub fn is_pending(&self) -> bool {
        !self.is_auxiliary()
            && self.body.lines().all(|line| {
                let trimmed = line.trim();
                trimmed.is_empty() || is_comment(trimmed) || is_placeholder(trimmed)
            })
            || self.body.lines().any(|line| is_placeholder(line.trim()))
    }

    /// A hole that only exists to support another one — `imports` or
    /// `<anything>-imports`, where the code filling a sibling hole adds what
    /// it needs. Empty is its normal state, so it is never work by itself.
    pub fn is_auxiliary(&self) -> bool {
        self.name == "imports" || self.name.ends_with("-imports")
    }
}

const COMMENT_PREFIXES: [&str; 7] = ["//", "#", "--", "/*", "*", "<!--", ";"];

fn is_comment(line: &str) -> bool {
    COMMENT_PREFIXES
        .iter()
        .any(|prefix| line.starts_with(prefix))
}

const PLACEHOLDERS: [&str; 9] = [
    "todo!(",
    "unimplemented!(",
    "not implemented",
    "not yet implemented",
    "notimplementederror",
    "ai_fill",
    "implement me",
    "add business logic here",
    "panic(\"todo",
];

fn is_placeholder(line: &str) -> bool {
    // Python's and TypeScript's empty bodies.
    if matches!(
        line,
        "pass" | "..." | "return;" | "return nil" | "return nil, nil"
    ) {
        return true;
    }
    let lower = line.to_ascii_lowercase();
    PLACEHOLDERS.iter().any(|p| lower.contains(p))
}

/// Every hole in `content`, in file order.
pub fn holes(content: &str) -> Vec<Hole> {
    let mut out = Vec::new();
    let mut open: Option<(String, u32, Vec<&str>)> = None;
    let mut last = 0;
    for (number, line, marker) in marked_lines(content) {
        last = number;
        match (open.take(), marker) {
            (Some((name, open_line, body)), Some(Marker::Close)) => out.push(Hole {
                name,
                open_line,
                close_line: number,
                body: body.join("\n"),
            }),
            (Some((name, open_line, mut body)), _) => {
                body.push(line);
                open = Some((name, open_line, body));
            }
            (None, Some(Marker::Open(name))) => open = Some((name, number, Vec::new())),
            (None, _) => {}
        }
    }
    if let Some((name, open_line, body)) = open {
        out.push(Hole {
            name,
            open_line,
            close_line: last,
            body: body.join("\n"),
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn holes_are_listed_with_names_lines_and_bodies() {
        let found = holes(GENERATED);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].name, "checkout-rules");
        assert_eq!((found[0].open_line, found[0].close_line), (3, 4));
        assert!(found[0].is_pending(), "an empty hole waits for code");
    }

    #[test]
    fn a_hole_with_code_is_filled_and_one_with_a_placeholder_is_not() {
        let filled = GENERATED.replace(
            "    // vord:hole checkout-rules\n",
            "    // vord:hole checkout-rules\n    // Empty carts are free.\n    if cart.is_empty() { return Total::zero(); }\n",
        );
        assert!(!holes(&filled)[0].is_pending());
        for placeholder in [
            "    todo!()",
            "\treturn errors.New(\"not yet implemented\")",
            "    raise NotImplementedError",
            "    // TODO: AI_FILL",
        ] {
            let stub = GENERATED.replace(
                "    // vord:hole checkout-rules\n",
                &format!("    // vord:hole checkout-rules\n{placeholder}\n"),
            );
            assert!(holes(&stub)[0].is_pending(), "{placeholder}");
        }
    }

    #[test]
    fn mentions_of_the_marker_are_not_holes() {
        let rust = "/// Wrap hand-written code in `// vord:hole <name>`.\nconst OPEN: &str = \"// vord:hole x\";\n//! // vord:hole doc-example\n";
        assert_eq!(hole_count(rust), 0);
        let markdown =
            "Holes look like this:\n\n```go\n// vord:hole place-rules\n// vord:end-hole\n```\n";
        assert_eq!(hole_count(markdown), 0);
        assert_eq!(
            first_skeleton_change(markdown, &markdown.replace("place", "x")),
            Some(4)
        );
        let jsx = "<main>\n  {/* vord:hole hero */}\n  {/* vord:end-hole */}\n</main>\n";
        assert_eq!(holes(jsx)[0].name, "hero");
    }

    #[test]
    fn an_empty_imports_hole_is_not_work() {
        let go = "import (\n\t// vord:hole order-imports\n\t// vord:end-hole\n)\n";
        assert!(!holes(go)[0].is_pending());
    }

    #[test]
    fn hole_names_survive_comment_closers_and_unclosed_holes_run_to_the_end() {
        let html = "<div>\n<!-- vord:hole hero -->\n<!-- vord:end-hole -->\n<!-- vord:hole footer\n<p>x</p>\n";
        let found = holes(html);
        assert_eq!(found[0].name, "hero");
        assert_eq!(found[1].name, "footer");
        assert_eq!(found[1].close_line, 5);
        assert_eq!(
            holes("<!-- vord:hole -->\n<!-- vord:end-hole -->")[0].name,
            ""
        );
    }

    // Built from escaped lines so this source file never itself starts a
    // line with a marker (which would make vord guard it as generated).
    const GENERATED: &str = concat!(
        "pub fn checkout(cart: &Cart) -> Total {\n",
        "    let subtotal = cart.subtotal();\n",
        "    // vord:hole checkout-rules\n",
        "    // vord:end-hole\n",
        "    Total::new(subtotal)\n",
        "}\n",
    );

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
