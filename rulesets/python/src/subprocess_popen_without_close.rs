//! Rule: flags `subprocess.Popen(...)` assigned to a variable that is
//! neither used as a `with` context manager nor followed, anywhere in the
//! enclosing function, by a call that would reap it (`.wait()`,
//! `.communicate()`, `.terminate()`, `.kill()`). Left dangling, the child
//! process becomes a zombie once it exits and the pipes `Popen` opened for
//! it leak file descriptors for as long as the parent process runs.

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

use crate::common::other_kind_name;

const CLOSING_METHODS: &[&str] = &["wait", "communicate", "terminate", "kill"];

fn is_popen_call(node: &AstNode) -> bool {
    *node.kind() == NodeKind::Call
        && node
            .first_child()
            .is_some_and(|callee| callee.text() == "subprocess.Popen")
}

fn scope_has_closing_call(scope_text: &str, var: &str) -> bool {
    CLOSING_METHODS
        .iter()
        .any(|method| scope_text.contains(&format!("{var}.{method}(")))
}

/// Whether `var` occurs as a whole word anywhere in a `return` statement's
/// text within `scope_text`. A function that hands the `Popen` result back
/// to its caller (`p = subprocess.Popen(cmd); return p`) transfers
/// ownership — the caller is now responsible for waiting on/terminating
/// it, and this function has no way to close something it no longer
/// owns. Deliberately permissive (any `return` line mentioning the name,
/// not just a bare `return var`) to also cover `return p, other`,
/// `return {"proc": p}`, and similar shapes without needing full
/// structural analysis.
fn scope_returns(scope_text: &str, var: &str) -> bool {
    scope_text.lines().any(|line| {
        let trimmed = line.trim_start();
        if !trimmed.starts_with("return") {
            return false;
        }
        contains_word(trimmed, var)
    })
}

/// Whether `word` occurs in `haystack` as a bare identifier — not as a
/// substring of a longer identifier (`p` inside `pipe`), and not as an
/// attribute *of* or *on* something else (`p` inside `self.p` or `p.pid`).
/// The latter matters here specifically: `return p.pid` returns an `int`
/// attribute, not the `Popen` object itself, so it must not be mistaken
/// for `return p` transferring ownership of the process handle.
fn contains_word(haystack: &str, word: &str) -> bool {
    if word.is_empty() {
        return false;
    }
    let bytes = haystack.as_bytes();
    let wbytes = word.as_bytes();
    let wlen = wbytes.len();
    if wlen > bytes.len() {
        return false;
    }
    let is_boundary_char = |b: u8| b.is_ascii_alphanumeric() || b == b'_' || b == b'.';
    (0..=bytes.len() - wlen).any(|i| {
        &bytes[i..i + wlen] == wbytes
            && !bytes.get(i.wrapping_sub(1)).is_some_and(|b| is_boundary_char(*b))
            && !bytes.get(i + wlen).is_some_and(|b| is_boundary_char(*b))
    })
}

/// Walks the tree tracking the nearest enclosing function/module text (to
/// search for a later closing call) and whether we're inside a `with`
/// clause (where `Popen` is already scoped by the context manager).
fn walk(node: &AstNode, in_with_clause: bool, scope_text: &str, out: &mut Vec<Finding>) {
    let kind_str = other_kind_name(node).unwrap_or("");

    if !in_with_clause && node.kind() == &NodeKind::Assignment {
        if let (Some(target), Some(value)) = (node.children().first(), node.children().last()) {
            if target.kind() == &NodeKind::Identifier
                && is_popen_call(value)
                && !scope_has_closing_call(scope_text, target.text())
                && !scope_returns(scope_text, target.text())
            {
                out.push(Finding::new(
                    "subprocess.Popen result is never waited on, communicated with, or terminated; use it as a `with` context manager, or call .wait()/.communicate() so the child process doesn't leak",
                    node.span(),
                ));
            }
        }
    }

    let child_scope_text = if *node.kind() == NodeKind::FunctionDef {
        node.text()
    } else {
        scope_text
    };
    let child_in_with = in_with_clause || kind_str == "with_clause" || kind_str == "with_item";
    for child in node.children() {
        walk(child, child_in_with, child_scope_text, out);
    }
}

pub struct SubprocessPopenWithoutCloseRule {
    id: RuleId,
}

impl SubprocessPopenWithoutCloseRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("python:subprocess-popen-without-close").expect("valid rule id"),
        }
    }
}

impl Default for SubprocessPopenWithoutCloseRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for SubprocessPopenWithoutCloseRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, lang: &LanguageIdentifier) -> bool {
        *lang == LanguageIdentifier::python()
    }

    fn default_severity(&self) -> Severity {
        Severity::Major
    }

    fn issue_type(&self) -> IssueType {
        IssueType::Bug
    }

    fn remediation_effort_minutes(&self) -> u32 {
        10
    }

    fn metadata(&self) -> vord_rules_engine::RuleMetadata {
        vord_rules_engine::RuleMetadata {
            description: "A subprocess.Popen result that is never waited on, communicated with, or terminated leaves the child process a zombie once it exits and leaks the pipes Popen opened for it; use it as a context manager or call .wait()/.communicate().".into(),
            tags: vec!["bug".into(), "resource-leak".into()],
            cwe: Some(772),
            produces_hotspots: false,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        if crate::common::is_test_file(file.path()) {
            return Vec::new();
        }
        let mut out = Vec::new();
        walk(ast, false, ast.text(), &mut out);
        out
    }
}

#[cfg(test)]
mod tests {
    use vord_rules_engine::AstParser;

    use super::*;

    fn findings(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.py", code, LanguageIdentifier::python()).unwrap();
        let ast = vord_parser_python::PythonParser::new()
            .parse(&file)
            .unwrap();
        SubprocessPopenWithoutCloseRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_popen_never_closed() {
        let code = "def f():\n    p = subprocess.Popen(['ls'])\n    return p.pid\n";
        assert_eq!(findings(code).len(), 1);
    }

    #[test]
    fn allows_popen_with_wait() {
        let code = "def f():\n    p = subprocess.Popen(['ls'])\n    p.wait()\n";
        assert!(findings(code).is_empty());
    }

    #[test]
    fn allows_popen_with_communicate() {
        let code = "def f():\n    p = subprocess.Popen(['ls'])\n    out, err = p.communicate()\n";
        assert!(findings(code).is_empty());
    }

    #[test]
    fn allows_popen_as_context_manager() {
        let code = "def f():\n    with subprocess.Popen(['ls']) as p:\n        p.stdout.read()\n";
        assert!(findings(code).is_empty());
    }

    /// Regression: a factory function that hands the live `Popen` handle
    /// back to its caller transfers ownership — the caller is now
    /// responsible for waiting on/terminating it, and this function
    /// cannot close something it no longer owns.
    #[test]
    fn allows_popen_returned_to_caller() {
        let code = "def start_process(cmd):\n    p = subprocess.Popen(cmd)\n    return p\n";
        assert!(findings(code).is_empty());
    }

    #[test]
    fn allows_popen_returned_as_part_of_a_tuple() {
        let code = "def start_process(cmd):\n    p = subprocess.Popen(cmd)\n    return p, cmd\n";
        assert!(findings(code).is_empty());
    }

    /// Returning just an *attribute* of the Popen result (`p.pid`, an
    /// `int`) does not transfer ownership of the process handle itself —
    /// this must still be flagged.
    #[test]
    fn flags_popen_when_only_an_attribute_is_returned() {
        let code = "def f():\n    p = subprocess.Popen(['ls'])\n    return p.pid\n";
        assert_eq!(findings(code).len(), 1);
    }
}
