//! Rule: flags a socket or DB connection acquired outside a `with`
//! context manager (`socket.socket(...)`, `sqlite3.connect(...)`,
//! `psycopg2.connect(...)`, `urllib.request.urlopen(...)`,
//! `shelve.open(...)`). Complements `python:unclosed-open-file`, which
//! covers only `open()`: every one of these acquires an OS-level resource
//! (a file descriptor, a DB connection, a socket) that leaks if an
//! exception skips past a manual `.close()`.

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

use crate::common::other_kind_name;

const RESOURCE_CALLEES: &[&str] = &[
    "socket.socket",
    "sqlite3.connect",
    "psycopg2.connect",
    "urllib.request.urlopen",
    "shelve.open",
];

fn is_resource_call(node: &AstNode) -> bool {
    *node.kind() == NodeKind::Call
        && node
            .first_child()
            .is_some_and(|callee| RESOURCE_CALLEES.contains(&callee.text()))
}

/// Whether `word` occurs in `haystack` as a bare identifier — not as a
/// substring of a longer identifier (`conn` inside `db_conn`), and not as
/// an attribute of/on something else (`conn` inside `conn.close` or
/// `self.conn`). The latter matters for `scope_returns`: `return
/// conn.cursor()` returns something derived from the connection, not the
/// connection object itself, and must not be mistaken for `return conn`
/// transferring ownership of the resource.
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
    let is_boundary = |b: u8| b.is_ascii_alphanumeric() || b == b'_' || b == b'.';
    (0..=bytes.len() - wlen).any(|i| {
        &bytes[i..i + wlen] == wbytes
            && !bytes.get(i.wrapping_sub(1)).is_some_and(|b| is_boundary(*b))
            && !bytes.get(i + wlen).is_some_and(|b| is_boundary(*b))
    })
}

fn scope_returns(scope_text: &str, var: &str) -> bool {
    scope_text.lines().any(|line| {
        let trimmed = line.trim_start();
        trimmed.starts_with("return") && contains_word(trimmed, var)
    })
}

/// Walks the tree tracking whether the current node sits inside a `with`
/// clause (already scoped by the context manager) and the nearest
/// enclosing function/module text (to check whether an assigned resource
/// is later handed back to the caller).
///
/// A resource-acquiring call is only *this function's* leak risk to fix
/// when this function keeps ownership of it. A factory that hands the
/// connection back to its caller — directly
/// (`return sqlite3.connect(...)`) or via a variable
/// (`conn = sqlite3.connect(...); return conn`) — transfers that
/// responsibility to the caller, who is expected to close (or `with`) it;
/// this is the standard connection-factory / `get_db()` shape, not a leak
/// at this call site.
fn walk(node: &AstNode, in_with_clause: bool, scope_text: &str, out: &mut Vec<Finding>) {
    let kind_str = other_kind_name(node).unwrap_or("");

    // `return sqlite3.connect(...)` — ownership handed straight to the
    // caller; don't recurse into it as an ordinary resource call.
    let directly_returned_resource_call = (kind_str == "return_statement")
        .then(|| node.first_child())
        .flatten()
        .filter(|value| is_resource_call(value));
    if let Some(call) = directly_returned_resource_call {
        let child_scope_text = scope_text;
        for child in call.children() {
            walk(child, in_with_clause, child_scope_text, out);
        }
        return;
    }

    if !in_with_clause && node.kind() == &NodeKind::Assignment {
        if let (Some(target), Some(value)) = (node.children().first(), node.children().last()) {
            if target.kind() == &NodeKind::Identifier && is_resource_call(value) {
                if !scope_returns(scope_text, target.text()) {
                    out.push(Finding::new(
                        "resource acquired outside a `with` context manager leaks if an exception skips past a manual close()",
                        node.span(),
                    ));
                }
                // The resource call itself has been fully accounted for
                // (flagged or not) — recurse into its own arguments
                // directly, rather than through the shared loop below,
                // so the generic "is_resource_call(node)" branch never
                // sees this same call node a second time and double-
                // reports it.
                let child_in_with_clause =
                    in_with_clause || kind_str == "with_clause" || kind_str == "with_item";
                for child in value.children() {
                    walk(child, child_in_with_clause, scope_text, out);
                }
                return;
            }
        }
    } else if !in_with_clause && is_resource_call(node) {
        // A resource call used inline — not assigned to a variable, and
        // not the direct value of a `return` (handled above). Used
        // immediately (`sqlite3.connect(...).execute(...)`) or passed
        // somewhere else, this still isn't scoped by a `with`, so it's
        // flagged exactly as before.
        out.push(Finding::new(
            "resource acquired outside a `with` context manager leaks if an exception skips past a manual close()",
            node.span(),
        ));
    }

    let child_scope_text = if *node.kind() == NodeKind::FunctionDef {
        node.text()
    } else {
        scope_text
    };
    let child_in_with_clause = in_with_clause || kind_str == "with_clause" || kind_str == "with_item";
    for child in node.children() {
        walk(child, child_in_with_clause, child_scope_text, out);
    }
}

pub struct ResourceOpenedWithoutContextManagerRule {
    id: RuleId,
}

impl ResourceOpenedWithoutContextManagerRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("python:missing-context-manager-for-resource").expect("valid rule id"),
        }
    }
}

impl Default for ResourceOpenedWithoutContextManagerRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for ResourceOpenedWithoutContextManagerRule {
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
        IssueType::CodeSmell
    }

    fn remediation_effort_minutes(&self) -> u32 {
        10
    }

    fn metadata(&self) -> vord_rules_engine::RuleMetadata {
        vord_rules_engine::RuleMetadata {
            description: "A socket or DB connection acquired outside a `with` context manager leaks if an exception skips past a manual .close(); use `with ... as x:` instead.".into(),
            tags: vec!["resource-leak".into(), "cwe".into()],
            cwe: Some(772),
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        let mut findings = Vec::new();
        walk(ast, false, ast.text(), &mut findings);
        findings
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
        ResourceOpenedWithoutContextManagerRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_bare_sqlite_connect() {
        assert_eq!(findings("conn = sqlite3.connect('db.sqlite3')\n").len(), 1);
    }

    #[test]
    fn flags_bare_socket() {
        assert_eq!(
            findings("s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n").len(),
            1
        );
    }

    #[test]
    fn ignores_resource_inside_a_with_statement() {
        assert!(findings("with sqlite3.connect('db.sqlite3') as conn:\n    conn.execute('SELECT 1')\n").is_empty());
    }

    #[test]
    fn ignores_unrelated_calls() {
        assert!(findings("requests.get(url)\n").is_empty());
    }

    /// Regression: a factory function that hands the live connection
    /// back to its caller — directly — transfers ownership; the caller
    /// is expected to close (or `with`) it. This is the standard
    /// `get_db()` / connection-factory shape.
    #[test]
    fn allows_resource_directly_returned_to_caller() {
        let code = "def get_connection():\n    return sqlite3.connect('db.sqlite3')\n";
        assert!(findings(code).is_empty());
    }

    /// Same ownership transfer, via an intermediate variable.
    #[test]
    fn allows_resource_returned_via_variable() {
        let code = "def get_connection():\n    conn = sqlite3.connect('db.sqlite3')\n    return conn\n";
        assert!(findings(code).is_empty());
    }

    /// Returning just something *derived from* the resource (a cursor)
    /// does not transfer ownership of the connection itself — this must
    /// still be flagged.
    #[test]
    fn flags_resource_when_only_a_derived_value_is_returned() {
        let code = "def get_cursor():\n    conn = sqlite3.connect('db.sqlite3')\n    return conn.cursor()\n";
        assert_eq!(findings(code).len(), 1);
    }
}
