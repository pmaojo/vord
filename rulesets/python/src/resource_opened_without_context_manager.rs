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

        fn walk(node: &AstNode, in_with_clause: bool, out: &mut Vec<Finding>) {
            let kind_str = other_kind_name(node).unwrap_or("");

            if !in_with_clause && *node.kind() == NodeKind::Call {
                if let Some(callee) = node.first_child() {
                    if RESOURCE_CALLEES.contains(&callee.text()) {
                        out.push(Finding::new(
                            "resource acquired outside a `with` context manager leaks if an exception skips past a manual close()",
                            node.span(),
                        ));
                    }
                }
            }

            let child_in_with_clause =
                in_with_clause || kind_str == "with_clause" || kind_str == "with_item";
            for child in node.children() {
                walk(child, child_in_with_clause, out);
            }
        }

        walk(ast, false, &mut findings);
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
}
