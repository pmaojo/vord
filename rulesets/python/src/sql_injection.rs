//! Rule: flags a DB cursor `.execute()`/`.executemany()` call whose query
//! string is built eagerly (an f-string, or `%`/`+` applied before the
//! call) instead of passed as a parameterized query plus separate bound
//! values. Building the query by interpolating a value directly into the
//! SQL text is exactly how untrusted input becomes SQL injection.

use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use yunq_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

const EXECUTE_METHODS: &[&str] = &["execute", "executemany"];

fn other_kind_name(node: &AstNode) -> Option<&str> {
    match node.kind() {
        NodeKind::Other(name) => Some(name.as_ref()),
        _ => None,
    }
}

fn is_eager_built_query(arg: &AstNode) -> bool {
    match arg.kind() {
        NodeKind::StringLiteral => arg.first_child().is_some_and(|start| {
            other_kind_name(start) == Some("string_start")
                && start.text().trim_start().starts_with(['f', 'F'])
        }),
        NodeKind::Other(name) => name.as_ref() == "binary_operator",
        _ => false,
    }
}

pub struct SqlInjectionRule {
    id: RuleId,
}

impl SqlInjectionRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("python:sql-injection-string-building").expect("valid rule id"),
        }
    }
}

impl Default for SqlInjectionRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for SqlInjectionRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, lang: &LanguageIdentifier) -> bool {
        *lang == LanguageIdentifier::python()
    }

    fn default_severity(&self) -> Severity {
        Severity::Blocker
    }

    fn issue_type(&self) -> IssueType {
        IssueType::Vulnerability
    }

    fn remediation_effort_minutes(&self) -> u32 {
        20
    }

    fn metadata(&self) -> yunq_rules_engine::RuleMetadata {
        yunq_rules_engine::RuleMetadata {
            description: "Building a SQL query by interpolating a value into the string before execute() is SQL injection if that value is ever influenced by external input; pass a parameterized query and the values as a separate argument instead.".into(),
            tags: vec!["security".into(), "injection".into(), "cwe".into(), "owasp-top10".into()],
            cwe: Some(89),
            produces_hotspots: false,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        if yunq_rules_engine::is_test_only_path(file.path()) {
            return Vec::new();
        }
        ast.descendants()
            .filter(|n| *n.kind() == NodeKind::Call)
            .filter_map(|call| {
                let callee = call.first_child()?;
                if callee.kind() != &NodeKind::MemberAccess {
                    return None;
                }
                let method = callee.children().last()?;
                if !EXECUTE_METHODS.contains(&method.text()) {
                    return None;
                }
                let args = call.children().iter().find(|c| other_kind_name(c) == Some("argument_list"))?;
                let first_arg = args.children().first()?;
                is_eager_built_query(first_arg).then(|| Finding::new("query string is built by interpolating a value directly into the SQL text; use a parameterized query with the value passed as a separate argument", call.span()))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use yunq_rules_engine::AstParser;

    use super::*;

    fn findings(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.py", code, LanguageIdentifier::python()).unwrap();
        let ast = yunq_parser_python::PythonParser::new()
            .parse(&file)
            .unwrap();
        SqlInjectionRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_fstring_query() {
        assert_eq!(
            findings("cursor.execute(f'SELECT * FROM t WHERE id={id}')\n").len(),
            1
        );
    }

    #[test]
    fn flags_percent_formatted_query() {
        assert_eq!(
            findings("cursor.execute('SELECT * FROM t WHERE id=%s' % id)\n").len(),
            1
        );
    }

    #[test]
    fn allows_parameterized_query() {
        assert!(findings("cursor.execute('SELECT * FROM t WHERE id=%s', (id,))\n").is_empty());
    }

    #[test]
    fn flags_execute_regardless_of_receiver_name() {
        assert_eq!(
            findings("conn.execute(f'SELECT * FROM t WHERE id={id}')\n").len(),
            1
        );
    }
}
