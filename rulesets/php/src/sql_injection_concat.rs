use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use yunq_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

use crate::common::{callee_node, is_other, operator_between};

const FUNCTION_SINKS: &[&str] = &[
    "mysqli_query",
    "mysql_query",
    "pg_query",
    "pg_exec",
    "sqlite_query",
    "sqlite_exec",
];
const METHOD_SINKS: &[&str] = &["query", "exec", "prepare"];

fn is_function_sink(call: &AstNode) -> bool {
    // A bare function call has exactly `[name, arguments]` — two children.
    call.children().len() == 2
        && callee_node(call).is_some_and(|c| {
            *c.kind() == NodeKind::Identifier && FUNCTION_SINKS.contains(&c.text())
        })
}

/// tree-sitter-php flattens a method call to `Call([receiver, method_name,
/// arguments])` rather than a receiver plus a `MemberAccess` callee, so
/// three children with an `Identifier` receiver and an `Identifier` method
/// name is what distinguishes `$conn->query(...)` from a bare call to a
/// function that happens to share a sink's name (PHP's own `exec()`, a
/// shell sink handled by `php:command-execution`, is exactly such a case).
fn is_method_sink(call: &AstNode) -> bool {
    match call.children() {
        [receiver, method, args] => {
            *receiver.kind() == NodeKind::Identifier
                && *method.kind() == NodeKind::Identifier
                && METHOD_SINKS.contains(&method.text())
                && is_other(args.kind(), "arguments")
        }
        _ => false,
    }
}

fn is_dot_concat(node: &AstNode, source: &str) -> bool {
    is_other(node.kind(), "binary_expression")
        && match node.children() {
            [left, right] => operator_between(source, left, right) == ".",
            _ => false,
        }
}

fn built_by_concatenation(arg: &AstNode, source: &str) -> bool {
    arg.descendants().any(|n| is_dot_concat(n, source))
}

/// A DB query executed with a query string built by string concatenation
/// (`.`) is SQL injection if any concatenated piece is ever influenced by
/// request input — the same scope limitation as `python:sql-injection-
/// string-building`: this checks the argument expression at the call site,
/// not whether that value can be traced back to untrusted input. Covers
/// both bare procedural sinks (`mysqli_query`, `pg_query`, ...) and the
/// `->query`/`->exec`/`->prepare` method names used by `mysqli`/`PDO`/PEAR
/// DB-style objects (matched by method name only, since this analyzer
/// doesn't resolve receiver types).
pub struct SqlInjectionConcatRule {
    id: RuleId,
}

impl SqlInjectionConcatRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("php:sql-injection-concat").expect("valid rule id"),
        }
    }
}

impl Default for SqlInjectionConcatRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for SqlInjectionConcatRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, language: &LanguageIdentifier) -> bool {
        *language == LanguageIdentifier::php()
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
            description: "Building a SQL query by concatenating a value into the string before \
                executing it is SQL injection if that value is ever influenced by external \
                input; use a parameterized/prepared query and bind the value separately \
                instead."
                .into(),
            tags: vec!["security".into(), "injection".into(), "php".into()],
            cwe: Some(89),
            produces_hotspots: false,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter(|n| *n.kind() == NodeKind::Call)
            .filter(|call| is_function_sink(call) || is_method_sink(call))
            .filter_map(|call| {
                let args = call
                    .children()
                    .iter()
                    .find(|c| is_other(c.kind(), "arguments"))?;
                args.children()
                    .iter()
                    .any(|arg| built_by_concatenation(arg, file.content()))
                    .then(|| {
                        Finding::new(
                            "query is built by concatenating a value directly into the SQL \
                            text; use a parameterized/prepared query instead"
                                .to_string(),
                            call.span(),
                        )
                    })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use yunq_ast::SourceFile;
    use yunq_rules_engine::AstParser;

    use super::*;

    fn check(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.php", code, LanguageIdentifier::php()).unwrap();
        let ast = yunq_parser_php::PhpParser::new().parse(&file).unwrap();
        SqlInjectionConcatRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_mysqli_query_concatenation() {
        assert_eq!(
            check("<?php\nmysqli_query($conn, \"SELECT * FROM t WHERE id=\" . $id);\n").len(),
            1
        );
    }

    #[test]
    fn flags_method_query_concatenation() {
        assert_eq!(
            check("<?php\n$conn->query(\"SELECT * FROM t WHERE id=\" . $id);\n").len(),
            1
        );
    }

    #[test]
    fn flags_prepare_concatenation() {
        assert_eq!(
            check("<?php\n$pdo->prepare(\"SELECT * FROM t WHERE id=\" . $id);\n").len(),
            1
        );
    }

    #[test]
    fn allows_parameterized_query() {
        assert!(check("<?php\n$pdo->prepare(\"SELECT * FROM t WHERE id = :id\");\n").is_empty());
    }

    #[test]
    fn ignores_unrelated_calls() {
        assert!(check("<?php\nstrtolower(\"a\" . $b);\n").is_empty());
    }

    #[test]
    fn ignores_bare_exec_call_despite_shared_method_sink_name() {
        // PHP's own exec() (a shell sink, covered by php:command-execution) must
        // not be mistaken for the ->exec() method sink just because it shares a
        // name — the two are distinguished by call shape (2 vs 3 children).
        assert!(check("<?php\nexec(\"ls \" . $dir);\n").is_empty());
    }
}
