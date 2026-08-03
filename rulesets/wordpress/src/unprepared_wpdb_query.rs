use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{
    Finding, IssueType, Rule, RuleId, RuleMetadata, Severity, declare_rule_id,
};

use crate::common::{call_arguments, is_other, operator_between};

/// `$wpdb` fetch methods that take a raw SQL string. `->query`/`->exec`/
/// `->prepare` are already covered by the generic `php:sql-injection-concat`
/// (it matches those three method names on any receiver); these WordPress-
/// specific fetch helpers are not, because they aren't sinks for any other
/// PHP database API.
const WPDB_FETCH_METHODS: &[&str] = &["get_results", "get_var", "get_col", "get_row"];

/// tree-sitter-php flattens `$wpdb->get_results(...)` to `Call([receiver,
/// method, arguments])`, the same shape `php:sql-injection-concat` matches
/// its own method sinks against — restricted here to a receiver literally
/// named `$wpdb`, the global `wpdb` instance every WordPress install
/// exposes, so this doesn't fire on an unrelated object with a same-named
/// method.
fn is_wpdb_fetch_call(call: &AstNode) -> bool {
    match call.children() {
        [receiver, method, args] => {
            *receiver.kind() == NodeKind::Identifier
                && receiver.text() == "$wpdb"
                && *method.kind() == NodeKind::Identifier
                && WPDB_FETCH_METHODS.contains(&method.text())
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

declare_rule_id!(UnpreparedWpdbQueryRule, "wordpress:unprepared-wpdb-query");

impl Rule for UnpreparedWpdbQueryRule {
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

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "`$wpdb->get_results()`/`get_var()`/`get_col()`/`get_row()` executed \
                with a query string built by concatenating a value directly into the SQL text \
                is SQL injection if that value is ever influenced by external input; build the \
                query with `$wpdb->prepare()` and bind the value with a placeholder instead — \
                mirrors WPCS's `WordPress.DB.PreparedSQL`."
                .into(),
            tags: vec![
                "security".into(),
                "injection".into(),
                "wordpress".into(),
                "php".into(),
            ],
            cwe: Some(89),
            produces_hotspots: false,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter(|n| *n.kind() == NodeKind::Call)
            .filter(|call| is_wpdb_fetch_call(call))
            .filter(|call| {
                call_arguments(call).is_some_and(|args| {
                    args.iter()
                        .any(|arg| built_by_concatenation(arg, file.content()))
                })
            })
            .map(|call| {
                Finding::new(
                    "query is built by concatenating a value directly into the SQL text; use \
                    $wpdb->prepare() with a placeholder instead"
                        .to_string(),
                    call.span(),
                )
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use vord_ast::SourceFile;
    use vord_rules_engine::AstParser;

    use super::*;

    fn check(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.php", code, LanguageIdentifier::php()).unwrap();
        let ast = vord_parser_php::PhpParser::new().parse(&file).unwrap();
        UnpreparedWpdbQueryRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_get_results_concatenation() {
        assert_eq!(
            check("<?php\n$wpdb->get_results(\"SELECT * FROM t WHERE id=\" . $id);\n").len(),
            1
        );
    }

    #[test]
    fn flags_get_var_concatenation() {
        assert_eq!(
            check("<?php\n$wpdb->get_var(\"SELECT count(*) FROM t WHERE id=\" . $id);\n").len(),
            1
        );
    }

    #[test]
    fn allows_prepared_query() {
        assert!(
            check(
                "<?php\n$wpdb->get_results($wpdb->prepare(\"SELECT * FROM t WHERE id=%d\", $id));\n"
            )
            .is_empty()
        );
    }

    #[test]
    fn ignores_unrelated_receiver() {
        assert!(
            check("<?php\n$conn->get_results(\"SELECT * FROM t WHERE id=\" . $id);\n").is_empty()
        );
    }

    #[test]
    fn ignores_unrelated_method() {
        assert!(check("<?php\n$wpdb->insert('t', $data);\n").is_empty());
    }
}
