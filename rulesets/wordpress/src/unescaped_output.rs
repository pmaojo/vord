use vord_ast::{AstNode, LanguageIdentifier, SourceFile};
use vord_rules_engine::{
    Finding, IssueType, Rule, RuleId, RuleMetadata, Severity, declare_rule_id,
};

use crate::common::{is_other, subtree_has_unwrapped_superglobal};

/// WordPress core functions that escape a value for a specific output
/// context. WPCS's `WordPress.Security.EscapeOutput` sniff accepts a wider
/// "whitelist" (including custom project functions configured via
/// `customEscapingFunctions`), but this rule only knows the ones WordPress
/// itself ships — the same closed-vocabulary tradeoff `php:sql-injection-
/// concat` makes for its own sink/safe-call lists.
const ESCAPING_FUNCTIONS: &[&str] = &[
    "esc_html",
    "esc_attr",
    "esc_url",
    "esc_url_raw",
    "esc_js",
    "esc_textarea",
    "esc_sql",
    "esc_html__",
    "esc_html_e",
    "esc_attr__",
    "esc_attr_e",
    "esc_html_x",
    "esc_attr_x",
    "wp_kses",
    "wp_kses_post",
    "wp_kses_data",
    "sanitize_text_field",
    "absint",
    "intval",
    "wp_json_encode",
];

/// The output-producing statement kinds tree-sitter-php parses `echo ...;`
/// and `print(...)`/`print ...;` into.
const OUTPUT_STATEMENTS: &[&str] = &["echo_statement", "print_intrinsic"];

/// `echo $a, $b;` parses as one `echo_statement` wrapping a single
/// `sequence_expression`; every other case (including `print_intrinsic`,
/// whose operand may itself be parenthesized) is a single child expression.
fn output_expressions(stmt: &AstNode) -> Vec<&AstNode> {
    stmt.children()
        .iter()
        .flat_map(|child| {
            if is_other(child.kind(), "sequence_expression") {
                child.children().iter().collect::<Vec<_>>()
            } else {
                vec![child]
            }
        })
        .collect()
}

declare_rule_id!(
    UnescapedOutputRule,
    "wordpress:unescaped-superglobal-output"
);

impl Rule for UnescapedOutputRule {
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
        15
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "Printing a `$_GET`/`$_POST`/`$_REQUEST`/`$_COOKIE`/`$_SERVER`/\
                `$_FILES` value (directly or built into a larger string) without passing it \
                through an escaping function first is reflected XSS. Wrap it in `esc_html()`, \
                `esc_attr()`, `esc_url()`, `esc_js()`, or `wp_kses()`/`wp_kses_post()` for the \
                context it's printed in — mirrors WPCS's `WordPress.Security.EscapeOutput`."
                .into(),
            tags: vec![
                "security".into(),
                "xss".into(),
                "wordpress".into(),
                "php".into(),
            ],
            cwe: Some(79),
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter(|n| OUTPUT_STATEMENTS.iter().any(|k| is_other(n.kind(), k)))
            .flat_map(|stmt| output_expressions(stmt).into_iter())
            .filter(|expr| subtree_has_unwrapped_superglobal(expr, ESCAPING_FUNCTIONS))
            .map(|expr| {
                Finding::new(
                    "request data is printed without escaping; wrap it in esc_html()/\
                    esc_attr()/esc_url()/wp_kses() (or the escaper matching this output \
                    context) before echoing it"
                        .to_string(),
                    expr.span(),
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
        UnescapedOutputRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_direct_superglobal_echo() {
        assert_eq!(check("<?php\necho $_GET['x'];\n").len(), 1);
    }

    #[test]
    fn flags_concatenated_superglobal_echo() {
        assert_eq!(check("<?php\necho 'Hi ' . $_GET['name'];\n").len(), 1);
    }

    #[test]
    fn flags_print_intrinsic() {
        assert_eq!(check("<?php\nprint($_GET['x']);\n").len(), 1);
    }

    #[test]
    fn flags_each_operand_in_echo_list() {
        assert_eq!(check("<?php\necho $_GET['a'], $_GET['b'];\n").len(), 2);
    }

    #[test]
    fn allows_escaped_output() {
        assert!(check("<?php\necho esc_html($_GET['x']);\n").is_empty());
    }

    #[test]
    fn allows_escaped_concatenation() {
        assert!(check("<?php\necho esc_html('Hi ' . $_GET['name']);\n").is_empty());
    }

    #[test]
    fn allows_ternary_guarded_by_isset_and_escaped_in_both_arms() {
        assert!(
            check("<?php\necho isset( $_GET['name'] ) ? esc_html( $_GET['name'] ) : '';\n")
                .is_empty()
        );
    }

    #[test]
    fn flags_ternary_with_unescaped_arm() {
        assert_eq!(
            check("<?php\necho isset( $_GET['name'] ) ? $_GET['name'] : '';\n").len(),
            1
        );
    }

    #[test]
    fn ignores_non_superglobal_output() {
        assert!(check("<?php\necho $x;\n").is_empty());
    }

    #[test]
    fn ignores_unrelated_calls() {
        assert!(check("<?php\nstrlen($x);\n").is_empty());
    }
}
