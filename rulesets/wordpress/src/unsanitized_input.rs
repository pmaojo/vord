use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{
    Finding, IssueType, Rule, RuleId, RuleMetadata, Severity, declare_rule_id,
};

use crate::common::subtree_has_unwrapped_superglobal;

/// Functions that actually validate/sanitize a value, as opposed to
/// `wp_unslash()` alone (removes magic-quote escaping, not a sanitizer —
/// WPCS still requires one of these wrapped around it) or an escaping
/// function meant for *output* (`esc_html()` et al., covered separately by
/// `wordpress:unescaped-superglobal-output` — escaping for display and
/// sanitizing for storage/use are different WPCS categories with different
/// function lists).
const SANITIZING_FUNCTIONS: &[&str] = &[
    "sanitize_text_field",
    "sanitize_textarea_field",
    "sanitize_email",
    "sanitize_key",
    "sanitize_file_name",
    "sanitize_html_class",
    "sanitize_title",
    "sanitize_url",
    "sanitize_meta",
    "esc_url_raw",
    "absint",
    "intval",
    "floatval",
    "boolval",
    "wp_kses",
    "wp_kses_post",
];

/// tree-sitter-php wraps every top-level statement's expression in an
/// `expression_statement`, which this workspace's PHP mapping also collapses
/// onto `NodeKind::Assignment` (alongside real `assignment_expression`
/// nodes) — so a genuine assignment is the two-child shape `[target,
/// value]`; a one-child `Assignment` is just the statement wrapper around
/// some other expression (a bare call, an echoed value, ...).
fn assignment_value(node: &AstNode) -> Option<&AstNode> {
    match node.children() {
        [_target, value] => Some(value),
        _ => None,
    }
}

declare_rule_id!(
    UnsanitizedInputRule,
    "wordpress:unsanitized-superglobal-input"
);

impl Rule for UnsanitizedInputRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, language: &LanguageIdentifier) -> bool {
        *language == LanguageIdentifier::php()
    }

    fn default_severity(&self) -> Severity {
        Severity::Major
    }

    fn issue_type(&self) -> IssueType {
        IssueType::Vulnerability
    }

    fn remediation_effort_minutes(&self) -> u32 {
        15
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "A `$_GET`/`$_POST`/`$_REQUEST`/`$_COOKIE`/`$_SERVER`/`$_FILES` value \
                is assigned to a variable without being validated or sanitized first — \
                `wp_unslash()` alone doesn't count, it only reverses magic-quote escaping. Wrap \
                it in `sanitize_text_field()`, `sanitize_email()`, `absint()`, or whichever \
                sanitizer matches the expected shape before using the value — mirrors WPCS's \
                `WordPress.Security.ValidatedSanitizedInput`."
                .into(),
            tags: vec!["security".into(), "wordpress".into(), "php".into()],
            cwe: Some(20),
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter(|n| *n.kind() == NodeKind::Assignment)
            .filter_map(assignment_value)
            .filter(|value| subtree_has_unwrapped_superglobal(value, SANITIZING_FUNCTIONS))
            .map(|value| {
                Finding::new(
                    "request data is assigned without validation or sanitization; wrap it in \
                    sanitize_text_field()/sanitize_email()/absint()/... before use"
                        .to_string(),
                    value.span(),
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
        UnsanitizedInputRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_direct_assignment_from_post() {
        assert_eq!(check("<?php\n$name = $_POST['name'];\n").len(), 1);
    }

    #[test]
    fn flags_unslash_alone_as_insufficient() {
        assert_eq!(
            check("<?php\n$name = wp_unslash($_POST['name']);\n").len(),
            1
        );
    }

    #[test]
    fn allows_sanitize_text_field() {
        assert!(check("<?php\n$name = sanitize_text_field($_POST['name']);\n").is_empty());
    }

    #[test]
    fn allows_sanitize_wrapped_around_unslash() {
        assert!(
            check("<?php\n$name = sanitize_text_field(wp_unslash($_POST['name']));\n").is_empty()
        );
    }

    #[test]
    fn allows_isset_guarded_ternary_sanitized_in_both_arms() {
        assert!(
            check(
                "<?php\n$name = isset( $_POST['name'] ) ? sanitize_text_field( wp_unslash( $_POST['name'] ) ) : '';\n"
            )
            .is_empty()
        );
    }

    #[test]
    fn flags_isset_guarded_ternary_with_unsanitized_arm() {
        assert_eq!(
            check("<?php\n$name = isset( $_POST['name'] ) ? $_POST['name'] : '';\n").len(),
            1
        );
    }

    #[test]
    fn allows_array_map_with_sanitizing_callback() {
        assert!(check("<?php\n$ids = array_map( 'absint', $_GET['ID'] );\n").is_empty());
    }

    #[test]
    fn flags_array_map_with_non_sanitizing_callback() {
        assert_eq!(
            check("<?php\n$tags = array_map( 'trim', $_POST['tags'] );\n").len(),
            1
        );
    }

    #[test]
    fn ignores_assignment_from_local_variable() {
        assert!(check("<?php\n$name = $default;\n").is_empty());
    }

    #[test]
    fn ignores_bare_call_statement() {
        assert!(check("<?php\nupdate_option('x', 'y');\n").is_empty());
    }
}
