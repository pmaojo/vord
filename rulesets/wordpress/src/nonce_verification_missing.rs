use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{
    Finding, IssueType, Rule, RuleId, RuleMetadata, Severity, declare_rule_id,
};

use crate::common::callee_node;

/// `$_POST`/`$_GET`/`$_REQUEST` are the form-data superglobals a nonce check
/// actually guards; `$_COOKIE`/`$_SERVER`/`$_FILES` are out of scope here
/// the same way WPCS's own `NonceVerification` sniff leaves them alone.
const FORM_SUPERGLOBALS: &[&str] = &["$_POST", "$_GET", "$_REQUEST"];

const NONCE_CHECK_FUNCTIONS: &[&str] = &[
    "wp_verify_nonce",
    "check_admin_referer",
    "check_ajax_referer",
];

fn is_form_superglobal(node: &AstNode) -> bool {
    *node.kind() == NodeKind::Identifier && FORM_SUPERGLOBALS.contains(&node.text())
}

fn is_nonce_check_call(node: &AstNode) -> bool {
    *node.kind() == NodeKind::Call
        && callee_node(node).is_some_and(|c| {
            *c.kind() == NodeKind::Identifier && NONCE_CHECK_FUNCTIONS.contains(&c.text())
        })
}

declare_rule_id!(
    NonceVerificationMissingRule,
    "wordpress:nonce-verification-missing"
);

impl Rule for NonceVerificationMissingRule {
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
        20
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "A function that reads `$_POST`/`$_GET`/`$_REQUEST` without calling \
                `wp_verify_nonce()`, `check_admin_referer()`, or `check_ajax_referer()` \
                anywhere in its body processes form data with no CSRF protection. Verify a \
                nonce before acting on the request, or confirm this function is read-only and \
                cannot be the sink for a forged request — mirrors WPCS's `WordPress.Security.\
                NonceVerification`."
                .into(),
            tags: vec![
                "security".into(),
                "csrf".into(),
                "wordpress".into(),
                "php".into(),
            ],
            cwe: Some(352),
            produces_hotspots: true,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter(|n| *n.kind() == NodeKind::FunctionDef)
            .filter_map(|func| {
                let first_use = func.descendants().find(|n| is_form_superglobal(n))?;
                (!func.descendants().any(is_nonce_check_call)).then(|| {
                    Finding::hotspot(
                        "this function reads request data without verifying a nonce anywhere \
                        in its body; confirm a caller already verified one, or add \
                        wp_verify_nonce()/check_admin_referer()/check_ajax_referer()"
                            .to_string(),
                        first_use.span(),
                    )
                })
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
        NonceVerificationMissingRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_post_read_without_nonce_check() {
        assert_eq!(
            check("<?php\nfunction save() {\n  update_option('x', $_POST['x']);\n}\n").len(),
            1
        );
    }

    #[test]
    fn allows_post_read_guarded_by_wp_verify_nonce() {
        assert!(
            check(
                "<?php\nfunction save() {\n  if (!wp_verify_nonce($_POST['nonce'], 'a')) { return; }\n  \
                update_option('x', $_POST['x']);\n}\n"
            )
            .is_empty()
        );
    }

    #[test]
    fn allows_post_read_guarded_by_check_admin_referer() {
        assert!(
            check(
                "<?php\nfunction save() {\n  check_admin_referer('save-action');\n  \
                update_option('x', $_POST['x']);\n}\n"
            )
            .is_empty()
        );
    }

    #[test]
    fn ignores_function_with_no_request_data() {
        assert!(check("<?php\nfunction greet() {\n  return 'hi';\n}\n").is_empty());
    }

    #[test]
    fn ignores_server_superglobal() {
        assert!(
            check("<?php\nfunction log_ip() {\n  return $_SERVER['REMOTE_ADDR'];\n}\n").is_empty()
        );
    }
}
