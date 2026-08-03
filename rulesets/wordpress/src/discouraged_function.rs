use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{
    Finding, IssueType, Rule, RuleId, RuleMetadata, Severity, declare_rule_id,
};

use crate::common::callee_node;

/// WordPress core functions that are deprecated or actively discouraged,
/// each paired with the replacement WPCS's own `WordPress.WP.
/// DeprecatedFunctions`/`WordPress.WP.DiscouragedFunctions`/`WordPress.
/// Security.SafeRedirect`/`WordPress.PHP.DiscouragedPHPFunctions` sniffs
/// point to.
const DISCOURAGED_FUNCTIONS: &[(&str, &str)] = &[
    (
        "query_posts",
        "a new WP_Query( ... ) — query_posts() overwrites the main query and can \
        break pagination/conditional tags for the rest of the request",
    ),
    (
        "get_currentuserinfo",
        "wp_get_current_user() — get_currentuserinfo() has been deprecated \
        since WordPress 4.5",
    ),
    (
        "like_escape",
        "$wpdb->esc_like() — like_escape() has been deprecated since WordPress 4.0",
    ),
    (
        "attribute_escape",
        "esc_attr() — attribute_escape() is a deprecated alias",
    ),
    ("clean_url", "esc_url() — clean_url() is a deprecated alias"),
    ("js_escape", "esc_js() — js_escape() is a deprecated alias"),
    (
        "wp_specialchars",
        "esc_html() — wp_specialchars() is a deprecated alias",
    ),
    (
        "create_function",
        "an anonymous function/closure — create_function() has been removed \
        in PHP 8.0 and was always an eval() call in disguise",
    ),
    (
        "wp_redirect",
        "wp_safe_redirect() — wp_redirect() does not validate the target host \
        against the site's allowed redirect hosts, so redirecting to unvalidated input is an \
        open-redirect vector",
    ),
    (
        "get_settings",
        "get_option() — get_settings() has been deprecated since WordPress 2.0",
    ),
    (
        "wp_get_http",
        "the WP_Http class — wp_get_http() has been deprecated since WordPress 4.4",
    ),
    (
        "screen_icon",
        "nothing — screen_icon() has been deprecated since WordPress 3.8 and is a \
        no-op",
    ),
    (
        "get_userdatabylogin",
        "get_user_by( 'login', ... ) — get_userdatabylogin() has been \
        deprecated since WordPress 3.3",
    ),
    (
        "wp_setcookie",
        "wp_set_auth_cookie() — wp_setcookie() has been deprecated since \
        WordPress 2.5",
    ),
    (
        "curl_init",
        "the WordPress HTTP API (wp_remote_get()/wp_remote_post()) — it respects the \
        site's proxy, SSL and blocked-host configuration, which a raw curl_init() call bypasses",
    ),
    (
        "curl_exec",
        "the WordPress HTTP API (wp_remote_get()/wp_remote_post()) — it respects the \
        site's proxy, SSL and blocked-host configuration, which a raw curl_exec() call bypasses",
    ),
    (
        "date_default_timezone_set",
        "get_option( 'timezone_string' )/wp_timezone() — WordPress \
        manages PHP's timezone itself; calling date_default_timezone_set() directly changes it \
        globally for the rest of the request, affecting every other plugin and core system \
        running in it",
    ),
];

/// A bare function call has exactly `[name, arguments]` — two children;
/// this excludes a method call that happens to share one of these names.
fn discouraged_replacement(call: &AstNode) -> Option<&'static str> {
    if call.children().len() != 2 {
        return None;
    }
    let name = callee_node(call)
        .filter(|c| *c.kind() == NodeKind::Identifier)?
        .text();
    DISCOURAGED_FUNCTIONS
        .iter()
        .find(|(fn_name, _)| *fn_name == name)
        .map(|(_, replacement)| *replacement)
}

declare_rule_id!(DiscouragedFunctionRule, "wordpress:discouraged-function");

impl Rule for DiscouragedFunctionRule {
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
        IssueType::CodeSmell
    }

    fn remediation_effort_minutes(&self) -> u32 {
        10
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "This function is deprecated or discouraged by WordPress core; use \
                the replacement WordPress documents instead. Mirrors WPCS's `WordPress.WP.\
                DeprecatedFunctions`/`WordPress.WP.DiscouragedFunctions`."
                .into(),
            tags: vec!["wordpress".into(), "deprecated".into(), "php".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter(|n| *n.kind() == NodeKind::Call)
            .filter_map(|call| {
                discouraged_replacement(call)
                    .map(|replacement| Finding::new(format!("use {replacement}"), call.span()))
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
        DiscouragedFunctionRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_query_posts() {
        assert_eq!(check("<?php\nquery_posts('a=1');\n").len(), 1);
    }

    #[test]
    fn flags_get_currentuserinfo() {
        assert_eq!(check("<?php\nget_currentuserinfo();\n").len(), 1);
    }

    #[test]
    fn flags_create_function() {
        assert_eq!(
            check("<?php\n$f = create_function('$a', 'return $a;');\n").len(),
            1
        );
    }

    #[test]
    fn flags_wp_redirect() {
        assert_eq!(check("<?php\nwp_redirect($_GET['url']);\n").len(), 1);
    }

    #[test]
    fn flags_curl_init() {
        assert_eq!(
            check("<?php\n$ch = curl_init('https://example.com');\n").len(),
            1
        );
    }

    #[test]
    fn allows_wp_safe_redirect() {
        assert!(check("<?php\nwp_safe_redirect(home_url('/'));\n").is_empty());
    }

    #[test]
    fn flags_date_default_timezone_set() {
        assert_eq!(check("<?php\ndate_default_timezone_set('UTC');\n").len(), 1);
    }

    #[test]
    fn ignores_unrelated_calls() {
        assert!(check("<?php\nnew WP_Query('a=1');\n").is_empty());
    }

    #[test]
    fn ignores_method_call_sharing_a_discouraged_name() {
        assert!(check("<?php\n$obj->query_posts('a=1');\n").is_empty());
    }
}
