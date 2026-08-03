use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{
    Finding, IssueType, Rule, RuleId, RuleMetadata, Severity, declare_rule_id,
};

use crate::common::{call_arguments, callee_node, subtree_has_unwrapped_superglobal};

/// Admin-menu registration functions and the zero-based argument index that
/// carries `$menu_slug` for each — WordPress uses this value verbatim to
/// build the admin URL (`admin.php?page=$menu_slug`) and to match capability
/// checks against it, so a slug built from request data lets a crafted URL
/// register/resolve to a page the caller wasn't meant to reach. Mirrors
/// WPCS's `WordPress.Security.PluginMenuSlug`.
const MENU_SLUG_ARG_INDEX: &[(&str, usize)] = &[
    ("add_menu_page", 3),
    ("add_submenu_page", 4),
    ("add_options_page", 3),
    ("add_management_page", 3),
    ("add_theme_page", 3),
    ("add_plugins_page", 3),
    ("add_users_page", 3),
    ("add_dashboard_page", 3),
    ("add_posts_page", 3),
    ("add_media_page", 3),
    ("add_links_page", 3),
    ("add_comments_page", 3),
];

/// A bare function call has exactly `[name, arguments]` — two children;
/// this excludes a method call that happens to share one of these names.
fn menu_slug_argument(call: &AstNode) -> Option<&AstNode> {
    if call.children().len() != 2 {
        return None;
    }
    let name = callee_node(call)
        .filter(|c| *c.kind() == NodeKind::Identifier)?
        .text();
    let index = MENU_SLUG_ARG_INDEX
        .iter()
        .find(|(fn_name, _)| *fn_name == name)?
        .1;
    call_arguments(call)?.get(index)
}

declare_rule_id!(
    UnsafePluginMenuSlugRule,
    "wordpress:unsafe-plugin-menu-slug"
);

impl Rule for UnsafePluginMenuSlugRule {
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
            description: "The `$menu_slug` argument to this admin-menu registration function \
                is built from request data. WordPress uses it verbatim in the admin URL and to \
                resolve which page/capability check applies, so a slug an attacker can \
                influence can redirect an admin to an unintended page. Use a static, hardcoded \
                slug string — mirrors WPCS's `WordPress.Security.PluginMenuSlug`."
                .into(),
            tags: vec!["security".into(), "wordpress".into(), "php".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter(|n| *n.kind() == NodeKind::Call)
            .filter_map(menu_slug_argument)
            .filter(|arg| subtree_has_unwrapped_superglobal(arg, &[]))
            .map(|arg| {
                Finding::new(
                    "menu slug is built from request data; use a static, hardcoded string \
                    instead"
                        .to_string(),
                    arg.span(),
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
        UnsafePluginMenuSlugRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_add_menu_page_with_superglobal_slug() {
        assert_eq!(
            check("<?php\nadd_menu_page( 't', 'm', 'manage_options', $_GET['slug'], 'cb' );\n")
                .len(),
            1
        );
    }

    #[test]
    fn flags_add_submenu_page_with_superglobal_slug() {
        assert_eq!(
            check(
                "<?php\nadd_submenu_page( 'parent', 't', 'm', 'manage_options', $_GET['slug'], 'cb' );\n"
            )
            .len(),
            1
        );
    }

    #[test]
    fn allows_static_slug() {
        assert!(
            check("<?php\nadd_menu_page( 't', 'm', 'manage_options', 'my-slug', 'cb' );\n")
                .is_empty()
        );
    }

    #[test]
    fn ignores_unrelated_calls() {
        assert!(check("<?php\nadd_action( 'init', $_GET['cb'] );\n").is_empty());
    }
}
