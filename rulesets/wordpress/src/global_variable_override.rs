use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{
    Finding, IssueType, Rule, RuleId, RuleMetadata, Severity, declare_rule_id,
};

use crate::common::is_other;

/// WordPress core globals a plugin/theme reassigning wholesale corrupts for
/// every other piece of code running in the same request — the entire
/// point of `global $wpdb;` is to *read* the shared instance, not replace
/// it. Mirrors WPCS's `WordPress.WP.GlobalVariablesOverride`.
const PROTECTED_GLOBALS: &[&str] = &[
    "post",
    "wpdb",
    "wp_query",
    "wp_the_query",
    "wp",
    "wp_rewrite",
    "current_user",
    "wp_object_cache",
    "table_prefix",
    "wp_customize",
    "wp_scripts",
    "wp_styles",
    "wp_locale",
    "wp_filesystem",
];

fn is_protected_name(name: &str) -> bool {
    PROTECTED_GLOBALS.contains(&name)
}

fn string_content(node: &AstNode) -> Option<&str> {
    (*node.kind() == NodeKind::StringLiteral)
        .then(|| node.children().first().map_or("", |c| c.text()))
}

/// `$GLOBALS['wpdb'] = ...` — an unconditional clobber, no scope tracking
/// needed to know it's wrong.
fn globals_array_key(target: &AstNode) -> Option<&str> {
    if !is_other(target.kind(), "subscript_expression") {
        return None;
    }
    match target.children() {
        [base, key] if *base.kind() == NodeKind::Identifier && base.text() == "$GLOBALS" => {
            string_content(key)
        }
        _ => None,
    }
}

/// `global $post;` followed by `$post = ...;` in the same function body —
/// scoped per `FunctionDef` the same way `wordpress:nonce-verification-
/// missing` scopes its own check, so a `global $x;` in one function can't
/// pair with an unrelated `$x = ...;` in another.
fn function_scope_overrides(func: &AstNode) -> Vec<Finding> {
    let declared_protected_names: Vec<&str> = func
        .descendants()
        .filter(|n| is_other(n.kind(), "global_declaration"))
        .flat_map(|g| g.children().iter())
        .filter(|id| *id.kind() == NodeKind::Identifier)
        .map(|id| id.text().trim_start_matches('$'))
        .filter(|name| is_protected_name(name))
        .collect();
    if declared_protected_names.is_empty() {
        return Vec::new();
    }
    func.descendants()
        .filter(|n| *n.kind() == NodeKind::Assignment)
        .filter_map(|assign| match assign.children() {
            [target, _value] if *target.kind() == NodeKind::Identifier => {
                let name = target.text().trim_start_matches('$');
                declared_protected_names.contains(&name).then(|| {
                    Finding::new(
                        format!(
                            "reassigns ${name} after `global ${name};`, replacing WordPress's \
                            own ${name} instead of reading it"
                        ),
                        assign.span(),
                    )
                })
            }
            _ => None,
        })
        .collect()
}

declare_rule_id!(
    GlobalVariableOverrideRule,
    "wordpress:global-variable-override"
);

impl Rule for GlobalVariableOverrideRule {
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
        IssueType::Bug
    }

    fn remediation_effort_minutes(&self) -> u32 {
        15
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "Reassigning a WordPress core global (`$post`, `$wpdb`, `$wp_query`, \
                ...) replaces the shared instance every other piece of code in the request \
                reads from, instead of the value it was pulled in to read. Mutate the object \
                itself, use the accessor WordPress provides (`wp_reset_postdata()`, a new \
                `WP_Query`, ...), or write to a variable that isn't shadowing a core global — \
                mirrors WPCS's `WordPress.WP.GlobalVariablesOverride`."
                .into(),
            tags: vec!["wordpress".into(), "php".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        let globals_array_overrides = ast
            .descendants()
            .filter(|n| *n.kind() == NodeKind::Assignment)
            .filter_map(|assign| match assign.children() {
                [target, _value] => globals_array_key(target)
                    .filter(|key| is_protected_name(key))
                    .map(|key| {
                        Finding::new(
                            format!(
                                "overwrites $GLOBALS['{key}'], replacing WordPress's own \
                                ${key} instead of reading it"
                            ),
                            assign.span(),
                        )
                    }),
                _ => None,
            });

        let function_scope_overrides = ast
            .descendants()
            .filter(|n| *n.kind() == NodeKind::FunctionDef)
            .flat_map(function_scope_overrides);

        globals_array_overrides
            .chain(function_scope_overrides)
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
        GlobalVariableOverrideRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_globals_array_clobber() {
        assert_eq!(check("<?php\n$GLOBALS['wpdb'] = $custom;\n").len(), 1);
    }

    #[test]
    fn flags_global_declared_then_reassigned_in_function() {
        assert_eq!(
            check("<?php\nfunction reset() {\n  global $post;\n  $post = $new_post;\n}\n").len(),
            1
        );
    }

    #[test]
    fn allows_global_declared_and_only_mutated() {
        assert!(
            check("<?php\nfunction rename() {\n  global $post;\n  $post->post_title = 'x';\n}\n")
                .is_empty()
        );
    }

    #[test]
    fn ignores_globals_array_write_to_unprotected_key() {
        assert!(check("<?php\n$GLOBALS['my_plugin_state'] = $custom;\n").is_empty());
    }

    #[test]
    fn ignores_local_variable_assignment() {
        assert!(check("<?php\nfunction run() {\n  $post = get_post();\n}\n").is_empty());
    }
}
