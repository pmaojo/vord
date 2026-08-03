use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{
    Finding, IssueType, Rule, RuleId, RuleMetadata, Severity, declare_rule_id,
};

use crate::common::{call_arguments, callee_node};

const ENQUEUE_FUNCTIONS: &[&str] = &[
    "wp_enqueue_script",
    "wp_register_script",
    "wp_enqueue_style",
    "wp_register_style",
];

/// `wp_enqueue_script( $handle, $src, $deps, $ver, $in_footer )`/
/// `wp_enqueue_style( $handle, $src, $deps, $ver, $media )` — `$ver` is
/// `$src`'s 0-based argument index plus 2.
const VER_ARG_INDEX: usize = 3;
const SRC_ARG_INDEX: usize = 1;

/// `call_arguments` returns each `arguments` child as-is — the `argument`
/// wrapper tree-sitter-php puts around it, not the `StringLiteral` inside —
/// so this looks for a `StringLiteral` anywhere in the (one-node-deep)
/// subtree rather than requiring `node` itself to be one.
fn string_literal_content(node: &AstNode) -> Option<&str> {
    node.descendants()
        .find(|n| *n.kind() == NodeKind::StringLiteral)
        .map(|s| s.children().first().map_or("", |c| c.text()))
}

/// A bare function call has exactly `[name, arguments]` — two children;
/// this excludes a method call that happens to share one of these names.
fn enqueue_issue(call: &AstNode) -> Option<&'static str> {
    if call.children().len() != 2 {
        return None;
    }
    let name = callee_node(call)
        .filter(|c| *c.kind() == NodeKind::Identifier)?
        .text();
    if !ENQUEUE_FUNCTIONS.contains(&name) {
        return None;
    }
    let args = call_arguments(call)?;
    if args.len() <= VER_ARG_INDEX {
        return Some(
            "is missing its $ver argument; an omitted version falls back to the current \
            WordPress version, so the browser cache for this asset only busts when WordPress \
            itself updates, not when this file changes — pass an explicit version string (or \
            null to opt out)",
        );
    }
    if args
        .get(SRC_ARG_INDEX)
        .and_then(|arg| string_literal_content(arg))
        .is_some_and(|src| src.contains('?'))
    {
        return Some(
            "has a query string baked into $src; pass the version through the dedicated $ver \
            argument instead so WordPress can manage cache-busting consistently",
        );
    }
    None
}

declare_rule_id!(
    EnqueuedResourceVersionRule,
    "wordpress:unversioned-enqueued-resource"
);

impl Rule for EnqueuedResourceVersionRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, language: &LanguageIdentifier) -> bool {
        *language == LanguageIdentifier::php()
    }

    fn default_severity(&self) -> Severity {
        Severity::Minor
    }

    fn issue_type(&self) -> IssueType {
        IssueType::CodeSmell
    }

    fn remediation_effort_minutes(&self) -> u32 {
        5
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "This enqueued script/style either omits its $ver argument or bakes a \
                query string into $src instead of using $ver, so the browser cache for it \
                doesn't reliably bust when the file changes. Mirrors WPCS's `WordPress.WP.\
                EnqueuedResourceParameters`."
                .into(),
            tags: vec!["wordpress".into(), "performance".into(), "php".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter(|n| *n.kind() == NodeKind::Call)
            .filter_map(|call| {
                enqueue_issue(call).map(|msg| Finding::new(msg.to_string(), call.span()))
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
        EnqueuedResourceVersionRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_missing_ver_argument() {
        assert_eq!(
            check("<?php\nwp_enqueue_script( 'h', 'script.js' );\n").len(),
            1
        );
    }

    #[test]
    fn flags_query_string_in_src() {
        assert_eq!(
            check("<?php\nwp_enqueue_script( 'h', 'script.js?ver=1', array(), null, true );\n")
                .len(),
            1
        );
    }

    #[test]
    fn allows_explicit_version_argument() {
        assert!(
            check("<?php\nwp_enqueue_script( 'h', 'script.js', array(), '1.0', true );\n")
                .is_empty()
        );
    }

    #[test]
    fn allows_null_version_to_opt_out() {
        assert!(check("<?php\nwp_enqueue_style( 'h', 'style.css', array(), null );\n").is_empty());
    }

    #[test]
    fn ignores_unrelated_calls() {
        assert!(check("<?php\nwp_enqueue_media();\n").is_empty());
    }

    #[test]
    fn ignores_method_call_sharing_an_enqueue_name() {
        assert!(check("<?php\n$obj->wp_enqueue_script( 'h', 'script.js' );\n").is_empty());
    }
}
