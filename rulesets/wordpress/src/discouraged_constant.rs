use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{
    Finding, IssueType, Rule, RuleId, RuleMetadata, Severity, declare_rule_id,
};

/// Deprecated WordPress constants with a function-call replacement that
/// resolves correctly for child themes (`TEMPLATEPATH`/`STYLESHEETPATH`
/// point at the *parent* theme even from a child theme's context, which is
/// rarely what code reading them wants). Mirrors WPCS's `WordPress.WP.
/// DiscouragedConstants`.
const DISCOURAGED_CONSTANTS: &[(&str, &str)] = &[
    (
        "TEMPLATEPATH",
        "get_template_directory() — TEMPLATEPATH is deprecated and, unlike \
        get_template_directory(), is unreliable when a child theme is active",
    ),
    (
        "STYLESHEETPATH",
        "get_stylesheet_directory() — STYLESHEETPATH is deprecated and, unlike \
        get_stylesheet_directory(), is unreliable when a child theme is active",
    ),
];

/// Walks the tree looking for a bare (non-`$`) `Identifier` matching one of
/// `DISCOURAGED_CONSTANTS`, without descending into a variable reference's
/// own subtree — tree-sitter-php's `variable_name` node is itself an
/// `Identifier` (text `"$dir"`) wrapping a second `Identifier` for the bare
/// name (text `"dir"`), so a variable that happens to be named e.g.
/// `$TEMPLATEPATH` would otherwise look identical, at that inner node, to a
/// real reference to the `TEMPLATEPATH` constant.
fn find_discouraged_constants<'a>(node: &'a AstNode, out: &mut Vec<&'a AstNode>) {
    if *node.kind() == NodeKind::Identifier {
        if node.text().starts_with('$') {
            return;
        }
        if DISCOURAGED_CONSTANTS
            .iter()
            .any(|(name, _)| *name == node.text())
        {
            out.push(node);
        }
        return;
    }
    for child in node.children() {
        find_discouraged_constants(child, out);
    }
}

declare_rule_id!(DiscouragedConstantRule, "wordpress:discouraged-constant");

impl Rule for DiscouragedConstantRule {
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
            description: "This constant is deprecated by WordPress core in favor of a function \
                that resolves correctly under a child theme. Mirrors WPCS's `WordPress.WP.\
                DiscouragedConstants`."
                .into(),
            tags: vec!["wordpress".into(), "deprecated".into(), "php".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        let mut matches = Vec::new();
        find_discouraged_constants(ast, &mut matches);
        matches
            .into_iter()
            .map(|n| {
                let replacement = DISCOURAGED_CONSTANTS
                    .iter()
                    .find(|(name, _)| *name == n.text())
                    .map(|(_, replacement)| *replacement)
                    .expect("find_discouraged_constants only returns matches");
                Finding::new(format!("use {replacement}"), n.span())
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
        DiscouragedConstantRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_templatepath() {
        assert_eq!(check("<?php\n$dir = TEMPLATEPATH;\n").len(), 1);
    }

    #[test]
    fn flags_stylesheetpath() {
        assert_eq!(check("<?php\n$dir = STYLESHEETPATH;\n").len(), 1);
    }

    #[test]
    fn allows_replacement_function() {
        assert!(check("<?php\n$dir = get_template_directory();\n").is_empty());
    }

    #[test]
    fn ignores_similarly_named_variable() {
        assert!(check("<?php\n$TEMPLATEPATH = 'x';\n").is_empty());
    }
}
