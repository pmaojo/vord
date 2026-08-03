use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{
    Finding, IssueType, Rule, RuleId, RuleMetadata, Severity, declare_rule_id,
};

use crate::common::{call_arguments, callee_node};

/// WordPress's translation functions and the argument count each requires
/// once the trailing text-domain argument is included — the domain is what
/// lets a translation-management tool (or another plugin/theme reusing the
/// same string) find the right `.mo` file; a call missing it silently falls
/// back to WordPress core's own domain and is never translated in the
/// plugin/theme's own language pack. Mirrors WPCS's `WordPress.WP.I18n`
/// `MissingArgDomain` check.
const REQUIRED_ARGS: &[(&str, usize)] = &[
    ("__", 2),
    ("_e", 2),
    ("esc_html__", 2),
    ("esc_html_e", 2),
    ("esc_attr__", 2),
    ("esc_attr_e", 2),
    ("_x", 3),
    ("_ex", 3),
    ("esc_html_x", 3),
    ("esc_attr_x", 3),
    ("_n", 4),
    ("_nx", 5),
];

/// A bare function call has exactly `[name, arguments]` — two children;
/// this excludes a method call that happens to share one of these names.
fn translation_call(call: &AstNode) -> Option<(&str, usize)> {
    if call.children().len() != 2 {
        return None;
    }
    let name = callee_node(call)
        .filter(|c| *c.kind() == NodeKind::Identifier)?
        .text();
    REQUIRED_ARGS
        .iter()
        .find(|(fn_name, _)| *fn_name == name)
        .map(|(fn_name, required)| (*fn_name, *required))
}

declare_rule_id!(
    I18nMissingTextDomainRule,
    "wordpress:i18n-missing-text-domain"
);

impl Rule for I18nMissingTextDomainRule {
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
            description: "This translation function call is missing its text-domain argument, \
                so it silently falls back to WordPress core's own domain instead of this \
                plugin's/theme's — the string will never be picked up for translation. Add the \
                text domain as the last argument (e.g. `__( 'Text', 'my-plugin' )`)."
                .into(),
            tags: vec!["wordpress".into(), "i18n".into(), "php".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter(|n| *n.kind() == NodeKind::Call)
            .filter_map(|call| {
                let (name, required) = translation_call(call)?;
                let actual = call_arguments(call).map_or(0, <[AstNode]>::len);
                if actual >= required {
                    return None;
                }
                Some(Finding::new(
                    format!(
                        "{name}() is missing its text-domain argument ({actual} of {required} \
                        arguments given)"
                    ),
                    call.span(),
                ))
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
        I18nMissingTextDomainRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_double_underscore_without_domain() {
        assert_eq!(check("<?php\n__('Hello');\n").len(), 1);
    }

    #[test]
    fn allows_double_underscore_with_domain() {
        assert!(check("<?php\n__('Hello', 'my-plugin');\n").is_empty());
    }

    #[test]
    fn flags_plural_n_missing_domain() {
        assert_eq!(
            check("<?php\n_n('One item', 'Many items', $count);\n").len(),
            1
        );
    }

    #[test]
    fn allows_plural_n_with_domain() {
        assert!(check("<?php\n_n('One item', 'Many items', $count, 'my-plugin');\n").is_empty());
    }

    #[test]
    fn ignores_unrelated_calls() {
        assert!(check("<?php\nstrlen('Hello');\n").is_empty());
    }

    #[test]
    fn ignores_method_call_sharing_a_translation_function_name() {
        assert!(check("<?php\n$obj->__('Hello');\n").is_empty());
    }
}
