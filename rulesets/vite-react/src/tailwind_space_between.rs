//! Rule: a `space-x-*`/`space-y-*` Tailwind utility in a JSX
//! `className`/`class` attribute — Tailwind itself deprecated the
//! `space-between` utilities in favor of `gap-*` (flex/grid `gap` avoids
//! the "last child gets an extra margin" artifact `space-*`'s
//! sibling-selector approach produces, and composes cleanly with
//! `flex-wrap`, which `space-*` does not).

use globset::GlobSet;
use vord_ast::{AstNode, LanguageIdentifier, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

use crate::common::{
    build_globset, class_attribute_span, class_attribute_text, is_excepted, is_jsx_kind,
};

pub struct TailwindSpaceBetweenRule {
    id: RuleId,
    exceptions: GlobSet,
}

impl TailwindSpaceBetweenRule {
    pub fn new() -> Self {
        Self::with_exceptions(Vec::new())
    }

    pub fn with_exceptions(globs: Vec<String>) -> Self {
        Self {
            id: RuleId::new("vite-react:tailwind-space-between").expect("valid rule id"),
            exceptions: build_globset(&globs),
        }
    }
}

impl Default for TailwindSpaceBetweenRule {
    fn default() -> Self {
        Self::new()
    }
}

fn space_between_token(class_list: &str) -> Option<&str> {
    class_list
        .split_whitespace()
        .find(|token| token.starts_with("space-x-") || token.starts_with("space-y-"))
}

impl Rule for TailwindSpaceBetweenRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, language: &LanguageIdentifier) -> bool {
        language.is_typescript() || language.is_javascript()
    }

    fn default_severity(&self) -> Severity {
        Severity::Minor
    }

    fn issue_type(&self) -> IssueType {
        IssueType::CodeSmell
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "A `space-x-*`/`space-y-*` Tailwind utility sits in a JSX class list — use `gap-*` on a flex/grid container instead: it avoids the extra-margin-on-the-last-child artifact and composes with `flex-wrap`.".into(),
            tags: vec!["vite-react".into(), "tailwind".into(), "css".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        if vord_rules_engine::is_test_only_path(file.path())
            || is_excepted(file.path(), &self.exceptions)
        {
            return Vec::new();
        }
        ast.descendants()
            .filter(|n| is_jsx_kind(n))
            .filter_map(|el| {
                let text = class_attribute_text(el)?;
                let token = space_between_token(&text)?;
                let span = class_attribute_span(el).unwrap_or_else(|| el.span());
                Some(Finding::new(
                    format!(
                        "`{token}` in a class list — Tailwind deprecated `space-between` utilities; use `gap-*` on a flex/grid container instead"
                    ),
                    span,
                ))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vord_rules_engine::AstParser;

    fn tsx(code: &str) -> Vec<Finding> {
        let file = SourceFile::new(
            "src/components/Toolbar.tsx",
            code,
            LanguageIdentifier::typescript(),
        )
        .unwrap();
        let ast = vord_parser_typescript::TypeScriptParser::new()
            .parse(&file)
            .unwrap();
        TailwindSpaceBetweenRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_space_x_in_class_name() {
        let findings = tsx("const el = <div className=\"flex space-x-4\">x</div>;\n");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("space-x-4"));
    }

    #[test]
    fn flags_space_y_in_a_self_closing_element() {
        let findings = tsx("const el = <ul className=\"space-y-2\" />;\n");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("space-y-2"));
    }

    #[test]
    fn flags_the_class_attribute_too() {
        let findings = tsx("const el = <div class=\"space-x-4\">x</div>;\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn silent_on_gap_utilities() {
        assert!(tsx("const el = <div className=\"flex gap-4\">x</div>;\n").is_empty());
    }

    #[test]
    fn silent_with_no_class_attribute() {
        assert!(tsx("const el = <div>x</div>;\n").is_empty());
    }

    #[test]
    fn silent_on_a_dynamic_class_expression() {
        assert!(tsx("const el = <div className={styles.container}>x</div>;\n").is_empty());
    }
}
