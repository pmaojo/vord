//! Rule: flags passing `children` as an explicit JSX attribute (`<Comp children={...} />`)
//! instead of nested JSX elements.

use yunq_ast::{AstNode, LanguageIdentifier, SourceFile};
use yunq_rules_engine::{declare_rule_id, Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

use crate::common::{find_attribute, is_jsx_kind};

declare_rule_id!(NoChildrenPropRule, "react:no-children-prop");

impl Rule for NoChildrenPropRule {
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
            description: "Passing `children` as an explicit prop (`<Comp children={...} />`) is anti-idiomatic in React. Children should be passed as nested elements inside the JSX tag.".into(),
            tags: vec!["react".into(), "jsx".into(), "style".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        let mut findings = Vec::new();

        for node in ast.descendants() {
            if !is_jsx_kind(node) {
                continue;
            }

            if let Some(attr) = find_attribute(node, "children") {
                findings.push(Finding::new(
                    "Avoid passing `children` as an explicit JSX prop. Pass children as nested JSX elements inside `<Comp>...</Comp>` instead.",
                    attr.span(),
                ));
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use yunq_rules_engine::AstParser;

    fn check(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.tsx", code, LanguageIdentifier::typescript()).unwrap();
        let ast = yunq_parser_typescript::TypeScriptParser::new()
            .parse(&file)
            .unwrap();
        NoChildrenPropRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_explicit_children_prop_with_string() {
        let code = "const el = <Comp children=\"Hello\" />;\n";
        let findings = check(code);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("children"));
    }

    #[test]
    fn flags_explicit_children_prop_with_expression() {
        let code = "const el = <Comp children={<span>Content</span>} />;\n";
        let findings = check(code);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn allows_nested_jsx_children() {
        let code = "const el = <Comp><span>Content</span></Comp>;\n";
        let findings = check(code);
        assert!(findings.is_empty());
    }

    #[test]
    fn allows_other_props() {
        let code = "const el = <Comp title=\"Children\"><span>Content</span></Comp>;\n";
        let findings = check(code);
        assert!(findings.is_empty());
    }
}
