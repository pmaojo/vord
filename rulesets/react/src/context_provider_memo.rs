use yunq_ast::{AstNode, LanguageIdentifier, SourceFile};
use yunq_rules_engine::{declare_rule_id, Finding, IssueType, Rule, RuleId, Severity};

use crate::common::{attributes, attribute_name, attribute_value, opening_tag, is_other};

declare_rule_id!(ContextProviderMemoRule, "react:context-provider-value-memo");

impl Rule for ContextProviderMemoRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, language: &LanguageIdentifier) -> bool {
        language.is_typescript() || language.is_javascript()
    }

    fn default_severity(&self) -> Severity {
        Severity::Major
    }

    fn issue_type(&self) -> IssueType {
        IssueType::CodeSmell
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        let mut findings = Vec::new();

        fn walk(node: &AstNode, out: &mut Vec<Finding>) {
            if is_other(node, "jsx_element") || is_other(node, "jsx_self_closing_element") {
                if let Some(tag) = opening_tag(node) {
                    let text = tag.text();
                    if text.contains(".Provider") || text.ends_with("Provider") {
                        for attr in attributes(node) {
                            if attribute_name(attr) == Some("value") {
                                if let Some(val_node) = attribute_value(attr) {
                                    let val_text = val_node.text();
                                    // Check for inline object {{...}} or array [[...]]
                                    if val_text.starts_with("{{") || val_text.starts_with("{[") {
                                        out.push(Finding::new(
                                            "Inline object/array literal passed to Context Provider `value`. Wrap value in `useMemo` to prevent unneeded re-renders of all consumer components.",
                                            val_node.span(),
                                        ));
                                    }
                                }
                            }
                        }
                    }
                }
            }
            for child in node.children() {
                walk(child, out);
            }
        }

        walk(ast, &mut findings);
        findings
    }
}
