use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use yunq_rules_engine::{declare_rule_id, Finding, IssueType, Rule, RuleId, Severity};

declare_rule_id!(EventHandlerPrefixRule, "naming:event-handler-prefix");

impl Rule for EventHandlerPrefixRule {
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

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        let mut findings = Vec::new();

        fn walk(node: &AstNode, out: &mut Vec<Finding>) {
            if *node.kind() == NodeKind::Identifier {
                let text = node.text();
                // Flag internal function names ending with Handler or starting with onClick_
                if (text.ends_with("Handler") || text.ends_with("_handler")) && !text.starts_with("handle") {
                    out.push(Finding::new(
                        format!("Event handler `{}` should start with `handle` (e.g. `handleClick`, `handleSubmit`).", text),
                        node.span(),
                    ));
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
