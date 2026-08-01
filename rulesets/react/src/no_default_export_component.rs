use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use yunq_rules_engine::{declare_rule_id, Finding, IssueType, Rule, RuleId, Severity};

declare_rule_id!(NoDefaultExportComponentRule, "react:no-default-export");

impl Rule for NoDefaultExportComponentRule {
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
            // export_statement with "default" keyword
            if matches!(node.kind(), NodeKind::Other(k) if k.as_ref() == "export_statement") {
                let text = node.text();
                if text.contains("export default") {
                    out.push(Finding::new(
                        "Prefer explicit named exports (`export const MyComponent = ...`) over default exports for consistent refactoring and AI context resolution.",
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
