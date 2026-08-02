use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, Severity, declare_rule_id};

declare_rule_id!(BooleanNamingRule, "naming:boolean-prefix");

impl Rule for BooleanNamingRule {
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
            // Check variable declarators with boolean type annotation or true/false assignment
            if matches!(node.kind(), NodeKind::Other(k) if k.as_ref() == "variable_declarator") {
                if let Some(id_node) = node.first_child() {
                    let name = id_node.text();
                    let text = node.text();
                    if (text.contains(": boolean")
                        || text.ends_with(" = true")
                        || text.ends_with(" = false"))
                        && !name.starts_with("is")
                        && !name.starts_with("has")
                        && !name.starts_with("should")
                        && !name.starts_with("can")
                    {
                        out.push(Finding::new(
                            format!("Boolean variable or property `{}` should start with `is`, `has`, `should`, or `can` (e.g. `isLoading`, `hasPermission`).", name),
                            id_node.span(),
                        ));
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
