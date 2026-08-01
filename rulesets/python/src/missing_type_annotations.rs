use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use yunq_rules_engine::{declare_rule_id, Finding, IssueType, Rule, RuleId, Severity};

declare_rule_id!(MissingTypeAnnotationsRule, "python:missing-type-annotations");

impl Rule for MissingTypeAnnotationsRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, language: &LanguageIdentifier) -> bool {
        *language == LanguageIdentifier::python()
    }

    fn default_severity(&self) -> Severity {
        Severity::Major
    }

    fn issue_type(&self) -> IssueType {
        IssueType::CodeSmell
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        let mut findings = Vec::new();

        fn walk<'a>(node: &'a AstNode, out: &mut Vec<Finding>) {
            if *node.kind() == NodeKind::FunctionDef {
                let text = node.text();
                // Check if top-level or public function `def foo(...)` lacks `->` return type hint
                if let Some(first_line) = text.lines().next() {
                    if first_line.starts_with("def ") && !first_line.starts_with("def _") {
                        if !first_line.contains("->") {
                            out.push(Finding::new(
                                "Public Python function missing explicit return type annotation (`-> ReturnType`). Enforce strict typing for AI agent clarity.",
                                node.span(),
                            ));
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
