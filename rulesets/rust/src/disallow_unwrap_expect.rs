use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use yunq_rules_engine::{declare_rule_id, Finding, IssueType, Rule, RuleId, Severity};

declare_rule_id!(DisallowUnwrapExpectRule, "rust:disallow-unwrap-expect");

impl Rule for DisallowUnwrapExpectRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, language: &LanguageIdentifier) -> bool {
        *language == LanguageIdentifier::rust()
    }

    fn default_severity(&self) -> Severity {
        Severity::Major
    }

    fn issue_type(&self) -> IssueType {
        IssueType::CodeSmell
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        // Skip test files / test modules
        let path = file.path();
        if path.contains("tests/") || path.contains("_test.rs") {
            return Vec::new();
        }

        let mut findings = Vec::new();

        fn walk(node: &AstNode, out: &mut Vec<Finding>) {
            if matches!(node.kind(), NodeKind::Other(k) if k.as_ref() == "call_expression") {
                if let Some(field) = node.first_child() {
                    let text = field.text();
                    if text.ends_with(".unwrap") || text.ends_with(".expect") {
                        out.push(Finding::new(
                            "Avoid `.unwrap()` or `.expect()` in production code as it causes panics. Propagate errors using `?` or handle them explicitly with `match`/`if let`.",
                            field.span(),
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
