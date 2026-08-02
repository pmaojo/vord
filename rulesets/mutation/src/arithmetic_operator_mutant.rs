use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, Severity, declare_rule_id};

declare_rule_id!(ArithmeticOperatorMutantRule, "mutation:arithmetic-operator");

impl Rule for ArithmeticOperatorMutantRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, _language: &LanguageIdentifier) -> bool {
        true
    }

    fn default_severity(&self) -> Severity {
        Severity::Info
    }

    fn issue_type(&self) -> IssueType {
        IssueType::CodeSmell
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        let mut findings = Vec::new();

        fn walk(node: &AstNode, out: &mut Vec<Finding>) {
            let is_binary = matches!(node.kind(), NodeKind::Other(k) if k.as_ref() == "binary_expression" || k.as_ref() == "infix_expression");

            if is_binary {
                let text = node.text();
                if text.contains('+') && !text.contains("++") && !text.contains("+=") {
                    out.push(Finding::new(
                        "Arithmetic Operator Mutant Gap: `+` operator detected. Ensure unit tests cover addition logic (mutant: `-`).",
                        node.span(),
                    ));
                } else if text.contains('-') && !text.contains("--") && !text.contains("-=") && !text.contains("->") {
                    out.push(Finding::new(
                        "Arithmetic Operator Mutant Gap: `-` operator detected. Ensure unit tests cover subtraction logic (mutant: `+`).",
                        node.span(),
                    ));
                } else if text.contains('*') && !text.contains("**") && !text.contains("*=") {
                    out.push(Finding::new(
                        "Arithmetic Operator Mutant Gap: `*` operator detected. Ensure unit tests cover multiplication logic (mutant: `/`).",
                        node.span(),
                    ));
                }
            }

            for child in node.children() {
                walk(child, out);
            }
        }

        for child in ast.children() {
            walk(child, &mut findings);
        }

        findings
    }
}
