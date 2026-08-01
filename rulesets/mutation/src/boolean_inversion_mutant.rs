use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use yunq_rules_engine::{Finding, IssueType, Rule, RuleId, Severity, declare_rule_id};

declare_rule_id!(BooleanInversionMutantRule, "mutation:boolean-inversion");

impl Rule for BooleanInversionMutantRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, _language: &LanguageIdentifier) -> bool {
        true
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
            let is_conditional = matches!(node.kind(), NodeKind::Other(k) if k.as_ref() == "if_statement" || k.as_ref() == "if_expression" || k.as_ref() == "conditional_expression");

            if is_conditional {
                let text = node.text();
                if text.contains("&&") {
                    out.push(Finding::new(
                        "Boolean Logic Mutant Gap: Logical AND `&&` in condition. Ensure tests independently verify both operands (mutant: `||`).",
                        node.span(),
                    ));
                } else if text.contains("||") {
                    out.push(Finding::new(
                        "Boolean Logic Mutant Gap: Logical OR `||` in condition. Ensure tests independently verify both operands (mutant: `&&`).",
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
