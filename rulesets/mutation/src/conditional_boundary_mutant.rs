use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use yunq_rules_engine::{Finding, IssueType, Rule, RuleId, Severity, declare_rule_id};

declare_rule_id!(ConditionalBoundaryMutantRule, "mutation:conditional-boundary");

impl Rule for ConditionalBoundaryMutantRule {
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
            let text = node.text();
            let is_binary = matches!(node.kind(), NodeKind::Other(k) if k.as_ref() == "binary_expression" || k.as_ref() == "comparison_operator" || k.as_ref() == "infix_expression");

            if is_binary || *node.kind() == NodeKind::FunctionDef {
                // Scan boundary operators
                if text.contains(">=") {
                    out.push(Finding::new(
                        "Boundary Condition Mutant Gap: `>=` operator detected. Ensure tests cover boundary equality and off-by-one cases (mutant: `>`).",
                        node.span(),
                    ));
                } else if text.contains("<=") {
                    out.push(Finding::new(
                        "Boundary Condition Mutant Gap: `<=` operator detected. Ensure tests cover boundary equality and off-by-one cases (mutant: `<`).",
                        node.span(),
                    ));
                } else if text.contains(">") && !text.contains("->") && !text.contains("=>") {
                    out.push(Finding::new(
                        "Boundary Condition Mutant Gap: `>` operator detected. Ensure tests cover boundary equality and off-by-one cases (mutant: `>=`).",
                        node.span(),
                    ));
                } else if text.contains("<") && !text.contains("</") && !text.contains("<-") {
                    out.push(Finding::new(
                        "Boundary Condition Mutant Gap: `<` operator detected. Ensure tests cover boundary equality and off-by-one cases (mutant: `<=`).",
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
