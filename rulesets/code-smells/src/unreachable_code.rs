use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use yunq_rules_engine::{declare_rule_id, Finding, IssueType, Rule, RuleId, Severity};

declare_rule_id!(UnreachableCodeRule, "smells:unreachable-code");

impl Rule for UnreachableCodeRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, _language: &LanguageIdentifier) -> bool {
        true
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
            if matches!(node.kind(), NodeKind::Other(k) if k.as_ref() == "statement_block" || k.as_ref() == "block") {
                let children = node.children();
                let mut term_idx = None;

                for (i, child) in children.iter().enumerate() {
                    let text = child.text();
                    if text.starts_with("return") || text.starts_with("throw") || text.starts_with("raise") || text.starts_with("break") {
                        term_idx = Some(i);
                        break;
                    }
                }

                if let Some(idx) = term_idx {
                    if idx + 1 < children.len() {
                        let dead_node = &children[idx + 1];
                        out.push(Finding::new(
                            "Unreachable code detected: Statement appears after `return`, `throw`/`raise`, or `break`.",
                            dead_node.span(),
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
