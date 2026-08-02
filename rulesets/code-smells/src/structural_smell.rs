//! Structural Anti-Pattern Rule utilizing the Tree-sitter S-Expression Pattern Matching Engine.

use vord_ast::{AstNode, Pattern, SourceFile};
use vord_rules_engine::{Finding, Rule, RuleId, Severity};

pub struct StructuralSmellRule {
    id: RuleId,
    patterns: Vec<(Pattern, &'static str)>,
}

impl StructuralSmellRule {
    pub fn new() -> Self {
        let eval_pattern = Pattern::parse("(Call (Identifier) @fn (#eq? @fn \"eval\"))")
            .expect("valid eval pattern");
        let unsafe_pattern =
            Pattern::parse("(Call (Identifier) @fn (#match? @fn \"exec|system\"))")
                .expect("valid unsafe pattern");

        Self {
            id: RuleId::new("smells:structural-anti-pattern").expect("valid RuleId"),
            patterns: vec![
                (
                    eval_pattern,
                    "eval() invocation detected via S-expression AST pattern matching",
                ),
                (
                    unsafe_pattern,
                    "Unsafe system/exec invocation detected via S-expression AST pattern matching",
                ),
            ],
        }
    }
}

impl Default for StructuralSmellRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for StructuralSmellRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn default_severity(&self) -> Severity {
        Severity::Major
    }

    fn applies_to(&self, _lang: &vord_ast::LanguageIdentifier) -> bool {
        true
    }

    fn check(&self, _file: &SourceFile, root: &AstNode) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (pattern, message) in &self.patterns {
            let matches = pattern.find_matches(root);
            for m in matches {
                findings.push(Finding::new(message.to_string(), m.root.span()));
            }
        }
        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vord_ast::{LanguageIdentifier, NodeKind, Span};

    #[test]
    fn detects_structural_smell_pattern() {
        let rule = StructuralSmellRule::new();
        let file = SourceFile::new("test.js", "eval()", LanguageIdentifier::typescript()).unwrap();
        let fn_node = AstNode::new(NodeKind::Identifier, Span::new(1, 1, 1, 5), "eval", vec![]);
        let root = AstNode::new(
            NodeKind::Call,
            Span::new(1, 1, 1, 10),
            "eval()",
            vec![fn_node],
        );

        let findings = rule.check(&file, &root);
        assert_eq!(findings.len(), 1);
    }
}
