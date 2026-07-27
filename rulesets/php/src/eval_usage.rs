use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use yunq_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

use crate::common::callee_node;

/// Security hotspot: `eval()` executes a string as PHP code — if any part
/// of that string is ever influenced by request input, it's arbitrary code
/// execution. Mirrors Sonar's `php:S1523` ("Dynamic code execution should
/// not be vulnerable to injection attacks").
pub struct EvalUsageRule {
    id: RuleId,
}

impl EvalUsageRule {
    pub fn new() -> Self {
        Self { id: RuleId::new("php:eval-usage").expect("valid rule id") }
    }
}

impl Default for EvalUsageRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for EvalUsageRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, language: &LanguageIdentifier) -> bool {
        *language == LanguageIdentifier::php()
    }

    fn default_severity(&self) -> Severity {
        Severity::Critical
    }

    fn issue_type(&self) -> IssueType {
        IssueType::Vulnerability
    }

    fn remediation_effort_minutes(&self) -> u32 {
        20
    }

    fn metadata(&self) -> yunq_rules_engine::RuleMetadata {
        yunq_rules_engine::RuleMetadata {
            description: "`eval()` executes a string as PHP code; if any part of that string \
                can be influenced by request input, this is arbitrary code execution. Confirm \
                the argument is never attacker-controlled, or remove the `eval()`."
                .into(),
            tags: vec!["security".into(), "injection".into(), "php".into()],
            cwe: Some(95),
            produces_hotspots: true,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter(|n| *n.kind() == NodeKind::Call)
            .filter(|call| callee_node(call).is_some_and(|c| *c.kind() == NodeKind::Identifier && c.text() == "eval"))
            .map(|call| {
                Finding::hotspot(
                    "confirm this `eval()` argument can never be influenced by request input",
                    call.span(),
                )
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use yunq_ast::SourceFile;
    use yunq_rules_engine::AstParser;

    use super::*;

    fn check(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.php", code, LanguageIdentifier::php()).unwrap();
        let ast = yunq_parser_php::PhpParser::new().parse(&file).unwrap();
        EvalUsageRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_eval_call() {
        assert_eq!(check("<?php\neval($_POST['code']);\n").len(), 1);
    }

    #[test]
    fn ignores_unrelated_calls() {
        assert!(check("<?php\nstrlen($x);\n").is_empty());
    }
}
