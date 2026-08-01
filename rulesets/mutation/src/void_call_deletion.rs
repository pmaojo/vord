use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use yunq_rules_engine::{Finding, IssueType, Rule, RuleId, Severity, declare_rule_id};

declare_rule_id!(VoidCallDeletionMutantRule, "mutation:void-call-deletion");

/// Instant AST mutation gap analysis: a call used as a whole statement
/// (`foo();` / `logger.info(...)` / `cache.invalidate()`) is a *void call
/// deletion* site — removing it changes side effects but produces no
/// observable value, so a test suite proves it alive only by asserting on
/// the side effect (or by an assertion further down the line that breaks
/// when the call disappears). The classic Stryker/PIT `void method call`
/// mutant family.
impl Rule for VoidCallDeletionMutantRule {
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
        ast.descendants()
            .filter(|node| {
                let is_expr_statement = matches!(
                    node.kind(),
                    NodeKind::Other(k) if k.as_ref() == "expression_statement"
                );
                is_expr_statement
                    && node
                        .children()
                        .first()
                        .is_some_and(|child| *child.kind() == NodeKind::Call)
            })
            .map(|node| {
                Finding::new(
                    format!(
                        "Void Call Deletion Mutant Gap: statement-level call `{}` has no captured result. Ensure tests assert on its side effect (mutant: call removal).",
                        node.text()
                    ),
                    node.span(),
                )
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use yunq_ast::{LanguageIdentifier, SourceFile};
    use yunq_parser_typescript::TypeScriptParser;
    use yunq_rules_engine::AstParser;

    fn findings(code: &str, path: &str, language: LanguageIdentifier) -> Vec<Finding> {
        let file = SourceFile::new(path, code, language).unwrap();
        let ast = TypeScriptParser::new().parse(&file).unwrap();
        VoidCallDeletionMutantRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_statement_level_calls() {
        let f = findings(
            "function go() {\n  cache.invalidate();\n  track('evt');\n}\n",
            "go.ts",
            LanguageIdentifier::typescript(),
        );
        assert_eq!(f.len(), 2);
    }

    #[test]
    fn calls_whose_result_is_used_are_not_sites() {
        let f = findings(
            "function go() {\n  const n = compute();\n  return compute() + 1;\n}\n",
            "go.ts",
            LanguageIdentifier::typescript(),
        );
        assert!(f.is_empty(), "result is captured, deletion would be caught");
    }
}
