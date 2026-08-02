use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, Severity, declare_rule_id};

declare_rule_id!(ReturnValueSubstitutionMutantRule, "mutation:return-value-substitution");

/// Instant AST mutation gap analysis: a `return` that carries a computed
/// value is a substitution site — replacing the returned expression with a
/// neutral value (zero, empty, null, a default-constructed instance) is a
/// classic Stryker/PIT `return values` mutant, and the only way a test
/// suite proves it dead is by asserting on the exact value, not just on the
/// path being taken.
impl Rule for ReturnValueSubstitutionMutantRule {
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
                let is_return = matches!(node.kind(), NodeKind::Other(k) if k.starts_with("return"));
                // A bare `return;` (no value) has no substitution to make;
                // only returns carrying an expression are mutant sites.
                is_return && !node.children().is_empty()
            })
            .map(|node| {
                Finding::new(
                    "Return Value Substitution Mutant Gap: `return` carries a computed value. Ensure tests assert on this exact value (mutant: neutral-value substitution).",
                    node.span(),
                )
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vord_ast::{LanguageIdentifier, SourceFile};
    use vord_parser_typescript::TypeScriptParser;
    use vord_rules_engine::AstParser;

    fn findings(code: &str, path: &str, language: LanguageIdentifier) -> Vec<Finding> {
        let file = SourceFile::new(path, code, language).unwrap();
        let ast = TypeScriptParser::new().parse(&file).unwrap();
        ReturnValueSubstitutionMutantRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_returns_carrying_a_value() {
        let f = findings(
            "function f(x: number): number {\n  if (x > 0) { return x * 2; }\n  return 0;\n}\n",
            "f.ts",
            LanguageIdentifier::typescript(),
        );
        assert_eq!(f.len(), 2, "both value-carrying returns are sites");
    }

    #[test]
    fn bare_returns_are_not_sites() {
        let f = findings(
            "function f(x: number): void {\n  if (x > 0) { return; }\n  return;\n}\n",
            "f.ts",
            LanguageIdentifier::typescript(),
        );
        assert!(f.is_empty(), "no value to substitute");
    }
}
