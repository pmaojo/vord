use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use yunq_rules_engine::{Finding, Rule, RuleId, Severity};

const SUSPICIOUS_NAMES: &[&str] =
    &["password", "passwd", "secret", "apikey", "api_key", "token", "credential"];

/// Flags string literals assigned to credential-looking variables, and
/// AWS access key ids appearing anywhere in string literals.
pub struct HardcodedSecretRule {
    id: RuleId,
}

impl HardcodedSecretRule {
    pub fn new() -> Self {
        Self { id: RuleId::new("owasp:hardcoded-secret").expect("valid rule id") }
    }
}

impl Default for HardcodedSecretRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for HardcodedSecretRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, _language: &LanguageIdentifier) -> bool {
        true
    }

    fn default_severity(&self) -> Severity {
        Severity::Blocker
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        let mut findings = Vec::new();

        for node in ast
            .descendants()
            .filter(|n| matches!(n.kind(), NodeKind::VariableDecl | NodeKind::Assignment))
        {
            let Some(target) = node.first_child() else { continue };
            if *target.kind() != NodeKind::Identifier {
                continue;
            }
            let name = target.text().to_ascii_lowercase();
            if !SUSPICIOUS_NAMES.iter().any(|s| name.contains(s)) {
                continue;
            }
            for value in &node.children()[1..] {
                if let Some(literal) = value
                    .descendants()
                    .find(|n| *n.kind() == NodeKind::StringLiteral && n.text().len() > 2)
                {
                    findings.push(Finding::new(
                        format!("credential-looking variable `{}` holds a hardcoded string literal", target.text()),
                        literal.span(),
                    ));
                }
            }
        }

        for literal in ast.descendants().filter(|n| *n.kind() == NodeKind::StringLiteral) {
            if literal.text().contains("AKIA") && literal.text().len() >= 20 {
                findings.push(Finding::new(
                    "string literal looks like an AWS access key id",
                    literal.span(),
                ));
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use yunq_ast::SourceFile;
    use yunq_rules_engine::AstParser;

    use super::*;

    fn check_ts(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.ts", code, LanguageIdentifier::typescript()).unwrap();
        let ast = yunq_parser_typescript::TypeScriptParser::new().parse(&file).unwrap();
        HardcodedSecretRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_password_literal_and_aws_key() {
        let findings =
            check_ts("const dbPassword = \"hunter2\";\nconst key = \"AKIAIOSFODNN7EXAMPLE\";\n");
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn ignores_clean_variables() {
        assert!(check_ts("const username = \"alice\";\n").is_empty());
    }
}
