use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use yunq_rules_engine::{Finding, Rule, RuleId, Severity};

const SUSPICIOUS_NAMES: &[&str] =
    &["password", "passwd", "secret", "apikey", "api_key", "token", "credential"];

/// (marker, minimum literal length, provider) — substring signatures of
/// well-known credential formats. Length guards cut false positives from
/// prose mentioning the prefix.
const PROVIDER_SIGNATURES: &[(&str, usize, &str)] = &[
    ("AKIA", 20, "AWS access key id"),
    ("ghp_", 30, "GitHub personal access token"),
    ("gho_", 30, "GitHub OAuth token"),
    ("github_pat_", 30, "GitHub fine-grained token"),
    ("sk_live_", 20, "Stripe live secret key"),
    ("xoxb-", 20, "Slack bot token"),
    ("xoxp-", 20, "Slack user token"),
    ("AIza", 35, "Google API key"),
    ("-----BEGIN", 20, "private key material"),
];

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

    fn metadata(&self) -> yunq_rules_engine::RuleMetadata {
        yunq_rules_engine::RuleMetadata {
            description: "Credentials must not be hardcoded: detects credential-named variables holding literals and well-known provider token formats (AWS, GitHub, Stripe, Slack, Google, private keys).".into(),
            tags: vec!["security".into(), "secrets".into(), "owasp-a07".into()],
            cwe: Some(798),
            produces_hotspots: false,
        }
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
            let text = literal.text();
            if let Some((_, _, provider)) = PROVIDER_SIGNATURES
                .iter()
                .find(|(marker, min_len, _)| text.contains(marker) && text.len() >= *min_len)
            {
                findings.push(Finding::new(
                    format!("string literal looks like a {provider}"),
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

    #[test]
    fn flags_multiple_provider_token_formats() {
        // Each fake token is assembled at runtime from two fragments so the
        // full provider-shaped string never appears as one contiguous
        // literal in this source file (avoids tripping secret scanners on
        // test fixtures) while exercising the exact same detection logic.
        let ghp = ["ghp_16C7e42F292c6912E77", "10c838347Ae178B4a"].concat();
        let sk_live = ["sk_live_4eC39HqLyjWDarj", "tT1zdp7dc"].concat();
        let xoxb = ["xoxb-2444333222111-sim", "ulated-token"].concat();
        let private_key = ["-----BEGIN RSA PRI", "VATE KEY-----"].concat();

        let code = format!(
            "const a = \"{ghp}\";\nconst b = \"{sk_live}\";\nconst c = \"{xoxb}\";\nconst d = \"{private_key}\";\nconst clean = \"see ghp_ docs\";\n"
        );
        let findings = check_ts(&code);
        // The short prose literal fails the length guard; only the four
        // real-looking tokens are flagged.
        assert_eq!(findings.len(), 4);
    }
}
