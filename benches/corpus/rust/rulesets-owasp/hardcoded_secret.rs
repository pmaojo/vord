use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

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

/// Whether `value` — a credential-looking variable's initializer, or a
/// sub-expression reached while unwinding one — is itself a hardcoded string
/// literal, as opposed to a literal merely buried somewhere inside it. Only
/// follows a `Call`'s callee (first child) and a `MemberAccess`'s receiver
/// (first child): that's the chain a wrapped literal keeps exposing through
/// (`"secret".to_string()`, `"secret".into()`), whereas a literal passed as
/// an *argument* — `env::var("API_KEY")`, `header.strip_prefix("Bearer ")`,
/// `localStorage.getItem("session_token")` — is a lookup key or env var
/// name, not the variable's actual value, and is deliberately never visited.
fn own_literal(value: &AstNode) -> Option<&AstNode> {
    if *value.kind() == NodeKind::StringLiteral && value.text().len() > 2 {
        return Some(value);
    }
    match value.kind() {
        NodeKind::Call | NodeKind::MemberAccess => value.first_child().and_then(own_literal),
        _ => None,
    }
}

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

    fn issue_type(&self) -> IssueType {
        IssueType::Vulnerability
    }

    fn metadata(&self) -> vord_rules_engine::RuleMetadata {
        vord_rules_engine::RuleMetadata {
            description: "Credentials must not be hardcoded: detects credential-named variables holding literals and well-known provider token formats (AWS, GitHub, Stripe, Slack, Google, private keys).".into(),
            tags: vec!["security".into(), "secrets".into(), "owasp-a07".into()],
            cwe: Some(798),
            produces_hotspots: false,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        if vord_rules_engine::is_test_only_path(file.path()) {
            return Vec::new();
        }
        let test_ranges = vord_rules_engine::rust_test_module_ranges(file.content());
        let in_test = |line: u32| vord_rules_engine::in_ranges(&test_ranges, line);

        let mut findings = credential_assignment_findings(ast, &in_test);
        findings.extend(provider_signature_findings(ast, &in_test));
        findings
    }
}

/// Flags string literals assigned (directly, or via a receiver chain like
/// `.to_string()`/`.into()`) to a credential-looking variable name.
fn credential_assignment_findings(ast: &AstNode, in_test: &impl Fn(u32) -> bool) -> Vec<Finding> {
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
            if let Some(literal) = own_literal(value) {
                if in_test(literal.span().start_line) {
                    continue;
                }
                findings.push(Finding::new(
                    format!("credential-looking variable `{}` holds a hardcoded string literal", target.text()),
                    literal.span(),
                ));
            }
        }
    }
    findings
}

/// Flags string literals anywhere in the file matching a well-known
/// credential provider signature (AWS, GitHub, Stripe, Slack, Google,
/// private keys).
fn provider_signature_findings(ast: &AstNode, in_test: &impl Fn(u32) -> bool) -> Vec<Finding> {
    let mut findings = Vec::new();
    for literal in ast.descendants().filter(|n| *n.kind() == NodeKind::StringLiteral) {
        if in_test(literal.span().start_line) {
            continue;
        }
        let text = literal.text();
        if let Some((_, _, provider)) = PROVIDER_SIGNATURES
            .iter()
            .find(|(marker, min_len, _)| text.contains(marker) && text.len() >= *min_len)
        {
            findings.push(Finding::new(format!("string literal looks like a {provider}"), literal.span()));
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use vord_ast::SourceFile;
    use vord_rules_engine::AstParser;

    use super::*;

    fn check_ts(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.ts", code, LanguageIdentifier::typescript()).unwrap();
        let ast = vord_parser_typescript::TypeScriptParser::new().parse(&file).unwrap();
        HardcodedSecretRule::new().check(&file, &ast)
    }

    fn check_rust(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.rs", code, LanguageIdentifier::rust()).unwrap();
        let ast = vord_parser_rust::RustParser::new().parse(&file).unwrap();
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

    #[test]
    fn does_not_flag_a_lookup_key_passed_to_a_credential_named_variable() {
        // The string literal here is `localStorage`'s lookup key, not the
        // token's actual value — vord's own dogfood scan flagged exactly
        // this shape in frontend/src/lib/api.ts before this fix.
        assert!(check_ts("const token = localStorage.getItem('vord_session_token');\n").is_empty());
    }

    #[test]
    fn does_not_flag_an_env_var_name_read_into_a_credential_named_variable() {
        // `"VORD_LLM_API_KEY"` is the environment variable's *name*, not a
        // hardcoded secret value (infra/llm/src/lib.rs's real shape).
        assert!(check_rust("fn f() {\n    let api_key = std::env::var(\"VORD_LLM_API_KEY\").unwrap_or_default();\n}\n").is_empty());
    }

    #[test]
    fn does_not_flag_a_header_prefix_argument() {
        // `"Bearer "` is the prefix being stripped off an incoming header
        // value, not a hardcoded token (bin/server/src/auth.rs's real shape).
        let code = "fn f(value: &str) {\n    let token = value.strip_prefix(\"Bearer \").unwrap_or(value);\n}\n";
        assert!(check_rust(code).is_empty());
    }

    #[test]
    fn does_not_flag_a_format_string_naming_an_env_var() {
        // `credentials()`'s real shape: the format string names the env var
        // to read, it isn't the secret itself.
        let code = "fn f(prefix: &str) {\n    let client_secret = std::env::var(format!(\"{prefix}_CLIENT_SECRET\")).ok();\n}\n";
        assert!(check_rust(code).is_empty());
    }

    #[test]
    fn still_flags_a_literal_wrapped_in_to_string_or_into() {
        // A literal reached only through a receiver chain (never through a
        // call's *argument* position) is still the variable's own value —
        // must stay flagged.
        assert_eq!(check_rust("fn f() {\n    let password = \"hunter2\".to_string();\n}\n").len(), 1);
        assert_eq!(check_rust("fn f() {\n    let token: String = \"hunter2\".into();\n}\n").len(), 1);
    }
}
