//! Flags log/print statements that also mention a credential-named
//! identifier or string literal — logging a secret is nearly as bad as
//! hardcoding one, since it ends up in log aggregators, crash reporters and
//! shipped log files. Line-based like the other secrets rules so it fires
//! across every language without per-language AST support.

use regex::Regex;
use std::sync::LazyLock;
use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile, Span};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

/// Call-like markers for logging/printing statements across common
/// languages: `console.log(`, `logger.info(`, `log.warn(`, `print(`,
/// `println!(`, `fmt.Println(`, `logging.info(`, etc.
static LOG_CALL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)\b(console\.(log|info|warn|error|debug)|log(ger)?\.(trace|debug|info|warn|error|fatal|fine|severe)|logging\.\w+|println!|eprintln!|print!|fmt\.Print\w*|System\.out\.print\w*|\bprint\s*\(|\blog\s*\()"#,
    )
    .expect("valid regex")
});

/// Identifier fragments that suggest a credential/secret value.
///
/// Anchored with `\b` on both ends so this only matches a credential word
/// as its own token, not as a substring of some larger, unrelated
/// camelCase/PascalCase identifier — `secretsManager` (the common AWS SDK
/// client name), `tokenCount`, `apiKeyLength`, and `credentialsProvider`
/// all contain one of these words as a substring but aren't themselves a
/// logged secret value; unanchored matching flagged every one of them.
static CREDENTIAL_KEYWORD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(password|passwd|pwd|token|secret|api[_-]?key|apikey|credential|private[_-]?key)\b")
        .expect("valid regex")
});

pub struct SecretInLogMessageRule {
    id: RuleId,
}

impl SecretInLogMessageRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("secrets:secret-in-log-message").expect("valid rule id"),
        }
    }
}

impl Default for SecretInLogMessageRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for SecretInLogMessageRule {
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
        IssueType::Vulnerability
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "A log/print statement references a credential-named value (password, token, secret, api key, ...). Logged secrets end up in log aggregators, crash reports and shipped log files — redact or omit them instead.".into(),
            tags: vec!["security".into(), "secrets".into(), "owasp-a09".into()],
            cwe: Some(532),
            produces_hotspots: false,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        if *ast.kind() != NodeKind::SourceUnit {
            return Vec::new();
        }
        if vord_rules_engine::is_test_only_path(file.path()) {
            return Vec::new();
        }
        let test_ranges = vord_rules_engine::rust_test_module_ranges(file.content());

        let mut findings = Vec::new();
        for (idx, line) in file.content().lines().enumerate() {
            let line_no = (idx + 1) as u32;
            if vord_rules_engine::in_ranges(&test_ranges, line_no) {
                continue;
            }
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") || trimmed.starts_with('#') || trimmed.starts_with('*') {
                continue;
            }

            if LOG_CALL.is_match(line) && CREDENTIAL_KEYWORD.is_match(line) {
                findings.push(Finding::new(
                    "log/print statement appears to include a credential-named value; secrets logged this way end up in log aggregators and shipped log files",
                    Span::new(line_no, 1, line_no, line.len().max(1) as u32),
                ));
            }
        }
        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(path: &str, lang: LanguageIdentifier, code: &str) -> Vec<Finding> {
        let file = SourceFile::new(path, code, lang).unwrap();
        let ast = AstNode::new(
            NodeKind::SourceUnit,
            Span::new(1, 1, 1, code.len().max(1) as u32),
            code,
            vec![],
        );
        SecretInLogMessageRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_console_log_of_token() {
        let code = "console.log(\"user token:\", userToken);\n";
        assert_eq!(
            check("app.ts", LanguageIdentifier::typescript(), code).len(),
            1
        );
    }

    #[test]
    fn flags_python_logging_of_password() {
        let code = "logging.info(f\"login attempt with password={password}\")\n";
        assert_eq!(check("auth.py", LanguageIdentifier::python(), code).len(), 1);
    }

    #[test]
    fn flags_println_of_api_key_in_rust() {
        let code = "println!(\"using api_key={}\", api_key);\n";
        assert_eq!(check("main.rs", LanguageIdentifier::rust(), code).len(), 1);
    }

    #[test]
    fn ignores_log_call_without_credential_keyword() {
        let code = "console.log(\"user logged in\", userId);\n";
        assert!(check("app.ts", LanguageIdentifier::typescript(), code).is_empty());
    }

    #[test]
    fn ignores_credential_keyword_without_log_call() {
        let code = "const password = getSecretFromVault();\n";
        assert!(check("app.ts", LanguageIdentifier::typescript(), code).is_empty());
    }

    #[test]
    fn ignores_commented_out_line() {
        let code = "// console.log('token', token);\n";
        assert!(check("app.ts", LanguageIdentifier::typescript(), code).is_empty());
    }

    #[test]
    fn ignores_aws_secrets_manager_client_name() {
        // `secretsManager`/`SecretsManagerClient` is the AWS SDK's own
        // class name, not a logged secret value — "secret" only appears as
        // a substring of a larger identifier here.
        let code = "console.log(\"secretsManager client initialized\");\n";
        assert!(check("app.ts", LanguageIdentifier::typescript(), code).is_empty());
    }

    #[test]
    fn ignores_token_count_metadata_not_a_token_value() {
        // Logging a count/length about tokens is not logging a token.
        let code = "console.log(\"tokenCount:\", tokenCount);\n";
        assert!(check("app.ts", LanguageIdentifier::typescript(), code).is_empty());
    }

    #[test]
    fn still_flags_token_as_its_own_word_in_camelcase_call_site() {
        // A real leak still fires when the credential word is its own
        // token (space/punctuation-delimited), matching the pre-existing
        // `flags_console_log_of_token` shape.
        let code = "console.log(\"api key:\", apiKey);\n";
        assert_eq!(
            check("app.ts", LanguageIdentifier::typescript(), code).len(),
            1
        );
    }
}
