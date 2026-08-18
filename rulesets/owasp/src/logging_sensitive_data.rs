//! Rule: flags logging calls whose arguments reference PII-ish identifiers
//! (password, ssn, credit_card, cvv, social_security) directly — distinct
//! from `secrets:secret-in-log-message`, which targets credential/token
//! keywords. This one targets personal data whose exposure is a privacy
//! incident even when it isn't an authentication secret.

use regex::Regex;
use std::sync::LazyLock;
use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile, Span};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

/// Call-like markers for logging/printing statements across common
/// languages (shared vocabulary with `secrets:secret-in-log-message`).
static LOG_CALL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)\b(console\.(log|info|warn|error|debug)|log(ger)?\.(trace|debug|info|warn|error|fatal|fine|severe)|logging\.\w+|println!|eprintln!|print!|fmt\.Print\w*|System\.out\.print\w*|\bprint\s*\(|\blog\s*\()"#,
    )
    .expect("valid regex")
});

/// PII-ish identifier fragments distinct from the credential/token
/// vocabulary used by the secrets ruleset.
static PII_KEYWORD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(password|passwd|pwd|ssn|social[_-]?security|credit[_-]?card|creditcard|cvv)\b")
        .expect("valid regex")
});

pub struct LoggingSensitiveDataRule {
    id: RuleId,
}

impl LoggingSensitiveDataRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("owasp:logging-sensitive-data").expect("valid rule id"),
        }
    }
}

impl Default for LoggingSensitiveDataRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for LoggingSensitiveDataRule {
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
            description: "A log/print statement references PII (password, SSN, credit card, CVV, ...) directly. Logging personal data is a privacy incident even when the value isn't an authentication credential — redact or omit it instead.".into(),
            tags: vec!["security".into(), "privacy".into(), "owasp-a09".into()],
            cwe: Some(532),
            produces_hotspots: false,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        if *ast.kind() != NodeKind::SourceUnit {
            return Vec::new();
        }

        let mut findings = Vec::new();
        for (idx, line) in file.content().lines().enumerate() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") || trimmed.starts_with('#') || trimmed.starts_with('*') {
                continue;
            }

            if LOG_CALL.is_match(line) && PII_KEYWORD.is_match(line) {
                let line_no = (idx + 1) as u32;
                findings.push(Finding::new(
                    "log/print statement appears to reference PII (password, SSN, credit card, CVV, ...) directly; redact or omit it instead",
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
        LoggingSensitiveDataRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_log_of_password() {
        let code = "log(user.password);\n";
        assert_eq!(
            check("app.ts", LanguageIdentifier::typescript(), code).len(),
            1
        );
    }

    #[test]
    fn flags_python_logging_of_ssn() {
        let code = "logger.info(f\"processing user {ssn}\")\n";
        assert_eq!(check("app.py", LanguageIdentifier::python(), code).len(), 1);
    }

    #[test]
    fn flags_credit_card_logging() {
        let code = "console.log('charging card', creditCard);\n";
        assert_eq!(
            check("app.ts", LanguageIdentifier::typescript(), code).len(),
            1
        );
    }

    #[test]
    fn ignores_log_call_without_pii_keyword() {
        let code = "console.log('user logged in', userId);\n";
        assert!(check("app.ts", LanguageIdentifier::typescript(), code).is_empty());
    }

    #[test]
    fn ignores_pii_keyword_without_log_call() {
        let code = "const password = getPassword();\n";
        assert!(check("app.ts", LanguageIdentifier::typescript(), code).is_empty());
    }
}
