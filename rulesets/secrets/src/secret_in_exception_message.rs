//! Flags exception/error construction and re-raising that mentions a
//! credential-named identifier — the classic "include the token in the
//! error message for debuggability" mistake, which then surfaces the
//! secret in stack traces, crash reporters and error-tracking dashboards.

use regex::Regex;
use std::sync::LazyLock;
use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile, Span};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

/// Exception/error construction and re-raising markers across common
/// languages: `throw`, `raise`, `Exception(`, `Error(`, `panic!`, `.unwrap()`.
static EXCEPTION_MARKER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\b(throw\b|raise\b|panic!|\.unwrap\(|\.expect\(|new\s+\w*(Exception|Error)\s*\(|\w*(Exception|Error)\s*\()",
    )
    .expect("valid regex")
});

/// Identifier fragments that suggest a credential/secret value.
static CREDENTIAL_KEYWORD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(password|passwd|pwd|token|secret|api[_-]?key|apikey|credential|private[_-]?key)")
        .expect("valid regex")
});

pub struct SecretInExceptionMessageRule {
    id: RuleId,
}

impl SecretInExceptionMessageRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("secrets:secret-in-exception-message").expect("valid rule id"),
        }
    }
}

impl Default for SecretInExceptionMessageRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for SecretInExceptionMessageRule {
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
            description: "An exception/error is constructed or re-raised with a credential-named value in its message. Secrets embedded in error messages leak through stack traces, crash reporters and error-tracking dashboards.".into(),
            tags: vec!["security".into(), "secrets".into(), "owasp-a09".into()],
            cwe: Some(209),
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

        let mut findings = Vec::new();
        for (idx, line) in file.content().lines().enumerate() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") || trimmed.starts_with('#') || trimmed.starts_with('*') {
                continue;
            }

            if EXCEPTION_MARKER.is_match(line) && CREDENTIAL_KEYWORD.is_match(line) {
                let line_no = (idx + 1) as u32;
                findings.push(Finding::new(
                    "exception/error appears to embed a credential-named value in its message; secrets in error messages leak through stack traces and crash reporters",
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
        SecretInExceptionMessageRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_thrown_error_with_token() {
        let code = "throw new Error(`invalid token: ${apiToken}`);\n";
        assert_eq!(
            check("app.ts", LanguageIdentifier::typescript(), code).len(),
            1
        );
    }

    #[test]
    fn flags_python_raise_with_password() {
        let code = "raise ValueError(f\"bad password: {password}\")\n";
        assert_eq!(check("auth.py", LanguageIdentifier::python(), code).len(), 1);
    }

    #[test]
    fn flags_rust_panic_with_secret() {
        let code = "panic!(\"failed to parse secret: {}\", secret);\n";
        assert_eq!(check("main.rs", LanguageIdentifier::rust(), code).len(), 1);
    }

    #[test]
    fn ignores_exception_without_credential_keyword() {
        let code = "throw new Error(\"invalid request\");\n";
        assert!(check("app.ts", LanguageIdentifier::typescript(), code).is_empty());
    }

    #[test]
    fn ignores_credential_keyword_without_exception_marker() {
        let code = "const token = getToken();\n";
        assert!(check("app.ts", LanguageIdentifier::typescript(), code).is_empty());
    }
}
