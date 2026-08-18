//! Rule: flags cookie-setting code that doesn't set both the `Secure` and
//! `HttpOnly` flags, letting cookies (including session identifiers) leak
//! over plaintext connections or be read by client-side script (XSS).

use regex::Regex;
use std::sync::LazyLock;
use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile, Span};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

/// Cookie-setting call/header markers across common languages/frameworks.
static COOKIE_SETTER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)(set-cookie|\.cookie\s*\(|res\.cookie\s*\(|response\.cookie\s*\(|document\.cookie\s*=|cookie::new\s*\(|set_cookie\s*\()"#,
    )
    .expect("valid regex")
});

fn has_flag(line: &str, flag: &str) -> bool {
    line.to_lowercase().contains(&flag.to_lowercase())
}

pub struct InsecureCookieFlagsRule {
    id: RuleId,
}

impl InsecureCookieFlagsRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("owasp:insecure-cookie-flags").expect("valid rule id"),
        }
    }
}

impl Default for InsecureCookieFlagsRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for InsecureCookieFlagsRule {
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
            description: "A cookie is set without both the `Secure` and `HttpOnly` flags. Without `Secure` the cookie can be sent over plaintext HTTP; without `HttpOnly` client-side script (e.g. via XSS) can read it, including session identifiers.".into(),
            tags: vec!["security".into(), "owasp-a05".into(), "cookies".into()],
            cwe: Some(1004),
            produces_hotspots: false,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        if *ast.kind() != NodeKind::SourceUnit {
            return Vec::new();
        }
        // A test asserting this exact vulnerable shape is rejected (e.g.
        // a red-team fixture, or an `expect(...).toThrow()` covering the
        // attack) would otherwise be flagged as if the vulnerability were
        // live in production code.
        if vord_rules_engine::is_test_only_path(file.path()) {
            return Vec::new();
        }

        let mut findings = Vec::new();
        for (idx, line) in file.content().lines().enumerate() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") || trimmed.starts_with('#') || trimmed.starts_with('*') {
                continue;
            }
            if !COOKIE_SETTER.is_match(line) {
                continue;
            }
            // `document.cookie = ...` is a browser-side read/write of the whole
            // cookie jar and has no server-settable Secure/HttpOnly flags
            // (HttpOnly cannot be set from JS at all) — flag it unconditionally
            // as the classic client-side-readable-cookie anti-pattern.
            let is_document_cookie = line.to_lowercase().contains("document.cookie");

            let has_secure = has_flag(line, "secure");
            let has_httponly = has_flag(line, "httponly") || has_flag(line, "http_only");

            if is_document_cookie || !has_secure || !has_httponly {
                let line_no = (idx + 1) as u32;
                findings.push(Finding::new(
                    "cookie set without both Secure and HttpOnly flags; without Secure it can travel over plaintext HTTP, without HttpOnly client-side script can read it",
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
        InsecureCookieFlagsRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_express_cookie_without_flags() {
        let code = "res.cookie('session', sessionId);\n";
        assert_eq!(
            check("app.ts", LanguageIdentifier::typescript(), code).len(),
            1
        );
    }

    #[test]
    fn flags_document_cookie_assignment() {
        let code = "document.cookie = \"session=\" + sessionId;\n";
        assert_eq!(
            check("app.ts", LanguageIdentifier::typescript(), code).len(),
            1
        );
    }

    #[test]
    fn flags_set_cookie_header_missing_httponly() {
        let code = "response.setHeader('Set-Cookie', 'session=abc; Secure');\n";
        assert_eq!(
            check("app.ts", LanguageIdentifier::typescript(), code).len(),
            1
        );
    }

    #[test]
    fn ignores_cookie_with_both_flags() {
        let code = "res.cookie('session', sessionId, { secure: true, httpOnly: true });\n";
        assert!(check("app.ts", LanguageIdentifier::typescript(), code).is_empty());
    }

    #[test]
    fn ignores_python_cookie_with_both_flags() {
        let code = "response.set_cookie('session', session_id, secure=True, httponly=True)\n";
        assert!(check("app.py", LanguageIdentifier::python(), code).is_empty());
    }

    #[test]
    fn ignores_finding_inside_a_test_file() {
        // A security test that exercises this exact vulnerable shape (e.g.
        // asserting the attack is rejected, or as a red-team fixture) is
        // not itself the vulnerability — production-code paths are where
        // this rule's finding matters.
        let code = "res.cookie('session', sessionId);\n";
        assert!(check("app.test.ts", LanguageIdentifier::typescript(), code).is_empty());
    }
}
