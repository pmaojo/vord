//! Rule: flags session-identifier-looking query-string parameters embedded
//! literally in a URL (`;jsessionid=`, `?PHPSESSID=`, `?session_id=`,
//! `&sid=`, ...) rather than carried in a cookie. URL-embedded session ids
//! leak via browser history, proxy/server logs, the `Referer` header and
//! shoulder-surfing of a shared/pasted link.

use regex::Regex;
use std::sync::LazyLock;
use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile, Span};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

/// Session-identifier parameter names used as a literal URL query/path
/// parameter, e.g. `;jsessionid=`, `?PHPSESSID=`, `&session_id=`, `?sid=`.
static SESSION_ID_IN_URL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)[?&;](jsessionid|phpsessid|sessionid|session_id|sid)=").expect("valid regex")
});

pub struct SessionIdInUrlRule {
    id: RuleId,
}

impl SessionIdInUrlRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("owasp:session-id-in-url").expect("valid rule id"),
        }
    }
}

impl Default for SessionIdInUrlRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for SessionIdInUrlRule {
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
            description: "A session identifier is carried as a literal URL query/path parameter instead of a cookie. URL-embedded session ids leak via browser history, server/proxy access logs, the Referer header and shared links.".into(),
            tags: vec!["security".into(), "owasp-a07".into(), "session".into()],
            cwe: Some(598),
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
            if SESSION_ID_IN_URL.is_match(line) {
                findings.push(Finding::new(
                    "session identifier embedded as a literal URL query parameter; carry it in a cookie instead to avoid leaking it via logs, history and the Referer header",
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
        SessionIdInUrlRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_jsessionid_in_url() {
        let code = "String url = base + \";jsessionid=\" + session.getId();\n";
        assert_eq!(check("App.java", LanguageIdentifier::java(), code).len(), 1);
    }

    #[test]
    fn flags_phpsessid_query_param() {
        let code = "$url = $base . \"?PHPSESSID=\" . session_id();\n";
        assert_eq!(check("app.php", LanguageIdentifier::php(), code).len(), 1);
    }

    #[test]
    fn flags_session_id_query_param_in_ts() {
        let code = "const url = `${base}?session_id=${sessionId}`;\n";
        assert_eq!(
            check("app.ts", LanguageIdentifier::typescript(), code).len(),
            1
        );
    }

    #[test]
    fn ignores_session_cookie_usage() {
        let code = "res.cookie('session_id', sessionId, { secure: true, httpOnly: true });\n";
        assert!(check("app.ts", LanguageIdentifier::typescript(), code).is_empty());
    }

    #[test]
    fn ignores_unrelated_query_params() {
        let code = "const url = `${base}?page=2&sort=asc`;\n";
        assert!(check("app.ts", LanguageIdentifier::typescript(), code).is_empty());
    }

    #[test]
    fn ignores_finding_inside_a_test_file() {
        // A security test that exercises this exact vulnerable shape (e.g.
        // asserting the attack is rejected, or as a red-team fixture) is
        // not itself the vulnerability — production-code paths are where
        // this rule's finding matters.
        let code = "String url = base + \";jsessionid=\" + session.getId();\n";
        assert!(check("app.test.ts", LanguageIdentifier::typescript(), code).is_empty());
    }
}
