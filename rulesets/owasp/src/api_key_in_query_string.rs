//! Rule: flags API keys/tokens passed as URL query-string parameters
//! (`?api_key=`, `&apikey=`, `&access_token=`, `?token=`). Query strings
//! end up in server access logs, browser history, proxy logs and the
//! `Referer` header sent to third-party resources — an HTTP header
//! (`Authorization: Bearer ...`) is the safer place for a credential.

use regex::Regex;
use std::sync::LazyLock;
use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile, Span};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

/// API-key/token parameter names used as a literal URL query parameter,
/// e.g. `?api_key=`, `&apikey=`, `&access_token=`, `?token=`.
static API_KEY_IN_QUERY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)[?&](api[_-]?key|apikey|access_token|token)=").expect("valid regex")
});

pub struct ApiKeyInQueryStringRule {
    id: RuleId,
}

impl ApiKeyInQueryStringRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("owasp:api-key-in-query-string").expect("valid rule id"),
        }
    }
}

impl Default for ApiKeyInQueryStringRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for ApiKeyInQueryStringRule {
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
            description: "An API key/token is passed as a URL query-string parameter. Query strings end up in server access logs, browser history, proxy logs and the Referer header sent to third-party resources — send the credential in a header instead.".into(),
            tags: vec!["security".into(), "owasp-a07".into(), "secrets".into()],
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
            if API_KEY_IN_QUERY.is_match(line) {
                findings.push(Finding::new(
                    "API key/token passed as a URL query-string parameter; it will leak via access logs, browser history and the Referer header — send it in a header instead",
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
        ApiKeyInQueryStringRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_api_key_query_param_in_ts_fetch() {
        let code = "fetch(`https://api.example.com/data?api_key=${key}`);\n";
        assert_eq!(
            check("app.ts", LanguageIdentifier::typescript(), code).len(),
            1
        );
    }

    #[test]
    fn flags_access_token_query_param_in_python() {
        let code = "url = f\"https://api.example.com/v1?access_token={token}\"\n";
        assert_eq!(check("app.py", LanguageIdentifier::python(), code).len(), 1);
    }

    #[test]
    fn flags_apikey_query_param_in_go() {
        let code = "url := base + \"&apikey=\" + key\n";
        assert_eq!(check("main.go", LanguageIdentifier::go(), code).len(), 1);
    }

    #[test]
    fn ignores_header_based_auth() {
        let code = "req.headers['Authorization'] = `Bearer ${token}`;\n";
        assert!(check("app.ts", LanguageIdentifier::typescript(), code).is_empty());
    }

    #[test]
    fn ignores_unrelated_query_params() {
        let code = "fetch(`https://api.example.com/data?page=2&limit=10`);\n";
        assert!(check("app.ts", LanguageIdentifier::typescript(), code).is_empty());
    }

    #[test]
    fn ignores_finding_inside_a_test_file() {
        // A security test that exercises this exact vulnerable shape (e.g.
        // asserting the attack is rejected, or as a red-team fixture) is
        // not itself the vulnerability — production-code paths are where
        // this rule's finding matters.
        let code = "fetch(`https://api.example.com/data?api_key=${key}`);\n";
        assert!(check("app.test.ts", LanguageIdentifier::typescript(), code).is_empty());
    }
}
