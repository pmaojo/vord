//! Rule: flags redirect calls whose target is built from user input
//! (an identifier or an expression touching `req.`/`request.`/`params.`/
//! `query.`) rather than a hardcoded, trusted path — the classic open
//! redirect, usable for phishing since the URL bar shows the trusted host.

use regex::Regex;
use std::sync::LazyLock;
use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile, Span};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

/// Redirect call/header markers across common languages/frameworks, with
/// the argument/target captured in group 1.
static REDIRECT_CALL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)(?:res\.redirect|response\.redirect|HttpResponseRedirect|redirect_to|redirect)\s*\(\s*([^)]*?)\s*\)"#,
    )
    .expect("valid regex")
});

/// `header("Location: ...")`-style redirects, matched at the line level
/// since the target is often built via concatenation outside the string
/// literal (`header("Location: " . $_GET['url'])`), unlike the call-style
/// redirects above where the whole argument sits inside the parens.
static LOCATION_HEADER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)header\s*\(\s*["']Location:"#).expect("valid regex"));

/// Request-input markers checked against the *whole line* for the
/// line-level `LOCATION_HEADER` case (PHP superglobals plus the same
/// request-object prefixes used by [`is_user_influenced`]).
static REQUEST_INPUT_MARKER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(req\.|request\.|params\.|query\.|\$_get|\$_post|\$_request)")
        .expect("valid regex")
});

/// True when `target` reads as user-influenced (an identifier or an
/// expression referencing request input) rather than a hardcoded literal
/// path.
fn is_user_influenced(target: &str) -> bool {
    let trimmed = target.trim();
    if trimmed.is_empty() {
        return false;
    }
    // A plain string literal (optionally with simple concatenation of other
    // literals) is a hardcoded path, not user input.
    let looks_like_pure_literal = (trimmed.starts_with('"') || trimmed.starts_with('\''))
        && (trimmed.ends_with('"') || trimmed.ends_with('\''));
    if looks_like_pure_literal {
        return false;
    }
    let lower = trimmed.to_lowercase();
    lower.contains("req.")
        || lower.contains("request.")
        || lower.contains("params.")
        || lower.contains("query.")
        || lower.contains("get(")
        // Bare identifier / expression with no quotes at all: e.g. `next`,
        // `returnUrl`, `redirectUrl` — not a hardcoded literal.
        || (!trimmed.contains('"') && !trimmed.contains('\''))
}

pub struct OpenRedirectRule {
    id: RuleId,
}

impl OpenRedirectRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("owasp:open-redirect").expect("valid rule id"),
        }
    }
}

impl Default for OpenRedirectRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for OpenRedirectRule {
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
            description: "A redirect target is built from user-controllable input (a request parameter or bare variable) rather than a hardcoded, trusted path. An attacker can craft a link that redirects to an attacker-controlled site while the initial URL still shows the trusted host — the classic open-redirect phishing vector.".into(),
            tags: vec!["security".into(), "owasp-a01".into(), "redirect".into()],
            cwe: Some(601),
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
            let trimmed_line = line.trim_start();
            if trimmed_line.starts_with("//")
                || trimmed_line.starts_with('#')
                || trimmed_line.starts_with('*')
            {
                continue;
            }

            let mut flagged = false;
            if let Some(caps) = REDIRECT_CALL.captures(line)
                && is_user_influenced(&caps[1])
            {
                flagged = true;
            }
            if !flagged && LOCATION_HEADER.is_match(line) && REQUEST_INPUT_MARKER.is_match(line) {
                flagged = true;
            }

            if flagged {
                findings.push(Finding::new(
                    "redirect target is built from user-controllable input rather than a hardcoded path; validate against an allowlist to prevent an open redirect",
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
        OpenRedirectRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_redirect_from_query_param() {
        let code = "res.redirect(req.query.next);\n";
        assert_eq!(
            check("app.ts", LanguageIdentifier::typescript(), code).len(),
            1
        );
    }

    #[test]
    fn flags_redirect_from_bare_variable() {
        let code = "return HttpResponseRedirect(next_url)\n";
        assert_eq!(check("views.py", LanguageIdentifier::python(), code).len(), 1);
    }

    #[test]
    fn flags_location_header_with_request_param() {
        let code = "header(\"Location: \" . $_GET['url']);\n";
        assert_eq!(check("app.php", LanguageIdentifier::php(), code).len(), 1);
    }

    #[test]
    fn ignores_redirect_to_hardcoded_path() {
        let code = "res.redirect('/dashboard');\n";
        assert!(check("app.ts", LanguageIdentifier::typescript(), code).is_empty());
    }

    #[test]
    fn ignores_redirect_to_django_named_route() {
        let code = "return redirect('home')\n";
        assert!(check("views.py", LanguageIdentifier::python(), code).is_empty());
    }

    #[test]
    fn ignores_finding_inside_a_test_file() {
        // A security test that exercises this exact vulnerable shape (e.g.
        // asserting the attack is rejected, or as a red-team fixture) is
        // not itself the vulnerability — production-code paths are where
        // this rule's finding matters.
        let code = "res.redirect(req.query.next);\n";
        assert!(check("app.test.ts", LanguageIdentifier::typescript(), code).is_empty());
    }
}
