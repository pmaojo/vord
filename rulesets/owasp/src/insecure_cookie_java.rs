//! Rule: flags servlet cookies sent without the `Secure` flag — the OWASP
//! Benchmark "securecookie" family (CWE-614).
//!
//! Strategy: a `javax.servlet.http.Cookie` tracked through its variable is
//! a finding when it is added to the response without a `setSecure(true)`
//! call, or when `setSecure(false)` is called on it explicitly.

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

use crate::java_servlet_taint::{split_call, ServletTaint};

pub struct InsecureCookieJavaRule {
    id: RuleId,
}

impl InsecureCookieJavaRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("owasp:insecure-cookie-java").expect("valid rule id"),
        }
    }
}

impl Default for InsecureCookieJavaRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for InsecureCookieJavaRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, language: &LanguageIdentifier) -> bool {
        *language == LanguageIdentifier::java()
    }

    fn default_severity(&self) -> Severity {
        Severity::Major
    }

    fn issue_type(&self) -> IssueType {
        IssueType::Vulnerability
    }

    fn remediation_effort_minutes(&self) -> u32 {
        5
    }

    fn metadata(&self) -> vord_rules_engine::RuleMetadata {
        vord_rules_engine::RuleMetadata {
            description: "A servlet cookie is added to the response without the Secure flag, so it may be sent over unencrypted HTTP. Call cookie.setSecure(true).".into(),
            tags: vec!["security".into(), "owasp-a02".into(), "cookie".into(), "java".into()],
            cwe: Some(614),
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        let state = ServletTaint::analyze(ast);
        let mut findings = Vec::new();
        for node in ast.descendants().filter(|n| *n.kind() == NodeKind::Call) {
            let Some(call) = split_call(node) else {
                continue;
            };
            match call.method.as_str() {
                "addCookie" => {
                    let insecure = call.args.iter().any(|arg| {
                        (state.is_cookie(arg) && !state.cookie_is_secure(arg))
                            || (split_call(arg).is_some_and(|c| {
                                c.is_new && c.type_text.ends_with("Cookie")
                            }))
                    });
                    if insecure {
                        findings.push(Finding::new(
                            "this cookie is added to the response without cookie.setSecure(true) — it may be sent over plain HTTP",
                            node.span(),
                        ));
                    }
                }
                "setSecure" => {
                    let explicitly_insecure = call
                        .args
                        .first()
                        .map(|a| a.text().trim() == "false")
                        .unwrap_or(false);
                    if explicitly_insecure {
                        findings.push(Finding::new(
                            "cookie.setSecure(false) disables the Secure flag — this cookie may be sent over plain HTTP",
                            node.span(),
                        ));
                    }
                }
                _ => {}
            }
        }
        findings
    }
}

#[cfg(test)]
mod tests {
    use vord_ast::SourceFile;
    use vord_rules_engine::AstParser;

    use super::*;

    fn check(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("Test.java", code, LanguageIdentifier::java()).unwrap();
        let ast = vord_parser_java::JavaParser::new().parse(&file).unwrap();
        InsecureCookieJavaRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_cookie_without_secure_flag() {
        let findings = check(
            "class T { void f(HttpServletRequest request, HttpServletResponse response) {\n javax.servlet.http.Cookie cookie = new javax.servlet.http.Cookie(\"SomeCookie\", \"v\");\n cookie.setPath(\"/benchmark/\");\n response.addCookie(cookie);\n} }",
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_explicit_set_secure_false() {
        let findings = check(
            "class T { void f(HttpServletResponse response) {\n javax.servlet.http.Cookie cookie = new javax.servlet.http.Cookie(\"SomeCookie\", \"v\");\n cookie.setSecure(false);\n response.addCookie(cookie);\n} }",
        );
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn allows_secure_cookie() {
        let findings = check(
            "class T { void f(HttpServletResponse response) {\n javax.servlet.http.Cookie cookie = new javax.servlet.http.Cookie(\"SomeCookie\", \"v\");\n cookie.setSecure(true);\n response.addCookie(cookie);\n} }",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn allows_secure_cookie_set_before_add() {
        let findings = check(
            "class T { void f(HttpServletResponse response) {\n javax.servlet.http.Cookie c = new javax.servlet.http.Cookie(\"n\", \"v\");\n c.setSecure(true);\n c.setPath(\"/\");\n response.addCookie(c);\n} }",
        );
        assert!(findings.is_empty());
    }
}
