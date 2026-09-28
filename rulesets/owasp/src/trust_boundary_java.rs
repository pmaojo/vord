//! Rule: flags untrusted user input crossing a trust boundary into the
//! session or request attributes without validation — the OWASP Benchmark
//! "trustbound" family (CWE-501).
//!
//! Strategy: intra-file value flow ([`ServletTaint`]) —
//! `session.setAttribute`/`putValue`/`addValue` (including through
//! `request.getSession()`) is a finding when its value is user-controlled.
//!
//! The bar here is *validation*, not safe rendering: a value that was only
//! HTML-escaped is still attacker data, and handing it to the session passes
//! it to code that will later treat it as trusted. So the rule asks
//! [`ServletTaint::is_unvalidated_request_data`] rather than plain taint —
//! an output encoder silences the XSS rules without silencing this one.

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

use crate::java_servlet_taint::{split_call, ServletTaint};

const STORE_METHODS: &[&str] = &["setAttribute", "putValue", "addValue", "put"];

pub struct TrustBoundaryJavaRule {
    id: RuleId,
}

impl TrustBoundaryJavaRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("owasp:trust-boundary-java").expect("valid rule id"),
        }
    }
}

impl Default for TrustBoundaryJavaRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for TrustBoundaryJavaRule {
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
        10
    }

    fn metadata(&self) -> vord_rules_engine::RuleMetadata {
        vord_rules_engine::RuleMetadata {
            description: "Untrusted user input is stored in the session or request attributes without validation, crossing a trust boundary. Validate/normalize the value before storing it.".into(),
            tags: vec!["security".into(), "owasp-a04".into(), "java".into()],
            cwe: Some(501),
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        let state = ServletTaint::analyze(ast);
        ast.descendants()
            .filter(|n| *n.kind() == NodeKind::Call)
            .filter_map(|node| {
                let call = split_call(node)?;
                if !STORE_METHODS.contains(&call.method.as_str()) {
                    return None;
                }
                let receiver_text = call.receiver_text.as_str();
                if !(receiver_text.contains("ession") || receiver_text.contains("request")) {
                    return None;
                }
                let tainted_arg =
                    call.args.iter().any(|arg| state.is_unvalidated_request_data(arg));
                tainted_arg.then(|| {
                    Finding::new(
                        "user input from a servlet request is stored in the session/request without validation — this crosses a trust boundary",
                        node.span(),
                    )
                })
            })
            .collect()
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
        TrustBoundaryJavaRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_session_put_value_with_tainted_value() {
        let findings = check(
            "class T { void f(HttpServletRequest request) {\n String param = request.getParameter(\"u\");\n request.getSession().putValue(\"userid\", param);\n} }",
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_session_set_attribute_with_tainted_value() {
        let findings = check(
            "class T { void f(HttpServletRequest request, HttpSession session) {\n String bar = request.getParameter(\"u\");\n session.setAttribute(\"userid\", bar);\n} }",
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_encoded_but_unvalidated_value() {
        // HTML-escaping makes the value safe to render, not safe to trust:
        // storing it in the session still hands attacker data to code that
        // will later read it back as if it were the user's own.
        let findings = check(
            "class T { void f(HttpServletRequest request) {\n String param = request.getParameter(\"u\");\n String bar = org.apache.commons.lang.StringEscapeUtils.escapeHtml(param);\n request.getSession().putValue(\"userid\", bar);\n} }",
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_encoded_value_returned_from_inlined_helper() {
        // The OWASP inner-class family (BenchmarkTest01546 et al.): the
        // helper runs the encoder and returns, and the caller's `bar`
        // must keep the encoded-but-unvalidated status across the call.
        let findings = check(
            "class T { void f(HttpServletRequest request, HttpSession session) {\n String param = request.getParameter(\"vector\");\n String bar = doSomething(param);\n session.setAttribute(\"userid\", bar);\n}\n private static String doSomething(String p) {\n return org.apache.commons.lang.StringEscapeUtils.escapeHtml(p);\n}\n}",
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_inline_encoder_call_with_tainted_input() {
        // The encoder applied directly at the sink — never assigned to an
        // intermediate variable — is the same trust-boundary story.
        let findings = check(
            "class T { void f(HttpServletRequest request, HttpSession session) {\n String param = request.getParameter(\"u\");\n session.setAttribute(\"userid\", org.apache.commons.lang.StringEscapeUtils.escapeHtml(param));\n} }",
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn does_not_flag_encoding_of_a_constant_source() {
        // BenchmarkTest00923: `getTheValue()` returns a constant, so
        // escaping it produces a clean value, not unvalidated request
        // data — encoding only records status for real request input.
        let findings = check(
            "class T { void f(HttpServletRequest request, HttpSession session) {\n String param = new org.owasp.benchmark.helpers.SeparateClassRequest(request).getTheValue(\"vector\");\n String bar = org.apache.commons.lang.StringEscapeUtils.escapeHtml(param);\n session.setAttribute(\"userid\", bar);\n} }",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn allows_constant_value() {
        let findings = check(
            "class T { void f(HttpServletRequest request, HttpSession session) {\n session.setAttribute(\"userid\", \"anonymous\");\n} }",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn allows_unrelated_map_put() {
        let findings = check(
            "class T { void f(HttpServletRequest request, java.util.Map<String,String> m) {\n String bar = request.getParameter(\"u\");\n m.put(\"userid\", bar);\n} }",
        );
        assert!(findings.is_empty());
    }
}
