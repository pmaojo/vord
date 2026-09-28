//! Rule: flags servlet response writers receiving untrusted user input
//! without HTML-encoding — the classic Java reflected XSS pattern in the
//! OWASP Benchmark (and real-world servlets).
//!
//! Strategy: intra-file value flow ([`ServletTaint`]) — a finding is
//! reported only when user-controlled data actually reaches a response
//! writer sink. Sinks cover `response.getWriter()`/`getOutputStream()`
//! chains (`write`/`print`/`println`/`printf`/`format`/`append`) and
//! variables previously assigned a response writer. HTML/JS/URL encoders
//! (`ESAPI.encoder().encodeForHTML(…)`, `Encode.forHtml(…)`, …) cleanse
//! the flow.

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

use crate::java_servlet_taint::{split_call, ServletTaint};

/// Writer methods that write content into the HTTP response body.
const WRITER_METHODS: &[&str] = &["write", "print", "println", "printf", "format", "append"];

pub struct XssJavaRule {
    id: RuleId,
}

impl XssJavaRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("owasp:xss-java").expect("valid rule id"),
        }
    }
}

impl Default for XssJavaRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for XssJavaRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, language: &LanguageIdentifier) -> bool {
        *language == LanguageIdentifier::java()
    }

    fn default_severity(&self) -> Severity {
        Severity::Blocker
    }

    fn issue_type(&self) -> IssueType {
        IssueType::Vulnerability
    }

    fn remediation_effort_minutes(&self) -> u32 {
        10
    }

    fn metadata(&self) -> vord_rules_engine::RuleMetadata {
        vord_rules_engine::RuleMetadata {
            description: "Untrusted user input reaches a servlet response writer, which can lead to Cross-Site Scripting (XSS). Ensure all user-controlled values written to the HTTP response are properly HTML-encoded (e.g. using ESAPI.encoder().encodeForHTML(...)).".into(),
            tags: vec!["security".into(), "owasp-a03".into(), "xss".into(), "java".into()],
            cwe: Some(79),
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        let state = ServletTaint::analyze(ast);
        ast.descendants()
            .filter(|n| *n.kind() == NodeKind::Call)
            .filter_map(|node| {
                let call = split_call(node)?;
                if !WRITER_METHODS.contains(&call.method.as_str()) {
                    return None;
                }
                if !state.is_response_writer(call.receiver.unwrap_or(node)) {
                    return None;
                }
                let tainted_arg = call.args.iter().any(|arg| state.is_tainted(arg));
                tainted_arg.then(|| {
                    Finding::new(
                        "user input from a servlet request reaches response.getWriter() without HTML-encoding — this is a reflected XSS vulnerability",
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
        XssJavaRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_direct_parameter_written_to_getwriter() {
        let findings = check(
            "class T { void f(HttpServletRequest request, HttpServletResponse response) {\n String param = request.getParameter(\"name\");\n response.getWriter().write(param);\n} }",
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_printf_sink_with_tainted_argument() {
        // The OWASP `printf(Locale, …)` family: the format sink differs but
        // the taint story is the same.
        let findings = check(
            "class T { void f(HttpServletRequest request, HttpServletResponse response) {\n String bar = request.getParameter(\"vector\");\n Object[] obj = { \"a\", \"b\" };\n response.getWriter().printf(java.util.Locale.US, bar, obj);\n} }",
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_taint_through_list_get_after_remove() {
        let findings = check(
            "class T { void f(HttpServletRequest request, HttpServletResponse response) {\n String param = request.getParameter(\"vector\");\n java.util.List<String> valuesList = new java.util.ArrayList<String>();\n valuesList.add(\"safe\");\n valuesList.add(param);\n valuesList.remove(0);\n String bar = valuesList.get(0);\n response.getWriter().format(\"x %s\", bar);\n} }",
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn allows_list_get_of_safe_element() {
        let findings = check(
            "class T { void f(HttpServletRequest request, HttpServletResponse response) {\n String param = request.getParameter(\"vector\");\n java.util.List<String> valuesList = new java.util.ArrayList<String>();\n valuesList.add(\"safe\");\n valuesList.add(param);\n valuesList.add(\"moresafe\");\n valuesList.remove(0);\n String bar = valuesList.get(1);\n response.getWriter().format(\"x %s\", bar);\n} }",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn allows_encoded_output() {
        let findings = check(
            "class T { void f(HttpServletRequest request, HttpServletResponse response) {\n String param = request.getParameter(\"name\");\n response.getWriter().write(org.owasp.esapi.ESAPI.encoder().encodeForHTML(param));\n} }",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn allows_constant_output() {
        let findings = check(
            "class T { void f(HttpServletRequest request, HttpServletResponse response) {\n response.getWriter().println(\"constant text\");\n} }",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn allows_constant_true_ternary_value() {
        let findings = check(
            "class T { void f(HttpServletRequest request, HttpServletResponse response) {\n String param = request.getParameter(\"vector\");\n int num = 106;\n String bar = (7*18) + num > 200 ? \"This_should_always_happen\" : param;\n response.getWriter().write(bar);\n} }",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn flags_printwriter_variable_assigned_from_getwriter() {
        let findings = check(
            "class T { void f(HttpServletRequest request, HttpServletResponse response) {\n String param = request.getParameter(\"name\");\n java.io.PrintWriter out = response.getWriter();\n out.write(param);\n} }",
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_string_builder_flow() {
        let findings = check(
            "class T { void f(HttpServletRequest request, HttpServletResponse response) {\n String param = request.getParameter(\"name\");\n StringBuilder sb = new StringBuilder();\n sb.append(\"x\");\n sb.append(param);\n response.getWriter().write(sb.toString());\n} }",
        );
        assert_eq!(findings.len(), 1);
    }
}
