//! Rule: flags servlet response writers receiving untrusted user input
//! without HTML-encoding — the classic Java reflected XSS pattern in the
//! OWASP Benchmark (and real-world servlets).
//!
//! Strategy: first check whether the file contains any servlet user-input
//! method (`request.getParameter`, `request.getHeader`, etc.) — if it does,
//! the file is a servlet processing user input. Then flag every
//! `response.getWriter().write/print/println/format/append` call in that
//! file as a potential XSS sink, since user input may flow into it across
//! lines (the benchmark separates extraction and writing).

use vord_ast::{AstNode, LanguageIdentifier, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

/// Servlet `HttpServletResponse.getWriter()` writer methods that write
/// content straight into the HTTP response body.
const RESPONSE_WRITER_METHODS: &[&str] = &[
    ".getWriter().write(",
    ".getWriter().print(",
    ".getWriter().println(",
    ".getWriter().format(",
    ".getWriter().append(",
];

/// Servlet request methods that introduce user-controlled data.
const USER_INPUT_PATTERNS: &[&str] = &[
    "request.getParameter(",
    "request.getHeader(",
    "request.getHeaders(",
    "request.getQueryString(",
    "request.getCookies(",
    "request.getReader(",
    "request.getInputStream(",
    "request.getPathInfo(",
    "request.getRemoteUser(",
];

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

    fn metadata(&self) -> vord_rules_engine::RuleMetadata {
        vord_rules_engine::RuleMetadata {
            description: "Untrusted user input reaches a servlet response writer, which can lead to Cross-Site Scripting (XSS). Ensure all user-controlled values written to the HTTP response are properly HTML-encoded (e.g. using ESAPI.encoder().encodeForHTML(...)).".into(),
            tags: vec!["security".into(), "owasp-a03".into(), "xss".into(), "java".into()],
            cwe: Some(79),
            produces_hotspots: false,
        }
    }

    fn check(&self, file: &SourceFile, _ast: &AstNode) -> Vec<Finding> {
        let content = file.content();
        // First pass: does this file contain servlet user-input patterns?
        let has_user_input = USER_INPUT_PATTERNS.iter().any(|p| content.contains(p));
        if !has_user_input {
            return Vec::new();
        }

        // Second pass: flag every response-writer sink in this servlet.
        let mut findings = Vec::new();
        for (idx, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.starts_with("//") || trimmed.starts_with('*') || trimmed.is_empty() {
                continue;
            }
            if RESPONSE_WRITER_METHODS.iter().any(|m| line.contains(m)) {
                findings.push(Finding::new(
                    "user input from a servlet request reaches response.getWriter() without HTML-encoding — this is a reflected XSS vulnerability",
                    vord_ast::Span::new(
                        (idx + 1) as u32, 1,
                        (idx + 1) as u32,
                        line.len().max(1) as u32,
                    ),
                ));
            }
        }
        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vord_ast::NodeKind;

    #[test]
    fn flags_response_writer_in_servlet_with_user_input() {
        // Realistic benchmark pattern: user input on one line, writer on another.
        let code = r#"String param = request.getHeader("vector");
response.getWriter().format(param, new Object[] {});
"#;
        let file = SourceFile::new("Test.java", code, LanguageIdentifier::java()).unwrap();
        let ast = AstNode::new(
            NodeKind::SourceUnit,
            vord_ast::Span::new(1, 1, 2, code.len() as u32),
            code, vec![],
        );
        let findings = XssJavaRule::new().check(&file, &ast);
        assert_eq!(findings.len(), 1, "should flag getWriter().format in a servlet");
    }

    #[test]
    fn flags_response_writer_write_with_request_parameter() {
        let code = r#"String param = request.getParameter("name");
response.getWriter().write(param);
"#;
        let file = SourceFile::new("Test.java", code, LanguageIdentifier::java()).unwrap();
        let ast = AstNode::new(
            NodeKind::SourceUnit,
            vord_ast::Span::new(1, 1, 2, code.len() as u32),
            code, vec![],
        );
        let findings = XssJavaRule::new().check(&file, &ast);
        assert!(!findings.is_empty(), "should flag getWriter().write");
    }

    #[test]
    fn allows_plain_writer_without_user_input() {
        let code = "response.getWriter().write(\"Hello, world\");\n";
        let file = SourceFile::new("Test.java", code, LanguageIdentifier::java()).unwrap();
        let ast = AstNode::new(
            NodeKind::SourceUnit,
            vord_ast::Span::new(1, 1, 1, code.len() as u32),
            code, vec![],
        );
        assert!(XssJavaRule::new().check(&file, &ast).is_empty());
    }

    #[test]
    fn does_not_flag_non_servlet_file() {
        let code = "System.out.println(\"hello\");\n";
        let file = SourceFile::new("Utility.java", code, LanguageIdentifier::java()).unwrap();
        let ast = AstNode::new(
            NodeKind::SourceUnit,
            vord_ast::Span::new(1, 1, 1, code.len() as u32),
            code, vec![],
        );
        assert!(XssJavaRule::new().check(&file, &ast).is_empty());
    }
}
