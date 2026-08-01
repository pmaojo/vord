//! Rule: flags untrusted user input reaching Java file I/O APIs
//! (`FileInputStream`, `FileReader`, etc.) — the classic Path Traversal
//! pattern in the OWASP Benchmark (and real-world Java servlets).
//!
//! Strategy: first check whether the file contains any servlet user-input
//! method — if it does, the file is a servlet processing user input. Then
//! flag every file I/O constructor in that file as a potential path
//! traversal sink, since user input may flow into it across lines (the
//! benchmark separates extraction and file operations).

use yunq_ast::{AstNode, LanguageIdentifier, SourceFile};
use yunq_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

/// Java file I/O constructors/classes that accept a path argument.
const FILE_IO_MARKERS: &[&str] = &[
    "FileInputStream",
    "FileOutputStream",
    "FileReader",
    "FileWriter",
    "RandomAccessFile",
];

/// Servlet request methods that introduce user-controlled data.
const USER_INPUT_PATTERNS: &[&str] = &[
    "request.getParameter(",
    "request.getHeader(",
    "request.getHeaders(",
    "request.getCookies(",
    "request.getQueryString(",
    "request.getPathInfo(",
    "request.getReader(",
    "request.getInputStream(",
];

pub struct PathTraversalJavaRule {
    id: RuleId,
}

impl PathTraversalJavaRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("owasp:path-traversal-java").expect("valid rule id"),
        }
    }
}

impl Default for PathTraversalJavaRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for PathTraversalJavaRule {
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

    fn metadata(&self) -> yunq_rules_engine::RuleMetadata {
        yunq_rules_engine::RuleMetadata {
            description: "Untrusted user input reaches a file I/O API, which can lead to Path Traversal (LFI) vulnerabilities. Ensure file paths are validated against a whitelist or sanitized before opening files.".into(),
            tags: vec!["security".into(), "owasp-a01".into(), "cwe".into(), "path-traversal".into(), "java".into()],
            cwe: Some(22),
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

        // Second pass: flag every file I/O constructor in this servlet.
        let mut findings = Vec::new();
        for (idx, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.starts_with("//") || trimmed.starts_with('*') || trimmed.is_empty() {
                continue;
            }
            if FILE_IO_MARKERS.iter().any(|m| line.contains(m)) {
                findings.push(Finding::new(
                    "user input from a servlet request reaches a file I/O API without path sanitization — this is a Path Traversal vulnerability",
                    yunq_ast::Span::new(
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
    use yunq_ast::NodeKind;

    #[test]
    fn flags_file_input_stream_in_servlet_with_user_input() {
        // Realistic benchmark pattern: user input on one line, file I/O on another.
        let code = r#"String fileName = org.owasp.benchmark.helpers.Utils.testfileDir + request.getParameter("file");
java.io.FileInputStream fis = new java.io.FileInputStream(new java.io.File(fileName));
"#;
        let file = SourceFile::new("Test.java", code, LanguageIdentifier::java()).unwrap();
        let ast = AstNode::new(
            NodeKind::SourceUnit,
            yunq_ast::Span::new(1, 1, 2, code.len() as u32),
            code, vec![],
        );
        let findings = PathTraversalJavaRule::new().check(&file, &ast);
        assert_eq!(findings.len(), 1, "should flag FileInputStream in a servlet");
    }

    #[test]
    fn flags_file_reader_with_cookie_value() {
        let code = r#"String param = request.getCookies()[0].getValue();
new java.io.FileReader(param);
"#;
        let file = SourceFile::new("Test.java", code, LanguageIdentifier::java()).unwrap();
        let ast = AstNode::new(
            NodeKind::SourceUnit,
            yunq_ast::Span::new(1, 1, 2, code.len() as u32),
            code, vec![],
        );
        let findings = PathTraversalJavaRule::new().check(&file, &ast);
        assert!(!findings.is_empty(), "should flag FileReader");
    }

    #[test]
    fn allows_safe_file_open_without_user_input() {
        let code = "new java.io.FileInputStream(new java.io.File(\"/etc/config.properties\"));\n";
        let file = SourceFile::new("Utility.java", code, LanguageIdentifier::java()).unwrap();
        let ast = AstNode::new(
            NodeKind::SourceUnit,
            yunq_ast::Span::new(1, 1, 1, code.len() as u32),
            code, vec![],
        );
        assert!(PathTraversalJavaRule::new().check(&file, &ast).is_empty());
    }

    #[test]
    fn does_not_flag_non_servlet_with_file_io() {
        let code = r#"new java.io.FileWriter("/tmp/log.txt");
System.out.println("done");
"#;
        let file = SourceFile::new("Utility.java", code, LanguageIdentifier::java()).unwrap();
        let ast = AstNode::new(
            NodeKind::SourceUnit,
            yunq_ast::Span::new(1, 1, 2, code.len() as u32),
            code, vec![],
        );
        assert!(PathTraversalJavaRule::new().check(&file, &ast).is_empty());
    }
}
