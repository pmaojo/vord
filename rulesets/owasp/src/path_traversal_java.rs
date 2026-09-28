//! Rule: flags untrusted user input reaching Java file I/O APIs
//! (`FileInputStream`, `FileOutputStream`, `File`, …) — the classic Path
//! Traversal (LFI) pattern in the OWASP Benchmark and real servlets.
//!
//! Strategy: intra-file value flow ([`ServletTaint`]) — a finding is
//! reported only when user-controlled data actually reaches a file path
//! constructor argument. Constant paths (a fixed config file, a
//! hard-coded log path) stay silent.

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

use crate::java_servlet_taint::{split_call, ServletTaint};

/// Java types that open/construct filesystem paths.
const FILE_IO_TYPES: &[&str] = &[
    "FileInputStream",
    "FileOutputStream",
    "FileReader",
    "FileWriter",
    "RandomAccessFile",
    "File",
    "PrintWriter",
];

/// Free functions taking a path argument.
const FILE_IO_METHODS: &[&str] = &["newInputStream", "newOutputStream", "newBufferedReader", "newBufferedWriter", "openInputStream", "openOutputStream"];

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

    fn remediation_effort_minutes(&self) -> u32 {
        15
    }

    fn metadata(&self) -> vord_rules_engine::RuleMetadata {
        vord_rules_engine::RuleMetadata {
            description: "Untrusted user input reaches a file I/O API, which can lead to Path Traversal (LFI) vulnerabilities. Ensure file paths are validated against a whitelist or sanitized before opening files.".into(),
            tags: vec!["security".into(), "owasp-a01".into(), "cwe".into(), "path-traversal".into(), "java".into()],
            cwe: Some(22),
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        let state = ServletTaint::analyze(ast);
        ast.descendants()
            .filter(|n| *n.kind() == NodeKind::Call)
            .filter_map(|node| {
                let call = split_call(node)?;
                let is_sink = if call.is_new {
                    FILE_IO_TYPES
                        .iter()
                        .any(|t| call.type_text == *t || call.type_text.ends_with(&format!(".{t}")))
                } else {
                    FILE_IO_METHODS.contains(&call.method.as_str())
                };
                if !is_sink {
                    return None;
                }
                let tainted_arg = call.args.iter().any(|arg| state.is_tainted(arg));
                tainted_arg.then(|| {
                    Finding::new(
                        "user input from a servlet request reaches a file I/O API without path sanitization — this is a Path Traversal vulnerability",
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
        PathTraversalJavaRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_file_input_stream_with_tainted_path() {
        let findings = check(
            "class T { void f(HttpServletRequest request) {\n String fileName = org.owasp.benchmark.helpers.Utils.testfileDir + request.getParameter(\"file\");\n java.io.FileInputStream fis = new java.io.FileInputStream(new java.io.File(fileName));\n} }",
        );
        assert!(!findings.is_empty());
    }

    #[test]
    fn flags_file_output_stream_with_tainted_path() {
        let findings = check(
            "class T { void f(HttpServletRequest request) {\n String param = request.getParameter(\"file\");\n String fileName = \"/tmp/\" + param;\n java.io.FileOutputStream fos = new java.io.FileOutputStream(fileName, false);\n} }",
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn allows_constant_path() {
        let findings = check(
            "class T { void f() {\n new java.io.FileInputStream(new java.io.File(\"/etc/config.properties\"));\n} }",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn allows_tainted_path_in_ternary_constant_branch() {
        let findings = check(
            "class T { void f(HttpServletRequest request) {\n String param = request.getParameter(\"file\");\n int num = 106;\n String bar = (7*18) + num > 200 ? \"This_should_always_happen\" : param;\n String fileName = org.owasp.benchmark.helpers.Utils.testfileDir + bar;\n new java.io.FileInputStream(new java.io.File(fileName));\n} }",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn ignores_non_servlet_file_io() {
        let findings = check(
            "class T { void f() {\n java.io.FileWriter fw = new java.io.FileWriter(\"/tmp/log.txt\");\n} }",
        );
        assert!(findings.is_empty());
    }
}
