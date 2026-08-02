use vord_ast::{AstNode, LanguageIdentifier, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};
use vord_taint::{TaintAnalysis, TaintConfig};

/// Taint-based Path Traversal detection for TypeScript: user-controlled input
/// (`req.query`, etc) must never reach a file system API without sanitization.
pub struct PathTraversalRule {
    id: RuleId,
    analysis: TaintAnalysis,
}

impl PathTraversalRule {
    pub fn new() -> Self {
        let config = TaintConfig::web_defaults()
            .with_sink("readFile")
            .with_sink("readFileSync")
            .with_sink("writeFile")
            .with_sink("writeFileSync")
            .with_sink("unlink")
            .with_sink("unlinkSync")
            .with_sink("open")
            .with_sink("openSync")
            .with_sink("createReadStream")
            .with_sink("createWriteStream")
            .with_sanitizer("basename")
            .with_sanitizer("sanitize"); // e.g. a custom sanitizePath or just sanitize
        Self {
            id: RuleId::new("owasp:path-traversal").expect("valid rule id"),
            analysis: TaintAnalysis::new(config),
        }
    }
}

impl Default for PathTraversalRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for PathTraversalRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, language: &LanguageIdentifier) -> bool {
        *language == LanguageIdentifier::typescript()
    }

    fn default_severity(&self) -> Severity {
        Severity::Blocker
    }

    fn issue_type(&self) -> IssueType {
        IssueType::Vulnerability
    }

    fn metadata(&self) -> vord_rules_engine::RuleMetadata {
        vord_rules_engine::RuleMetadata {
            description: "Untrusted user input reaches a file system API, which can lead to Path Traversal (LFI) vulnerabilities. Ensure the input is sanitized (e.g. using `path.basename`) before using it in file operations.".into(),
            tags: vec!["security".into(), "owasp-a01".into(), "cwe".into(), "path-traversal".into()],
            cwe: Some(22),
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        self.analysis
            .find_flows(ast)
            .into_iter()
            .map(|flow| {
                Finding::new(
                    format!(
                        "user input from `{}` reaches file system sink `{}`: {}",
                        flow.source,
                        flow.sink,
                        flow.trace.join("; ")
                    ),
                    flow.sink_span,
                )
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
        let file = SourceFile::new("t.ts", code, LanguageIdentifier::typescript()).unwrap();
        let ast = vord_parser_typescript::TypeScriptParser::new()
            .parse(&file)
            .unwrap();
        PathTraversalRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_argv_flowing_into_readfilesync() {
        let findings =
            check("const input = process.argv[2];\nconst copy = input;\nfs.readFileSync(copy);\n");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("process.argv"));
        assert!(findings[0].message.contains("readFileSync"));
    }

    #[test]
    fn clean_flow_is_silent() {
        assert!(check("const safe = \"/etc/passwd\";\nfs.readFileSync(safe);\n").is_empty());
    }

    #[test]
    fn sanitized_flow_is_silent() {
        let findings = check(
            "const input = process.argv[2];\nconst safe = path.basename(input);\nfs.readFileSync(safe);\n",
        );
        assert!(findings.is_empty());
    }
}
