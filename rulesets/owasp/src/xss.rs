use yunq_ast::{AstNode, LanguageIdentifier, SourceFile};
use yunq_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};
use yunq_taint::{TaintAnalysis, TaintConfig};

/// Taint-based Cross-Site Scripting detection: user-controlled input reaching
/// a DOM-writing sink without sanitization.
pub struct XssRule {
    id: RuleId,
    analysis: TaintAnalysis,
}

impl XssRule {
    pub fn new() -> Self {
        let config = TaintConfig::new()
            .with_source_marker("process.argv")
            .with_source_marker("process.env")
            .with_source_marker("req.query")
            .with_source_marker("req.body")
            .with_source_marker("req.params")
            .with_source_marker("location.hash")
            .with_source_marker("location.search")
            .with_sink("write")
            .with_sink("insertAdjacentHTML")
            .with_sink("html")
            .with_sanitizer("sanitize")
            .with_sanitizer("escapeHtml")
            .with_sanitizer("encodeURIComponent");
        Self { id: RuleId::new("owasp:xss").expect("valid rule id"), analysis: TaintAnalysis::new(config) }
    }
}

impl Default for XssRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for XssRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, lang: &LanguageIdentifier) -> bool {
        lang == &LanguageIdentifier::typescript()
    }

    fn default_severity(&self) -> Severity {
        Severity::Blocker
    }

    fn issue_type(&self) -> IssueType {
        IssueType::Vulnerability
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        self.analysis
            .find_flows(ast)
            .into_iter()
            .map(|flow| {
                Finding::new(
                    format!(
                        "user input from `{}` reaches DOM sink `{}` without sanitization: {}",
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
    use super::*;
    use yunq_rules_engine::AstParser;

    #[test]
    fn flags_direct_flow_into_document_write() {
        let code = "const name = req.query;\ndocument.write(name);\n";
        let file = SourceFile::new("app.ts", code, LanguageIdentifier::typescript()).unwrap();
        let ast = yunq_parser_typescript::TypeScriptParser::new().parse(&file).unwrap();

        let findings = XssRule::new().check(&file, &ast);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("write"));
    }

    #[test]
    fn allows_untainted_dom_write() {
        let code = "const name = 'safe';\ndocument.write(name);\n";
        let file = SourceFile::new("app.ts", code, LanguageIdentifier::typescript()).unwrap();
        let ast = yunq_parser_typescript::TypeScriptParser::new().parse(&file).unwrap();

        let findings = XssRule::new().check(&file, &ast);
        assert!(findings.is_empty());
    }

    #[test]
    fn allows_dom_write_of_a_sanitized_value() {
        let code = "const name = DOMPurify.sanitize(req.query);\ndocument.write(name);\n";
        let file = SourceFile::new("app.ts", code, LanguageIdentifier::typescript()).unwrap();
        let ast = yunq_parser_typescript::TypeScriptParser::new().parse(&file).unwrap();

        let findings = XssRule::new().check(&file, &ast);
        assert!(findings.is_empty());
    }
}
