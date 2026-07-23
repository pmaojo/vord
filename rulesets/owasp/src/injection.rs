use yunq_ast::{AstNode, LanguageIdentifier, SourceFile};
use yunq_rules_engine::{Finding, Rule, RuleId, Severity};
use yunq_taint::{TaintAnalysis, TaintConfig};

/// Taint-based injection detection for TypeScript: user-controlled input
/// (`process.argv`, request objects, …) must never reach a code- or
/// command-execution sink.
pub struct InjectionRule {
    id: RuleId,
    analysis: TaintAnalysis,
}

impl InjectionRule {
    pub fn new() -> Self {
        let config = TaintConfig::new()
            .with_source_marker("process.argv")
            .with_source_marker("process.env")
            .with_source_marker("req.query")
            .with_source_marker("req.body")
            .with_source_marker("req.params")
            .with_sink("eval")
            .with_sink("Function")
            .with_sink("exec")
            .with_sink("execSync")
            .with_sink("query")
            .with_sanitizer("escape")
            .with_sanitizer("escapeShellArg");
        Self {
            id: RuleId::new("owasp:injection").expect("valid rule id"),
            analysis: TaintAnalysis::new(config),
        }
    }
}

impl Default for InjectionRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for InjectionRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, language: &LanguageIdentifier) -> bool {
        *language == LanguageIdentifier::typescript()
    }

    fn default_severity(&self) -> Severity {
        Severity::Blocker
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        self.analysis
            .find_flows(ast)
            .into_iter()
            .map(|flow| {
                Finding::new(
                    format!(
                        "user input from `{}` reaches sink `{}`: {}",
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
    use yunq_ast::SourceFile;
    use yunq_rules_engine::AstParser;

    use super::*;

    fn check(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.ts", code, LanguageIdentifier::typescript()).unwrap();
        let ast = yunq_parser_typescript::TypeScriptParser::new().parse(&file).unwrap();
        InjectionRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_argv_flowing_into_eval() {
        let findings = check("const input = process.argv[2];\nconst copy = input;\neval(copy);\n");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("process.argv"));
        assert!(findings[0].message.contains("eval"));
    }

    #[test]
    fn clean_flow_is_silent() {
        assert!(check("const safe = \"literal\";\neval(safe);\n").is_empty());
    }

    #[test]
    fn sanitized_flow_is_silent() {
        let findings = check(
            "const input = process.argv[2];\nconst safe = escapeShellArg(input);\nexecSync(safe);\n",
        );
        assert!(findings.is_empty());
    }
}
