use yunq_ast::{AstNode, LanguageIdentifier, SourceFile};
use yunq_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};
use yunq_taint::{TaintAnalysis, TaintConfig};

/// Taint-based Server-Side Request Forgery detection for TypeScript:
/// user-controlled input reaching an outbound HTTP request sink lets an
/// attacker redirect the server's own requests at internal services
/// (metadata endpoints, admin APIs, `localhost` ports) that are otherwise
/// unreachable from outside the network. Semgrep, CodeQL and SonarQube all
/// ship dedicated SSRF rules; this fills the equivalent gap here.
pub struct SsrfRule {
    id: RuleId,
    analysis: TaintAnalysis,
}

impl SsrfRule {
    pub fn new() -> Self {
        let config = TaintConfig::web_defaults()
            .with_sink("fetch")
            .with_sink("request")
            .with_sink("get")
            .with_sink("post")
            .with_sanitizer("sanitize")
            .with_sanitizer("isAllowedHost");
        Self {
            id: RuleId::new("owasp:ssrf").expect("valid rule id"),
            analysis: TaintAnalysis::new(config),
        }
    }
}

impl Default for SsrfRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for SsrfRule {
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

    fn metadata(&self) -> yunq_rules_engine::RuleMetadata {
        yunq_rules_engine::RuleMetadata {
            description: "Untrusted user input reaches an outbound HTTP request (fetch/axios/http client), which can lead to Server-Side Request Forgery. Validate the destination against an allowlist of hosts before requesting it.".into(),
            tags: vec!["security".into(), "owasp-a10".into(), "cwe".into(), "ssrf".into()],
            cwe: Some(918),
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
                        "user input from `{}` reaches outbound HTTP request sink `{}`: {}",
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
        let ast = yunq_parser_typescript::TypeScriptParser::new()
            .parse(&file)
            .unwrap();
        SsrfRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_query_param_flowing_into_fetch() {
        let findings = check("const target = req.query;\nconst url = target;\nfetch(url);\n");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("req.query"));
        assert!(findings[0].message.contains("fetch"));
    }

    #[test]
    fn flags_body_param_flowing_into_axios_get() {
        let findings = check("const url = req.body;\naxios.get(url);\n");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("get"));
    }

    #[test]
    fn clean_flow_is_silent() {
        assert!(check("const safe = \"https://example.com\";\nfetch(safe);\n").is_empty());
    }

    #[test]
    fn sanitized_flow_is_silent() {
        let findings =
            check("const target = req.query;\nconst safe = isAllowedHost(target);\nfetch(safe);\n");
        assert!(findings.is_empty());
    }
}
