//! Rule: detects unvalidated user input parameters (`req.query`, `req.params`,
//! `req.body`, `request.args`) passed directly into HTTP request sinks (`fetch()`,
//! `axios.get()`, `http.get()`, `requests.get()`) without URL validation or host allowlisting,
//! which leads to Server-Side Request Forgery (SSRF).

use vord_ast::{AstNode, LanguageIdentifier, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};
use vord_taint::{TaintAnalysis, TaintConfig};

pub struct SsrfUnvalidatedUrlRule {
    id: RuleId,
    analysis: TaintAnalysis,
}

impl SsrfUnvalidatedUrlRule {
    pub fn new() -> Self {
        let config = TaintConfig::new()
            .with_source_marker("req.query")
            .with_source_marker("req.params")
            .with_source_marker("req.body")
            .with_source_marker("request.args")
            .with_sink("fetch")
            .with_sink("axios.get")
            .with_sink("axios.post")
            .with_sink("http.get")
            .with_sink("http.request")
            .with_sink("https.get")
            .with_sink("https.request")
            .with_sink("got")
            .with_sink("superagent")
            .with_sink("request")
            .with_sanitizer("sanitize")
            .with_sanitizer("isAllowedUrl")
            .with_sanitizer("isAllowedHost")
            .with_sanitizer("encodeURIComponent")
            .with_sanitizer("URL");
        Self {
            id: RuleId::new("owasp:ssrf-unvalidated-url").expect("valid rule id"),
            analysis: TaintAnalysis::new(config),
        }
    }
}

impl Default for SsrfUnvalidatedUrlRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for SsrfUnvalidatedUrlRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, language: &LanguageIdentifier) -> bool {
        *language == LanguageIdentifier::typescript()
            || *language == LanguageIdentifier::python()
    }

    fn default_severity(&self) -> Severity {
        Severity::Blocker
    }

    fn issue_type(&self) -> IssueType {
        IssueType::Vulnerability
    }

    fn metadata(&self) -> vord_rules_engine::RuleMetadata {
        vord_rules_engine::RuleMetadata {
            description: "User input parameters (`req.query`, `req.params`, `req.body`, `request.args`) passed directly into HTTP request sinks (`fetch()`, `axios.get()`, `http.get()`, `requests.get()`) without URL validation or host allowlisting lead to Server-Side Request Forgery (SSRF).".into(),
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
                        "Unvalidated user input parameter from `{}` passed directly into HTTP request sink `{}` without URL validation or host allowlisting: {}",
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
    use vord_rules_engine::AstParser;

    fn check_ts(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.ts", code, LanguageIdentifier::typescript()).unwrap();
        let ast = vord_parser_typescript::TypeScriptParser::new()
            .parse(&file)
            .unwrap();
        SsrfUnvalidatedUrlRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_req_query_in_fetch() {
        let code = "const target = req.query.url;\nfetch(target);\n";
        let findings = check_ts(code);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("req.query"));
        assert!(findings[0].message.contains("fetch"));
    }

    #[test]
    fn flags_req_params_in_axios_get() {
        let code = "const target = req.params.endpoint;\naxios.get(target);\n";
        let findings = check_ts(code);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("req.params"));
        assert!(findings[0].message.contains("get"));
    }

    #[test]
    fn flags_req_body_in_http_get() {
        let code = "const target = req.body.url;\nhttp.get(target);\n";
        let findings = check_ts(code);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("req.body"));
        assert!(findings[0].message.contains("get"));
    }

    #[test]
    fn sanitized_url_is_silent() {
        let code = "const target = req.query.url;\nconst safe = isAllowedUrl(target);\nfetch(safe);\n";
        let findings = check_ts(code);
        assert!(findings.is_empty());
    }

    #[test]
    fn hardcoded_url_is_silent() {
        let code = "const safe = \"https://api.example.com/v1\";\nfetch(safe);\n";
        let findings = check_ts(code);
        assert!(findings.is_empty());
    }
}
