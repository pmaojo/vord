//! Rule: flags XPath expressions built from untrusted user input — the
//! OWASP Benchmark "xpathi" family (CWE-643).
//!
//! Strategy: intra-file value flow ([`ServletTaint`]) — `XPath.evaluate`/
//! `XPath.compile` is a finding when the expression argument is
//! user-controlled.

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

use crate::java_servlet_taint::{split_call, ServletTaint};

pub struct XPathInjectionJavaRule {
    id: RuleId,
}

impl XPathInjectionJavaRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("owasp:xpath-injection-java").expect("valid rule id"),
        }
    }
}

impl Default for XPathInjectionJavaRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for XPathInjectionJavaRule {
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
            description: "Untrusted user input is concatenated into an XPath expression, which allows XPath injection. Use parameterized XPath variables or escape the input.".into(),
            tags: vec!["security".into(), "owasp-a03".into(), "xpath".into(), "java".into()],
            cwe: Some(643),
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        let state = ServletTaint::analyze(ast);
        ast.descendants()
            .filter(|n| *n.kind() == NodeKind::Call)
            .filter_map(|node| {
                let call = split_call(node)?;
                if !matches!(call.method.as_str(), "evaluate" | "compile") {
                    return None;
                }
                let receiver = call.receiver?;
                if !state.is_xpath(receiver) {
                    return None;
                }
                let tainted_arg = call.args.iter().any(|arg| state.is_tainted(arg));
                tainted_arg.then(|| {
                    Finding::new(
                        "user input from a servlet request reaches an XPath expression without escaping — this is an XPath injection vulnerability",
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
        XPathInjectionJavaRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_tainted_xpath_evaluate() {
        let findings = check(
            "class T { void f(HttpServletRequest request, org.w3c.dom.Document xmlDocument) throws Exception {\n String param = request.getParameter(\"xp\");\n String expression = \"//userName[text()='\" + param + \"']\";\n javax.xml.xpath.XPathFactory xpf = javax.xml.xpath.XPathFactory.newInstance();\n javax.xml.xpath.XPath xp = xpf.newXPath();\n String r = xp.evaluate(expression, xmlDocument);\n} }",
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_tainted_xpath_compile() {
        let findings = check(
            "class T { void f(HttpServletRequest request) throws Exception {\n String bar = request.getParameter(\"xp\");\n javax.xml.xpath.XPath xp = javax.xml.xpath.XPathFactory.newInstance().newXPath();\n javax.xml.xpath.XPathExpression ex = xp.compile(bar);\n} }",
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn allows_constant_xpath() {
        let findings = check(
            "class T { void f(org.w3c.dom.Document xmlDocument) throws Exception {\n javax.xml.xpath.XPath xp = javax.xml.xpath.XPathFactory.newInstance().newXPath();\n String r = xp.evaluate(\"//userName\", xmlDocument);\n} }",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn ignores_non_xpath_evaluate() {
        let findings = check(
            "class T { void f(HttpServletRequest request) throws Exception {\n String bar = request.getParameter(\"xp\");\n Object r = engine.evaluate(bar);\n} }",
        );
        assert!(findings.is_empty());
    }
}
