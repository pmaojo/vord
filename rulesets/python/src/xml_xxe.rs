//! Security hotspot: parsing XML with the standard library's `xml.etree`
//! or `xml.dom.minidom` resolves external entities by default, so a
//! malicious document can read local files or trigger SSRF (XXE). A
//! reviewer must confirm the input is trusted or that a hardened parser
//! (`defusedxml`) is used instead.

use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use yunq_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

const XXE_PRONE_CALLEES: &[&str] = &[
    "xml.etree.ElementTree.parse",
    "xml.etree.ElementTree.fromstring",
    "xml.etree.ElementTree.iterparse",
    "ElementTree.parse",
    "ElementTree.fromstring",
    "xml.dom.minidom.parse",
    "xml.dom.minidom.parseString",
    "xml.sax.parse",
    "xml.sax.parseString",
    "lxml.etree.parse",
    "lxml.etree.fromstring",
];

pub struct XmlXxeRule {
    id: RuleId,
}

impl XmlXxeRule {
    pub fn new() -> Self {
        Self { id: RuleId::new("python:xml-xxe-hotspot").expect("valid rule id") }
    }
}

impl Default for XmlXxeRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for XmlXxeRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, lang: &LanguageIdentifier) -> bool {
        *lang == LanguageIdentifier::python()
    }

    fn default_severity(&self) -> Severity {
        Severity::Major
    }

    fn issue_type(&self) -> IssueType {
        IssueType::Vulnerability
    }

    fn remediation_effort_minutes(&self) -> u32 {
        15
    }

    fn metadata(&self) -> yunq_rules_engine::RuleMetadata {
        yunq_rules_engine::RuleMetadata {
            description: "The standard library's XML parsers resolve external entities by default; parsing untrusted XML with them allows XXE (local file disclosure, SSRF). Confirm the input is trusted, or parse it with defusedxml instead.".into(),
            tags: vec!["security".into(), "xxe".into(), "cwe".into(), "owasp-top10".into()],
            cwe: Some(611),
            produces_hotspots: true,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        if yunq_rules_engine::is_test_only_path(file.path()) {
            return Vec::new();
        }
        ast.descendants()
            .filter(|n| *n.kind() == NodeKind::Call)
            .filter(|call| call.first_child().is_some_and(|callee| XXE_PRONE_CALLEES.contains(&callee.text())))
            .map(|call| Finding::hotspot("make sure parsing this XML with a default-resolving parser is safe against XXE, or switch to defusedxml", call.span()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use yunq_rules_engine::{AstParser, FindingKind};

    use super::*;

    fn findings(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.py", code, LanguageIdentifier::python()).unwrap();
        let ast = yunq_parser_python::PythonParser::new().parse(&file).unwrap();
        XmlXxeRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_elementtree_parse() {
        let f = findings("xml.etree.ElementTree.parse(f)\n");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].kind, FindingKind::Hotspot);
    }

    #[test]
    fn flags_minidom_parsestring() {
        assert_eq!(findings("xml.dom.minidom.parseString(data)\n").len(), 1);
    }

    #[test]
    fn allows_unrelated_calls() {
        assert!(findings("json.loads(data)\n").is_empty());
    }
}
