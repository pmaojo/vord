//! Rule: flags a `requests` call with `verify=False`. Disabling TLS
//! certificate verification means the client accepts a certificate from
//! anyone, turning the connection into one an on-path attacker can
//! intercept and read or modify without either party noticing.

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

use crate::common::other_kind_name;

const REQUESTS_METHODS: &[&str] = &[
    "requests.get",
    "requests.post",
    "requests.put",
    "requests.delete",
    "requests.patch",
    "requests.head",
    "requests.options",
    "requests.request",
    "requests.Session",
];

fn has_verify_false_argument(call: &AstNode) -> bool {
    let Some(args) = call
        .children()
        .iter()
        .find(|c| other_kind_name(c) == Some("argument_list"))
    else {
        return false;
    };
    args.children().iter().any(|arg| {
        other_kind_name(arg) == Some("keyword_argument")
            && arg
                .children()
                .first()
                .is_some_and(|name| name.text() == "verify")
            && arg
                .children()
                .get(1)
                .is_some_and(|value| other_kind_name(value) == Some("false"))
    })
}

pub struct RequestsVerifyFalseRule {
    id: RuleId,
}

impl RequestsVerifyFalseRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("python:requests-verify-false").expect("valid rule id"),
        }
    }
}

impl Default for RequestsVerifyFalseRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for RequestsVerifyFalseRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, lang: &LanguageIdentifier) -> bool {
        *lang == LanguageIdentifier::python()
    }

    fn default_severity(&self) -> Severity {
        Severity::Critical
    }

    fn issue_type(&self) -> IssueType {
        IssueType::Vulnerability
    }

    fn remediation_effort_minutes(&self) -> u32 {
        5
    }

    fn metadata(&self) -> vord_rules_engine::RuleMetadata {
        vord_rules_engine::RuleMetadata {
            description: "verify=False disables TLS certificate verification, so an on-path attacker can present any certificate and intercept or modify the traffic without either party noticing; fix the underlying certificate problem instead of disabling verification.".into(),
            tags: vec!["security".into(), "cwe".into()],
            cwe: Some(295),
            produces_hotspots: false,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        if crate::common::is_test_file(file.path()) {
            return Vec::new();
        }
        ast.descendants()
            .filter(|n| *n.kind() == NodeKind::Call)
            .filter(|call| call.first_child().is_some_and(|callee| REQUESTS_METHODS.contains(&callee.text())))
            .filter(|call| has_verify_false_argument(call))
            .map(|call| Finding::new("verify=False disables TLS certificate verification; an on-path attacker can intercept this connection undetected", call.span()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use vord_rules_engine::AstParser;

    use super::*;

    fn findings(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.py", code, LanguageIdentifier::python()).unwrap();
        let ast = vord_parser_python::PythonParser::new()
            .parse(&file)
            .unwrap();
        RequestsVerifyFalseRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_get_with_verify_false() {
        assert_eq!(findings("requests.get(url, verify=False)\n").len(), 1);
    }

    #[test]
    fn allows_verify_true() {
        assert!(findings("requests.get(url, verify=True)\n").is_empty());
    }

    #[test]
    fn allows_no_verify_argument() {
        assert!(findings("requests.get(url)\n").is_empty());
    }

    #[test]
    fn ignores_unrelated_calls() {
        assert!(findings("client.get(url, verify=False)\n").is_empty());
    }
}
