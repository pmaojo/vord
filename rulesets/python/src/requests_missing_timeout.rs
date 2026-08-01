//! Rule: flags a `requests` call with no `timeout=`. Without one, the
//! call blocks forever if the remote host never responds, turning a slow
//! or hung dependency into an unbounded hang (and, at scale, an easy
//! resource-exhaustion vector) in the calling service.

use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use yunq_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

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
];

fn has_timeout_argument(call: &AstNode) -> bool {
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
                .is_some_and(|name| name.text() == "timeout")
    })
}

pub struct RequestsMissingTimeoutRule {
    id: RuleId,
}

impl RequestsMissingTimeoutRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("python:requests-missing-timeout").expect("valid rule id"),
        }
    }
}

impl Default for RequestsMissingTimeoutRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for RequestsMissingTimeoutRule {
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
        IssueType::Bug
    }

    fn remediation_effort_minutes(&self) -> u32 {
        5
    }

    fn metadata(&self) -> yunq_rules_engine::RuleMetadata {
        yunq_rules_engine::RuleMetadata {
            description: "A requests call with no timeout blocks forever if the remote host never responds; pass timeout= so a hung dependency fails fast instead of hanging the caller.".into(),
            tags: vec!["reliability".into(), "cwe".into()],
            cwe: Some(400),
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
            .filter(|call| !has_timeout_argument(call))
            .map(|call| Finding::new("requests call has no timeout; it will hang forever if the remote host never responds", call.span()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use yunq_rules_engine::AstParser;

    use super::*;

    fn findings(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.py", code, LanguageIdentifier::python()).unwrap();
        let ast = yunq_parser_python::PythonParser::new()
            .parse(&file)
            .unwrap();
        RequestsMissingTimeoutRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_get_without_timeout() {
        assert_eq!(findings("requests.get(url)\n").len(), 1);
    }

    #[test]
    fn allows_get_with_timeout() {
        assert!(findings("requests.get(url, timeout=5)\n").is_empty());
    }

    #[test]
    fn ignores_unrelated_calls() {
        assert!(findings("client.get(url)\n").is_empty());
    }
}
