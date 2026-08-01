//! Rule: flags `tempfile.mktemp()`. It returns a path without creating
//! the file, leaving a window between the name being chosen and the
//! caller opening it — another process can create or symlink that path
//! first (a classic TOCTOU race). The stdlib docs call it deprecated for
//! exactly this reason.

use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use yunq_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

use crate::common::is_test_file;

pub struct InsecureTempfileRule {
    id: RuleId,
}

impl InsecureTempfileRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("python:insecure-tempfile").expect("valid rule id"),
        }
    }
}

impl Default for InsecureTempfileRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for InsecureTempfileRule {
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
        10
    }

    fn metadata(&self) -> yunq_rules_engine::RuleMetadata {
        yunq_rules_engine::RuleMetadata {
            description: "tempfile.mktemp() returns a path without creating the file, leaving a window for another process to create or symlink it first; use tempfile.mkstemp() or NamedTemporaryFile() instead.".into(),
            tags: vec!["security".into(), "race-condition".into(), "cwe".into()],
            cwe: Some(377),
            produces_hotspots: false,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        if is_test_file(file.path()) {
            return Vec::new();
        }
        ast.descendants()
            .filter(|n| *n.kind() == NodeKind::Call)
            .filter(|call| call.first_child().is_some_and(|callee| callee.text() == "tempfile.mktemp"))
            .map(|call| Finding::new("tempfile.mktemp() is a race condition; use tempfile.mkstemp() or NamedTemporaryFile() instead", call.span()))
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
        InsecureTempfileRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_mktemp() {
        assert_eq!(findings("path = tempfile.mktemp()\n").len(), 1);
    }

    #[test]
    fn allows_mkstemp() {
        assert!(findings("fd, path = tempfile.mkstemp()\n").is_empty());
    }
}
