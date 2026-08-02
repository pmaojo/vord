//! Security hotspot: `assert` statements are stripped when Python runs
//! with `-O`/`PYTHONOPTIMIZE`, so any `assert` used to enforce a security
//! or business invariant in production code silently disappears. A
//! reviewer must confirm the asserted condition isn't load-bearing.

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

pub struct AssertUsedRule {
    id: RuleId,
}

impl AssertUsedRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("python:assert-used-in-production").expect("valid rule id"),
        }
    }
}

impl Default for AssertUsedRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for AssertUsedRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, lang: &LanguageIdentifier) -> bool {
        *lang == LanguageIdentifier::python()
    }

    fn default_severity(&self) -> Severity {
        Severity::Minor
    }

    fn issue_type(&self) -> IssueType {
        IssueType::Vulnerability
    }

    fn remediation_effort_minutes(&self) -> u32 {
        10
    }

    fn metadata(&self) -> vord_rules_engine::RuleMetadata {
        vord_rules_engine::RuleMetadata {
            description: "`assert` is removed when Python runs with -O; confirm this condition is not enforcing a security or business invariant that must always run.".into(),
            tags: vec!["security".into(), "cwe".into()],
            cwe: Some(617),
            produces_hotspots: true,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        if vord_rules_engine::is_test_only_path(file.path()) {
            return Vec::new();
        }
        ast.descendants()
            .filter(|n| matches!(n.kind(), NodeKind::Other(name) if name.as_ref() == "assert_statement"))
            .map(|n| Finding::hotspot("make sure this `assert` isn't enforcing a security-critical invariant, since -O strips it at runtime", n.span()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use vord_rules_engine::{AstParser, FindingKind};

    use super::*;

    fn findings(path: &str, code: &str) -> Vec<Finding> {
        let file = SourceFile::new(path, code, LanguageIdentifier::python()).unwrap();
        let ast = vord_parser_python::PythonParser::new()
            .parse(&file)
            .unwrap();
        AssertUsedRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_assert_in_production_code() {
        let f = findings("app/auth.py", "assert user.is_admin\n");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].kind, FindingKind::Hotspot);
    }

    #[test]
    fn allows_assert_in_test_files() {
        assert!(findings("tests/test_auth.py", "assert result == expected\n").is_empty());
    }
}
