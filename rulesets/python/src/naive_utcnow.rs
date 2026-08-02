//! Rule: flags `datetime.utcnow()`. It returns a naive `datetime` (no
//! `tzinfo`) that silently represents UTC without saying so, so mixing
//! it with any timezone-aware value later raises `TypeError`, and
//! comparing it against local-time naive values is simply wrong. It is
//! also deprecated since Python 3.12 in favor of `datetime.now(timezone.utc)`.

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, Rule, RuleId, Severity};

pub struct NaiveUtcnowRule {
    id: RuleId,
}

impl NaiveUtcnowRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("python:datetime-utcnow-naive").expect("valid rule id"),
        }
    }
}

impl Default for NaiveUtcnowRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for NaiveUtcnowRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, lang: &LanguageIdentifier) -> bool {
        *lang == LanguageIdentifier::python()
    }

    fn default_severity(&self) -> Severity {
        Severity::Minor
    }

    fn remediation_effort_minutes(&self) -> u32 {
        5
    }

    fn metadata(&self) -> vord_rules_engine::RuleMetadata {
        vord_rules_engine::RuleMetadata {
            description: "datetime.utcnow() returns a naive datetime that silently represents UTC without saying so, and is deprecated since Python 3.12; use datetime.now(timezone.utc) instead.".into(),
            tags: vec!["reliability".into(), "python-idiom".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter(|n| *n.kind() == NodeKind::Call)
            .filter(|call| call.first_child().is_some_and(|callee| callee.text() == "datetime.utcnow"))
            .map(|call| Finding::new("datetime.utcnow() returns a naive datetime and is deprecated; use datetime.now(timezone.utc)", call.span()))
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
        NaiveUtcnowRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_datetime_utcnow() {
        assert_eq!(findings("now = datetime.utcnow()\n").len(), 1);
    }

    #[test]
    fn allows_timezone_aware_now() {
        assert!(findings("now = datetime.now(timezone.utc)\n").is_empty());
    }
}
