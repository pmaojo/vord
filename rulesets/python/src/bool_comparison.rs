//! Rule: flags `x == True` / `x == False` (and their `!=` forms). The
//! comparison is redundant — `x` and `not x` already express the same
//! check — and, like any `==` against a singleton, additionally invokes
//! `__eq__` instead of testing truthiness directly.

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, Rule, RuleId, Severity};

fn other_kind_name(node: &AstNode) -> Option<&str> {
    match node.kind() {
        NodeKind::Other(name) => Some(name.as_ref()),
        _ => None,
    }
}

fn is_equality_check(comparison: &AstNode) -> bool {
    comparison.text().contains("==") || comparison.text().contains("!=")
}

fn compares_to_bool_literal(comparison: &AstNode) -> bool {
    comparison
        .children()
        .iter()
        .any(|c| matches!(other_kind_name(c), Some("true") | Some("false")))
}

pub struct BoolComparisonRule {
    id: RuleId,
}

impl BoolComparisonRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("python:bool-comparison-with-equality").expect("valid rule id"),
        }
    }
}

impl Default for BoolComparisonRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for BoolComparisonRule {
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
            description: "Comparing a value to True/False with ==/!= is redundant with testing truthiness directly (`if x:` / `if not x:`) and additionally invokes __eq__ instead of bool().".into(),
            tags: vec!["python-idiom".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter(|n| other_kind_name(n) == Some("comparison_operator"))
            .filter(|n| is_equality_check(n) && compares_to_bool_literal(n))
            .map(|n| Finding::new("compare truthiness directly (`if x:` / `if not x:`) instead of `==`/`!=` against True/False", n.span()))
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
        BoolComparisonRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_equality_with_true() {
        assert_eq!(findings("if x == True:\n    pass\n").len(), 1);
    }

    #[test]
    fn flags_equality_with_false() {
        assert_eq!(findings("if x == False:\n    pass\n").len(), 1);
    }

    #[test]
    fn allows_direct_truthiness_check() {
        assert!(findings("if x:\n    pass\n").is_empty());
    }
}
