//! Rule: flags `x == None` / `x != None`. `None` is a singleton, so
//! identity comparison (`is` / `is not`) is the idiomatic and correct
//! check; `==` additionally invokes `__eq__`, which a class can override
//! to make the comparison lie.

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

fn compares_to_none(comparison: &AstNode) -> bool {
    comparison
        .children()
        .iter()
        .any(|c| other_kind_name(c) == Some("none"))
}

pub struct NoneComparisonRule {
    id: RuleId,
}

impl NoneComparisonRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("python:none-comparison-with-equality").expect("valid rule id"),
        }
    }
}

impl Default for NoneComparisonRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for NoneComparisonRule {
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
            description: "None is a singleton; compare with `is`/`is not` instead of `==`/`!=`, which additionally invokes __eq__ and can be overridden to lie.".into(),
            tags: vec!["python-idiom".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter(|n| other_kind_name(n) == Some("comparison_operator"))
            .filter(|n| is_equality_check(n) && compares_to_none(n))
            .map(|n| {
                Finding::new(
                    "compare with `is`/`is not None` instead of `==`/`!= None`",
                    n.span(),
                )
            })
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
        NoneComparisonRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_equality_with_none() {
        assert_eq!(findings("if x == None:\n    pass\n").len(), 1);
    }

    #[test]
    fn flags_inequality_with_none() {
        assert_eq!(findings("if x != None:\n    pass\n").len(), 1);
    }

    #[test]
    fn allows_is_none() {
        assert!(findings("if x is None:\n    pass\n").is_empty());
    }

    #[test]
    fn allows_unrelated_equality() {
        assert!(findings("if x == y:\n    pass\n").is_empty());
    }
}
