//! Rule: flags `type(x) == SomeType` (or `type(x) == type(y)`). It fails
//! for subclasses where `isinstance(x, SomeType)` would correctly
//! succeed, so code guarded this way silently takes the wrong branch for
//! any subclass instance.

use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use yunq_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

fn other_kind_name(node: &AstNode) -> Option<&str> {
    match node.kind() {
        NodeKind::Other(name) => Some(name.as_ref()),
        _ => None,
    }
}

fn is_type_call(node: &AstNode) -> bool {
    *node.kind() == NodeKind::Call && node.first_child().is_some_and(|callee| callee.text() == "type")
}

fn compares_via_type_call(comparison: &AstNode) -> bool {
    let text = comparison.text();
    (text.contains("==") || text.contains("!=")) && comparison.children().iter().any(is_type_call)
}

pub struct TypeComparisonRule {
    id: RuleId,
}

impl TypeComparisonRule {
    pub fn new() -> Self {
        Self { id: RuleId::new("python:type-comparison").expect("valid rule id") }
    }
}

impl Default for TypeComparisonRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for TypeComparisonRule {
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
        IssueType::Bug
    }

    fn remediation_effort_minutes(&self) -> u32 {
        5
    }

    fn metadata(&self) -> yunq_rules_engine::RuleMetadata {
        yunq_rules_engine::RuleMetadata {
            description: "Comparing type(x) to a class with == rejects subclasses that isinstance() would correctly accept; use isinstance(x, SomeType) unless an exact-type check is truly intended.".into(),
            tags: vec!["bug".into(), "python-idiom".into()],
            cwe: Some(697),
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter(|n| other_kind_name(n) == Some("comparison_operator"))
            .filter(|n| compares_via_type_call(n))
            .map(|n| Finding::new("type(x) == ... rejects subclasses; use isinstance() unless an exact-type check is intended", n.span()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use yunq_rules_engine::AstParser;

    use super::*;

    fn findings(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.py", code, LanguageIdentifier::python()).unwrap();
        let ast = yunq_parser_python::PythonParser::new().parse(&file).unwrap();
        TypeComparisonRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_type_call_vs_type_call() {
        assert_eq!(findings("if type(a) == type(b):\n    pass\n").len(), 1);
    }

    #[test]
    fn flags_type_call_vs_class() {
        assert_eq!(findings("if type(a) == MyClass:\n    pass\n").len(), 1);
    }

    #[test]
    fn allows_isinstance() {
        assert!(findings("if isinstance(a, MyClass):\n    pass\n").is_empty());
    }
}
