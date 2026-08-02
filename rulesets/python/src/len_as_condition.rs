//! Rule: flags `len(x) == 0` / `len(x) > 0` used as a truthiness check.
//! Every sized container is already truthy/falsy by its length, so `if
//! x:` / `if not x:` says the same thing without the extra `len()` call
//! — and unlike `len(x) == 0`, it also works on objects that define
//! `__bool__` without `__len__`.

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, Rule, RuleId, Severity};

fn other_kind_name(node: &AstNode) -> Option<&str> {
    match node.kind() {
        NodeKind::Other(name) => Some(name.as_ref()),
        _ => None,
    }
}

fn is_len_call(node: &AstNode) -> bool {
    *node.kind() == NodeKind::Call
        && node
            .first_child()
            .is_some_and(|callee| callee.text() == "len")
}

fn is_zero_literal(node: &AstNode) -> bool {
    other_kind_name(node) == Some("integer") && node.text() == "0"
}

fn is_len_vs_zero(comparison: &AstNode) -> bool {
    let children = comparison.children();
    if children.len() != 2 {
        return false;
    }
    let text = comparison.text();
    let compares_zero =
        (text.contains("==") || text.contains(">") || text.contains("<") || text.contains("!="))
            && !text.contains(" is ");
    compares_zero
        && ((is_len_call(&children[0]) && is_zero_literal(&children[1]))
            || (is_zero_literal(&children[0]) && is_len_call(&children[1])))
}

pub struct LenAsConditionRule {
    id: RuleId,
}

impl LenAsConditionRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("python:len-as-condition").expect("valid rule id"),
        }
    }
}

impl Default for LenAsConditionRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for LenAsConditionRule {
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
            description: "A sized container is already truthy/falsy by its length; `if x:` / `if not x:` says the same thing as `len(x) == 0`/`> 0` more directly.".into(),
            tags: vec!["python-idiom".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter(|n| other_kind_name(n) == Some("comparison_operator"))
            .filter(|n| is_len_vs_zero(n))
            .map(|n| Finding::new("use the container's truthiness (`if x:` / `if not x:`) instead of comparing len(x) to 0", n.span()))
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
        LenAsConditionRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_len_equals_zero() {
        assert_eq!(findings("if len(x) == 0:\n    pass\n").len(), 1);
    }

    #[test]
    fn flags_len_greater_than_zero() {
        assert_eq!(findings("if len(x) > 0:\n    pass\n").len(), 1);
    }

    #[test]
    fn allows_len_compared_to_nonzero() {
        assert!(findings("if len(x) == 5:\n    pass\n").is_empty());
    }

    #[test]
    fn allows_direct_truthiness() {
        assert!(findings("if x:\n    pass\n").is_empty());
    }
}
