//! Rule: flags `==`/`!=` used directly on a numpy float value
//! (`np.array([...])`, `np.float32(...)`, `np.float64(...)`). Floating
//! point arithmetic accumulates rounding error, so two values that are
//! mathematically equal are rarely bit-identical; `np.isclose`/
//! `np.allclose` compare within a tolerance instead of demanding an exact
//! match.

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, Rule, RuleId, Severity};

use crate::common::other_kind_name;

const NUMPY_FLOAT_CALLEES: &[&str] = &[
    "np.array",
    "numpy.array",
    "np.float32",
    "np.float64",
    "numpy.float32",
    "numpy.float64",
    "np.asarray",
    "numpy.asarray",
];

fn is_numpy_float_construct(node: &AstNode) -> bool {
    node.kind() == &NodeKind::Call
        && node
            .first_child()
            .is_some_and(|callee| NUMPY_FLOAT_CALLEES.contains(&callee.text()))
}

fn is_equality_operator(op_text: &str) -> bool {
    let trimmed = op_text.trim();
    trimmed == "==" || trimmed == "!="
}

pub struct NumpyFloatComparisonEqRule {
    id: RuleId,
}

impl NumpyFloatComparisonEqRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("python:numpy-float-comparison-eq").expect("valid rule id"),
        }
    }
}

impl Default for NumpyFloatComparisonEqRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for NumpyFloatComparisonEqRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, lang: &LanguageIdentifier) -> bool {
        *lang == LanguageIdentifier::python()
    }

    fn default_severity(&self) -> Severity {
        Severity::Major
    }

    fn remediation_effort_minutes(&self) -> u32 {
        10
    }

    fn metadata(&self) -> vord_rules_engine::RuleMetadata {
        vord_rules_engine::RuleMetadata {
            description: "== / != on a numpy float value demands bit-exact equality, but floating point arithmetic accumulates rounding error; use np.isclose/np.allclose to compare within a tolerance instead.".into(),
            tags: vec!["bug".into(), "numeric".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter(|n| other_kind_name(n) == Some("comparison_operator"))
            .filter(|n| n.children().len() == 2)
            .filter_map(|n| {
                let left = &n.children()[0];
                let right = &n.children()[1];
                let op_text = n.text_between(left, right)?;
                if !is_equality_operator(op_text) {
                    return None;
                }
                (is_numpy_float_construct(left) || is_numpy_float_construct(right)).then(|| {
                    Finding::new(
                        "==/!= on a numpy float value demands bit-exact equality; use np.isclose/np.allclose to compare within a tolerance instead",
                        n.span(),
                    )
                })
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
        NumpyFloatComparisonEqRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_array_equality() {
        assert_eq!(findings("if np.array([1.0, 2.0]) == expected:\n    pass\n").len(), 1);
    }

    #[test]
    fn flags_float64_inequality() {
        assert_eq!(findings("if result != np.float64(3.14):\n    pass\n").len(), 1);
    }

    #[test]
    fn allows_isclose() {
        assert!(findings("if np.isclose(a, np.array([1.0])):\n    pass\n").is_empty());
    }

    #[test]
    fn ignores_non_numpy_comparison() {
        assert!(findings("if a == b:\n    pass\n").is_empty());
    }

    #[test]
    fn ignores_ordering_comparison() {
        assert!(findings("if np.array([1.0]) < expected:\n    pass\n").is_empty());
    }
}
