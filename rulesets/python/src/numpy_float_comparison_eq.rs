//! Rule: flags `==`/`!=` used directly on a numpy float value
//! (`np.array([...])`, `np.float32(...)`, `np.float64(...)`). Floating
//! point arithmetic accumulates rounding error, so two values that are
//! mathematically equal are rarely bit-identical; `np.isclose`/
//! `np.allclose` compare within a tolerance instead of demanding an exact
//! match.

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, Rule, RuleId, Severity};

use crate::common::other_kind_name;

// `np.float32`/`np.float64` unambiguously construct a float value: always
// the "float rounding error" risk this rule targets.
const UNAMBIGUOUS_FLOAT_CALLEES: &[&str] =
    &["np.float32", "np.float64", "numpy.float32", "numpy.float64"];

// `np.array`/`np.asarray` build whatever dtype their contents imply — an
// integer array (`np.array([1, 2, 3])`) compares exactly with `==` just
// fine, so these only count as the float-comparison risk when there's
// actual textual evidence the array holds floats.
const GENERIC_ARRAY_CALLEES: &[&str] = &["np.array", "numpy.array", "np.asarray", "numpy.asarray"];

/// Whether `call`'s own argument text gives any evidence it builds a
/// floating-point array: a decimal-point/exponent numeric literal
/// (`1.0`, `1e-3`), or an explicit `dtype=float`/`dtype=np.float32`/etc.
/// keyword argument. Best-effort and text-based — this can't resolve a
/// dtype that comes from a variable — but it's enough to stop flagging
/// the common, unambiguous integer-array case (`np.array([1, 2, 3])`)
/// while still catching the equally common float-literal case.
fn args_suggest_float_dtype(call: &AstNode) -> bool {
    let text = call.text();
    if text.contains("dtype") && (text.contains("float") || text.contains("f4") || text.contains("f8")) {
        return true;
    }
    // A float literal contains a `.` or an exponent marker next to
    // digits; integer literals and identifiers don't. Scanning the raw
    // text for a digit-adjacent `.` is a simple, reliable enough proxy
    // without needing to parse each array element individually.
    let bytes = text.as_bytes();
    bytes.iter().enumerate().any(|(i, &b)| {
        b == b'.'
            && i > 0
            && bytes[i - 1].is_ascii_digit()
            && bytes.get(i + 1).is_some_and(|b| b.is_ascii_digit())
    })
}

fn is_numpy_float_construct(node: &AstNode) -> bool {
    if node.kind() != &NodeKind::Call {
        return false;
    }
    let Some(callee) = node.first_child() else {
        return false;
    };
    let text = callee.text();
    if UNAMBIGUOUS_FLOAT_CALLEES.contains(&text) {
        return true;
    }
    GENERIC_ARRAY_CALLEES.contains(&text) && args_suggest_float_dtype(node)
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

    /// Regression: `np.array([1, 2, 3])` builds an *integer* array by
    /// default — comparing it with `==` is exact and completely valid,
    /// not the float-rounding-error risk this rule targets. The old
    /// blanket "any np.array(...) call" check flagged this too.
    #[test]
    fn allows_integer_array_equality() {
        assert!(findings("if np.array([1, 2, 3]) == expected:\n    pass\n").is_empty());
    }

    #[test]
    fn allows_integer_array_equality_with_variable() {
        assert!(findings("if np.array(values) == expected:\n    pass\n").is_empty());
    }

    /// An explicit `dtype=float` (or `np.float32`/`np.float64`) keyword
    /// is real evidence of a float array even without a float literal in
    /// the contents, and must still be flagged.
    #[test]
    fn flags_array_with_explicit_float_dtype() {
        let code = "if np.array([1, 2, 3], dtype=float) == expected:\n    pass\n";
        assert_eq!(findings(code).len(), 1);
    }
}
