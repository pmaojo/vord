use yunq_ast::{AstNode, LanguageIdentifier, SourceFile};
use yunq_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

use crate::common::{is_other, operator_between};

/// Direct `==`/`!=` comparison against a floating-point literal is fragile:
/// arithmetic that's mathematically exact on paper (`0.1 + 0.2`) routinely
/// lands one ULP away from the literal it "should" equal once rounded to
/// `f32`/`f64`, so the comparison silently takes the wrong branch. An
/// epsilon-based comparison (or `f64::EPSILON`-scaled tolerance) is the
/// correct fix; syntactically restricted to the literal-operand case here
/// since it needs no type inference to catch with confidence. Mirrors
/// `clippy::float_cmp_const`.
pub struct FloatLiteralEqRule {
    id: RuleId,
}

impl FloatLiteralEqRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("rust:float-literal-eq").expect("valid rule id"),
        }
    }
}

impl Default for FloatLiteralEqRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for FloatLiteralEqRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, language: &LanguageIdentifier) -> bool {
        *language == LanguageIdentifier::rust()
    }

    fn default_severity(&self) -> Severity {
        Severity::Major
    }

    fn issue_type(&self) -> IssueType {
        IssueType::Bug
    }

    fn metadata(&self) -> yunq_rules_engine::RuleMetadata {
        yunq_rules_engine::RuleMetadata {
            description: "Comparing a floating-point value to a literal with `==`/`!=` is \
                fragile: rounding from prior arithmetic often makes mathematically-equal values \
                compare unequal. Use an epsilon-based comparison instead."
                .into(),
            tags: vec!["reliability".into(), "rust".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter(|n| is_other(n.kind(), "binary_expression"))
            .filter_map(|expr| match expr.children() {
                [left, right] => Some((expr, left, right)),
                _ => None,
            })
            .filter(|(_, left, right)| {
                is_other(left.kind(), "float_literal") || is_other(right.kind(), "float_literal")
            })
            .filter_map(|(expr, left, right)| {
                let op = operator_between(file.content(), left, right);
                (op == "==" || op == "!=").then(|| {
                    Finding::new(
                        format!(
                            "`{}` compares a float to a literal with `{op}`; rounding makes this \
                            fragile — use an epsilon-based comparison instead",
                            expr.text()
                        ),
                        expr.span(),
                    )
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use yunq_ast::SourceFile;
    use yunq_rules_engine::AstParser;

    use super::*;

    fn check(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.rs", code, LanguageIdentifier::rust()).unwrap();
        let ast = yunq_parser_rust::RustParser::new().parse(&file).unwrap();
        FloatLiteralEqRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_variable_equals_float_literal() {
        let findings = check("fn f(x: f64) { if x == 1.0 {} }\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_float_literal_equals_variable() {
        let findings = check("fn f(x: f64) { if 2.0 == x {} }\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_not_equal_too() {
        let findings = check("fn f(x: f64) { if x != 0.0 {} }\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn ignores_integer_literal_comparison() {
        assert!(check("fn f(x: i32) { if x == 1 {} }\n").is_empty());
    }

    #[test]
    fn ignores_non_equality_float_comparison() {
        assert!(check("fn f(x: f64) { if x < 1.0 {} }\n").is_empty());
    }
}
