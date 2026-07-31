use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use yunq_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

use crate::common::{is_other, operator_between};

fn is_literal(kind: &NodeKind) -> bool {
    matches!(kind, NodeKind::StringLiteral)
        || is_other(kind, "integer_literal")
        || is_other(kind, "float_literal")
        || is_other(kind, "boolean_literal")
        || is_other(kind, "char_literal")
}

/// `x == x` (or `x != x`) is always true (or always false) regardless of
/// `x`'s value — bar `NaN`, which is the one case anyone writes this
/// deliberately, and even then `.is_nan()` says what's meant far more
/// clearly. Comparing an expression to a byte-identical copy of itself is
/// otherwise a near-certain sign that one side was meant to reference
/// something else — the classic copy-paste-and-forgot-to-rename bug.
/// Mirrors `clippy::eq_op`.
pub struct SelfComparisonRule {
    id: RuleId,
}

impl SelfComparisonRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("rust:self-comparison").expect("valid rule id"),
        }
    }
}

impl Default for SelfComparisonRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for SelfComparisonRule {
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
            description: "Comparing an expression to a byte-identical copy of itself with \
                `==`/`!=` always evaluates to the same result (barring NaN) — likely one side \
                was meant to reference something else. If this is an intentional NaN check, \
                use `.is_nan()` instead."
                .into(),
            tags: vec!["correctness".into(), "rust".into()],
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
            .filter(|(_, left, _)| !is_literal(left.kind()))
            .filter(|(_, left, right)| left.text().trim() == right.text().trim())
            .filter_map(|(expr, left, right)| {
                let op = operator_between(file.content(), left, right);
                (op == "==" || op == "!=").then(|| {
                    let always = if op == "==" { "true" } else { "false" };
                    Finding::new(
                        format!(
                            "`{}` compares `{}` to itself, which is always {always} outside \
                            NaN; if that's what you meant, use `.is_nan()` instead — otherwise \
                            one side likely should reference something else",
                            expr.text(),
                            left.text()
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
        SelfComparisonRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_identifier_self_equality() {
        let findings = check("fn f(x: i32) { if x == x {} }\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_identifier_self_inequality() {
        let findings = check("fn f(x: i32) { if x != x {} }\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_matching_method_call_expressions() {
        let findings = check("fn f(x: Vec<i32>) { if x.len() == x.len() {} }\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn ignores_different_operands() {
        assert!(check("fn f(x: i32, y: i32) { if x == y {} }\n").is_empty());
    }

    #[test]
    fn ignores_literal_self_comparison() {
        assert!(check("fn f() { if 1 == 1 {} }\n").is_empty());
    }

    #[test]
    fn ignores_non_equality_operators() {
        assert!(check("fn f(x: i32) { if x <= x {} }\n").is_empty());
    }
}
