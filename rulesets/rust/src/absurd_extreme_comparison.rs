use std::collections::HashSet;

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

use crate::common::{is_other, operator_between};

const UNSIGNED_TYPES: &[&str] = &["u8", "u16", "u32", "u64", "u128", "usize"];

/// The names of `fn`'s parameters declared with an unsigned primitive type
/// (`u8`..`usize`) — comparing one of these against `0` with `<`/`>=` is a
/// tautology, since an unsigned value can never be negative.
fn unsigned_params(func: &AstNode) -> HashSet<&str> {
    let Some(params) = func
        .children()
        .iter()
        .find(|c| is_other(c.kind(), "parameters"))
    else {
        return HashSet::new();
    };
    params
        .children()
        .iter()
        .filter(|c| is_other(c.kind(), "parameter"))
        .filter_map(|p| {
            let ident = p
                .children()
                .iter()
                .find(|c| *c.kind() == NodeKind::Identifier)?;
            let ty = p
                .children()
                .iter()
                .find(|c| is_other(c.kind(), "primitive_type"))?;
            UNSIGNED_TYPES.contains(&ty.text()).then_some(ident.text())
        })
        .collect()
}

/// Whether `left OP right` is an always-false or always-true comparison
/// given that `unsigned` names an unsigned local, returning the explanatory
/// message if so.
fn absurd_message(
    unsigned: &HashSet<&str>,
    left: &AstNode,
    right: &AstNode,
    op: &str,
) -> Option<String> {
    if unsigned.contains(left.text()) && right.text() == "0" {
        return match op {
            "<" => Some(format!(
                "`{} < 0` is always false: `{}` is unsigned and can never be negative",
                left.text(),
                left.text()
            )),
            ">=" => Some(format!(
                "`{} >= 0` is always true: `{}` is unsigned and can never be negative",
                left.text(),
                left.text()
            )),
            _ => None,
        };
    }
    if unsigned.contains(right.text()) && left.text() == "0" {
        return match op {
            ">" => Some(format!(
                "`0 > {}` is always false: `{}` is unsigned and can never be negative",
                right.text(),
                right.text()
            )),
            "<=" => Some(format!(
                "`0 <= {}` is always true: `{}` is unsigned and can never be negative",
                right.text(),
                right.text()
            )),
            _ => None,
        };
    }
    None
}

/// Comparing an unsigned integer against `0` with `<`/`>=` (or the mirrored
/// `>`/`<=`) is always false or always true — the type system already
/// guarantees the result, so the comparison is either dead code or a sign of
/// a type that should not be unsigned.
pub struct AbsurdExtremeComparisonRule {
    id: RuleId,
}

impl AbsurdExtremeComparisonRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("rust:absurd-extreme-comparison").expect("valid rule id"),
        }
    }
}

impl Default for AbsurdExtremeComparisonRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for AbsurdExtremeComparisonRule {
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

    fn remediation_effort_minutes(&self) -> u32 {
        5
    }

    fn metadata(&self) -> vord_rules_engine::RuleMetadata {
        vord_rules_engine::RuleMetadata {
            description: "Comparing an unsigned integer against `0` with `<`, `>=`, `>`, or `<=` \
                is always false or always true, since an unsigned value can never be negative."
                .into(),
            tags: vec!["bug".into(), "rust".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        let test_ranges = vord_rules_engine::rust_test_module_ranges(file.content());

        ast.descendants()
            .filter(|n| *n.kind() == NodeKind::FunctionDef)
            .flat_map(|func| {
                let unsigned = unsigned_params(func);
                func.descendants()
                    .filter(|n| is_other(n.kind(), "binary_expression") && n.children().len() == 2)
                    .filter_map(|n| {
                        if vord_rules_engine::in_ranges(&test_ranges, n.span().start_line) {
                            return None;
                        }
                        let (left, right) = (&n.children()[0], &n.children()[1]);
                        let op = operator_between(file.content(), left, right);
                        absurd_message(&unsigned, left, right, op)
                            .map(|msg| Finding::new(msg, n.span()))
                    })
                    .collect::<Vec<_>>()
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use vord_ast::SourceFile;
    use vord_rules_engine::AstParser;

    use super::*;

    fn check(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.rs", code, LanguageIdentifier::rust()).unwrap();
        let ast = vord_parser_rust::RustParser::new().parse(&file).unwrap();
        AbsurdExtremeComparisonRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_unsigned_less_than_zero() {
        let findings = check("fn f(x: u32) { if x < 0 { } }\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_zero_greater_than_unsigned() {
        let findings = check("fn f(x: usize) { if 0 > x { } }\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_unsigned_greater_equal_zero_tautology() {
        let findings = check("fn f(x: u8) { if x >= 0 { } }\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn ignores_signed_comparison() {
        assert!(check("fn f(x: i32) { if x < 0 { } }\n").is_empty());
    }

    #[test]
    fn ignores_unsigned_compared_to_nonzero() {
        assert!(check("fn f(x: u32) { if x < 10 { } }\n").is_empty());
    }

    #[test]
    fn ignores_unsigned_compared_to_other_var() {
        assert!(check("fn f(x: u32, y: u32) { if x < y { } }\n").is_empty());
    }

    #[test]
    fn ignores_absurd_comparison_inside_a_cfg_test_module() {
        let code = "fn prod() {}\n\n#[cfg(test)]\nmod tests {\n    fn t(x: u32) {\n        if x < 0 { }\n    }\n}\n";
        assert!(check(code).is_empty());
    }
}
