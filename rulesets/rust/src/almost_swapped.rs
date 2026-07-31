use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use yunq_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

use crate::common::is_other;

/// The `Assignment` an `expression_statement` wraps, if it wraps exactly one.
fn assignment_of(stmt: &AstNode) -> Option<&AstNode> {
    if !is_other(stmt.kind(), "expression_statement") {
        return None;
    }
    let child = stmt.first_child()?;
    (*child.kind() == NodeKind::Assignment && child.children().len() == 2).then_some(child)
}

/// `a = b; b = a;` back-to-back overwrites `a` with `b` and then `b` with the
/// *new* `a` (which is just `b` again) — the original value of `a` is lost.
/// A real swap needs a temporary: `let tmp = a; a = b; b = tmp;`.
pub struct AlmostSwappedRule {
    id: RuleId,
}

impl AlmostSwappedRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("rust:almost-swapped").expect("valid rule id"),
        }
    }
}

impl Default for AlmostSwappedRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for AlmostSwappedRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, language: &LanguageIdentifier) -> bool {
        *language == LanguageIdentifier::rust()
    }

    fn default_severity(&self) -> Severity {
        Severity::Critical
    }

    fn issue_type(&self) -> IssueType {
        IssueType::Bug
    }

    fn remediation_effort_minutes(&self) -> u32 {
        5
    }

    fn metadata(&self) -> yunq_rules_engine::RuleMetadata {
        yunq_rules_engine::RuleMetadata {
            description: "`a = b; b = a;` does not swap the two values: by the time the second \
                assignment runs, `a` already holds `b`'s old value, so `b` ends up with a copy \
                of itself and `a`'s original value is lost. Use a temporary, or \
                `std::mem::swap`/tuple destructuring."
                .into(),
            tags: vec!["bug".into(), "rust".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter(|n| is_other(n.kind(), "block"))
            .flat_map(|block| {
                block.children().windows(2).filter_map(|pair| {
                    let first = assignment_of(&pair[0])?;
                    let second = assignment_of(&pair[1])?;
                    let (lhs1, rhs1) = (&first.children()[0], &first.children()[1]);
                    let (lhs2, rhs2) = (&second.children()[0], &second.children()[1]);
                    if lhs1.text() != rhs1.text()
                        && lhs1.text() == rhs2.text()
                        && rhs1.text() == lhs2.text()
                    {
                        Some(Finding::new(
                            format!(
                                "`{} = {}; {} = {};` does not swap the values — `{}`'s original \
                                value is lost; use a temporary or `std::mem::swap`",
                                lhs1.text(),
                                rhs1.text(),
                                lhs2.text(),
                                rhs2.text(),
                                lhs1.text()
                            ),
                            first.span(),
                        ))
                    } else {
                        None
                    }
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
        AlmostSwappedRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_almost_swapped_locals() {
        let findings = check("fn f(mut a: i32, mut b: i32) { a = b; b = a; }\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_almost_swapped_deref() {
        let findings = check("fn f(a: &mut i32, b: &mut i32) { *a = *b; *b = *a; }\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn ignores_real_swap_with_temp() {
        assert!(
            check("fn f(mut a: i32, mut b: i32) { let tmp = a; a = b; b = tmp; }\n").is_empty()
        );
    }

    #[test]
    fn ignores_mem_swap() {
        assert!(
            check("fn f(mut a: i32, mut b: i32) { std::mem::swap(&mut a, &mut b); }\n").is_empty()
        );
    }

    #[test]
    fn ignores_non_adjacent_assignments() {
        assert!(
            check("fn f(mut a: i32, mut b: i32, mut c: i32) { a = b; c = 1; b = a; }\n").is_empty()
        );
    }

    #[test]
    fn ignores_unrelated_assignments() {
        assert!(check("fn f(mut a: i32, mut b: i32, mut c: i32) { a = b; c = a; }\n").is_empty());
    }
}
