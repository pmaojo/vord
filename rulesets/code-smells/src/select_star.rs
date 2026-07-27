//! Rule: flags SQL string literals using `SELECT *` instead of naming columns.

use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use yunq_rules_engine::{Finding, Rule, RuleId, Severity};

fn contains_select_star(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower
        .match_indices("select")
        .any(|(idx, _)| lower[idx + "select".len()..].trim_start().starts_with('*'))
}

pub struct SelectStarRule {
    id: RuleId,
}

impl SelectStarRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("smells:select-star").expect("valid rule id"),
        }
    }
}

impl Default for SelectStarRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for SelectStarRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, _language: &LanguageIdentifier) -> bool {
        true
    }

    fn default_severity(&self) -> Severity {
        Severity::Minor
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        if yunq_rules_engine::is_test_only_path(file.path()) {
            return Vec::new();
        }
        let test_ranges = yunq_rules_engine::rust_test_module_ranges(file.content());

        ast.descendants()
            .filter(|n| *n.kind() == NodeKind::StringLiteral)
            .filter(|literal| {
                !yunq_rules_engine::in_ranges(&test_ranges, literal.span().start_line)
            })
            .filter(|literal| contains_select_star(literal.text()))
            .map(|literal| {
                Finding::new(
                    "query selects every column with `*`; name the columns you actually need",
                    literal.span(),
                )
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn string_literal(text: &str) -> AstNode {
        AstNode::new(
            NodeKind::StringLiteral,
            yunq_ast::Span::new(1, 1, 1, text.len() as u32),
            text,
            vec![],
        )
    }

    #[test]
    fn flags_select_star_query() {
        let ast = string_literal("\"SELECT * FROM users WHERE id = ?\"");
        let findings = SelectStarRule::new().check(
            &SourceFile::new("t.ts", "", LanguageIdentifier::typescript()).unwrap(),
            &ast,
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn allows_explicit_columns() {
        let ast = string_literal("\"SELECT id, name FROM users WHERE id = ?\"");
        let findings = SelectStarRule::new().check(
            &SourceFile::new("t.ts", "", LanguageIdentifier::typescript()).unwrap(),
            &ast,
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn allows_star_that_is_not_select() {
        let ast = string_literal("\"total = price * quantity\"");
        let findings = SelectStarRule::new().check(
            &SourceFile::new("t.ts", "", LanguageIdentifier::typescript()).unwrap(),
            &ast,
        );
        assert!(findings.is_empty());
    }
}
