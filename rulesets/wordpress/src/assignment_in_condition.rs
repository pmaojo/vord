use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{
    Finding, IssueType, Rule, RuleId, RuleMetadata, Severity, declare_rule_id,
};

use crate::common::is_other;

/// `if_statement`/`else_if_clause` — the two conditional shapes where an
/// assignment as the *entire* condition is almost always a typo for `==`/
/// `===`. `while ($row = $wpdb->get_row($q))` is deliberately excluded: an
/// assignment as a `while` condition is the standard PHP "fetch and test in
/// one step" idiom, not a mistake — the same distinction most linters with
/// a "no assignment in condition" check make (e.g. ESLint's `no-cond-assign`
/// defaults to allowing it there). WPCS enforces this indirectly via
/// `WordPress.PHP.YodaConditions` (forcing the literal onto the left of a
/// comparison, so a stray `=` fails to parse instead of silently compiling);
/// this rule flags the actual defect that convention exists to catch,
/// rather than the operand-ordering convention itself.
const CONDITION_STATEMENT_KINDS: &[&str] = &["if_statement", "else_if_clause"];

/// `if_statement`/`else_if_clause`'s condition is its first child, wrapped
/// in a `parenthesized_expression`.
fn condition_expr(stmt: &AstNode) -> Option<&AstNode> {
    let paren = stmt.children().first()?;
    if !is_other(paren.kind(), "parenthesized_expression") {
        return None;
    }
    match paren.children() {
        [inner] => Some(inner),
        _ => None,
    }
}

/// See `rulesets/wordpress/src/unsanitized_input.rs::assignment_value` for
/// why a genuine assignment is the two-child `Assignment` shape.
fn is_genuine_assignment(node: &AstNode) -> bool {
    *node.kind() == NodeKind::Assignment && node.children().len() == 2
}

declare_rule_id!(
    AssignmentInConditionRule,
    "wordpress:assignment-in-condition"
);

impl Rule for AssignmentInConditionRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, language: &LanguageIdentifier) -> bool {
        *language == LanguageIdentifier::php()
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

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "This `if`'s entire condition is a plain `=` assignment rather than a \
                comparison — almost always a typo for `==`/`===` that silently compiles into \
                \"assign, then test the assigned value for truthiness\" instead. Compare with \
                `==`/`===`, or if the assignment is intentional, make that explicit by wrapping \
                it in an extra pair of parentheses."
                .into(),
            tags: vec!["wordpress".into(), "php".into()],
            cwe: Some(481),
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter(|n| {
                CONDITION_STATEMENT_KINDS
                    .iter()
                    .any(|k| is_other(n.kind(), k))
            })
            .filter_map(condition_expr)
            .filter(|cond| is_genuine_assignment(cond))
            .map(|cond| {
                Finding::new(
                    "condition is a plain `=` assignment, not a comparison — likely a typo for \
                    `==`/`===`"
                        .to_string(),
                    cond.span(),
                )
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
        let file = SourceFile::new("t.php", code, LanguageIdentifier::php()).unwrap();
        let ast = vord_parser_php::PhpParser::new().parse(&file).unwrap();
        AssignmentInConditionRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_assignment_in_if_condition() {
        assert_eq!(check("<?php\nif ( $x = 5 ) { }\n").len(), 1);
    }

    #[test]
    fn allows_comparison_in_if_condition() {
        assert!(check("<?php\nif ( $x == 5 ) { }\n").is_empty());
    }

    #[test]
    fn allows_assignment_in_while_condition() {
        assert!(check("<?php\nwhile ( $row = $wpdb->get_row( $q ) ) { }\n").is_empty());
    }

    #[test]
    fn allows_function_call_condition() {
        assert!(check("<?php\nif ( is_admin() ) { }\n").is_empty());
    }
}
