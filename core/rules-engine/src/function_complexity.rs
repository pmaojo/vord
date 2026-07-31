//! Per-function cyclomatic complexity, computed once per parsed file
//! alongside `structural_metrics` so CRAP (`yunq-crap`, joined with per-line
//! coverage at the composition root once both exist on an `AnalysisReport`)
//! never needs a second parse of the same AST. Extracted from
//! `rulesets/code-smells::ComplexityRule`, which now calls [`compute`]
//! instead of keeping its own copy of the walk.

use yunq_ast::{AstNode, NodeKind, Span};

/// Grammar node kinds (per tree-sitter grammar) that add a decision point.
const BRANCH_KINDS: &[&str] = &[
    "if_statement",
    "if_expression",
    "elif_clause",
    "while_statement",
    "while_expression",
    "for_statement",
    "for_expression",
    "for_in_statement",
    "loop_expression",
    "match_arm",
    "case_clause",
    "switch_case",
    "expression_case",
    "catch_clause",
    "except_clause",
    "conditional_expression",
    "ternary_expression",
    "boolean_operator",
    "enhanced_for_statement", // Groovy/Java-family for-each
    "switch_label",           // Groovy's per-case switch marker
    "repeat_statement",       // Lua's `repeat ... until`
    "elseif_statement",       // Lua's `elseif` (no wrapping `elif_clause` node)
];

/// One function's cyclomatic complexity and source span. `cyclomatic` is
/// `1 + decision points in the body`, excluding nested functions (they are
/// measured on their own).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FunctionComplexity {
    pub span: Span,
    pub cyclomatic: u32,
}

fn decision_points(node: &AstNode) -> u32 {
    node.children()
        .iter()
        .map(|child| {
            // Nested functions are rated independently.
            if *child.kind() == NodeKind::FunctionDef {
                return 0;
            }
            let own = match child.kind() {
                NodeKind::Other(kind) if BRANCH_KINDS.contains(&kind.as_ref()) => 1,
                _ => 0,
            };
            own + decision_points(child)
        })
        .sum()
}

/// Walks `ast` once, returning every function's cyclomatic complexity.
pub fn compute(ast: &AstNode) -> Vec<FunctionComplexity> {
    ast.descendants()
        .filter(|n| *n.kind() == NodeKind::FunctionDef)
        .map(|function| FunctionComplexity {
            span: function.span(),
            cyclomatic: 1 + decision_points(function),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nested_functions_do_not_inflate_the_parent() {
        let leaf = AstNode::new(NodeKind::FunctionDef, Span::new(2, 1, 2, 20), "", vec![]);
        let root = AstNode::new(
            NodeKind::FunctionDef,
            Span::new(1, 1, 3, 1),
            "",
            vec![leaf.clone()],
        );
        let results = compute(&root);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].cyclomatic, 1);
        assert_eq!(results[1].cyclomatic, 1);
    }
}
