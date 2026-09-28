//! Per-function cyclomatic complexity, computed once per parsed file
//! alongside `structural_metrics` so CRAP (`vord-crap`, joined with per-line
//! coverage at the composition root once both exist on an `AnalysisReport`)
//! never needs a second parse of the same AST. Extracted from
//! `rulesets/code-smells::ComplexityRule`, which now calls [`compute`]
//! instead of keeping its own copy of the walk.

use vord_ast::{AstNode, NodeKind, Span};

/// Grammar node kinds (per tree-sitter grammar) that add a decision point,
/// grouped by what kind of bookkeeping they represent — see
/// [`ComplexityBreakdown`]. A flat total can't distinguish a function whose
/// complexity comes from a single arithmetic-heavy loop (mechanically busy)
/// from one with the same number tied up in nested conditionals
/// (conceptually tangled); the category split is what lets a caller tell
/// those apart.
const CONDITIONAL_KINDS: &[&str] = &[
    "if_statement",
    "if_expression",
    "elif_clause",
    "match_arm",
    "case_clause",
    "switch_case",
    "expression_case",
    "conditional_expression",
    "ternary_expression",
    "boolean_operator",
    "switch_label",     // Groovy's per-case switch marker
    "elseif_statement", // Lua's `elseif` (no wrapping `elif_clause` node)
];

const LOOP_KINDS: &[&str] = &[
    "while_statement",
    "while_expression",
    "for_statement",
    "for_expression",
    "for_in_statement",
    "loop_expression",
    "enhanced_for_statement", // Groovy/Java-family for-each
    "repeat_statement",       // Lua's `repeat ... until`
];

const EXCEPTION_KINDS: &[&str] = &["catch_clause", "except_clause"];

/// Cyclomatic complexity's decision-point total, split by the kind of
/// control structure each point came from. `branches + loops + exceptions`
/// equals `cyclomatic - 1` (the flat entry-point term).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ComplexityBreakdown {
    /// `if`/`else if`/`match`/`switch`/ternary/short-circuit branches —
    /// the "tangled conditional logic" component.
    pub branches: u32,
    /// `for`/`while`/`loop` headers — one point regardless of how much
    /// arithmetic or bookkeeping the loop body itself performs.
    pub loops: u32,
    /// `catch`/`except` clauses.
    pub exceptions: u32,
}

impl ComplexityBreakdown {
    pub fn total(&self) -> u32 {
        self.branches + self.loops + self.exceptions
    }

    fn add(&mut self, other: ComplexityBreakdown) {
        self.branches += other.branches;
        self.loops += other.loops;
        self.exceptions += other.exceptions;
    }
}

/// One function's cyclomatic complexity and source span. `cyclomatic` is
/// `1 + decision points in the body`, excluding nested functions (they are
/// measured on their own).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FunctionComplexity {
    pub span: Span,
    pub cyclomatic: u32,
    pub breakdown: ComplexityBreakdown,
}

fn decision_points(node: &AstNode) -> ComplexityBreakdown {
    let mut total = ComplexityBreakdown::default();
    for child in node.children() {
        // Nested functions are rated independently.
        if *child.kind() == NodeKind::FunctionDef {
            continue;
        }
        if let NodeKind::Other(kind) = child.kind() {
            let kind = kind.as_ref();
            if CONDITIONAL_KINDS.contains(&kind) {
                total.branches += 1;
            } else if LOOP_KINDS.contains(&kind) {
                total.loops += 1;
            } else if EXCEPTION_KINDS.contains(&kind) {
                total.exceptions += 1;
            }
        }
        total.add(decision_points(child));
    }
    total
}

/// Walks `ast` once, returning every function's cyclomatic complexity.
pub fn compute(ast: &AstNode) -> Vec<FunctionComplexity> {
    ast.descendants()
        .filter(|n| *n.kind() == NodeKind::FunctionDef)
        .map(|function| {
            let breakdown = decision_points(function);
            FunctionComplexity {
                span: function.span(),
                cyclomatic: 1 + breakdown.total(),
                breakdown,
            }
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

    #[test]
    fn breakdown_categorizes_decision_points_by_kind() {
        let other = |kind: &str, line: u32| {
            AstNode::new(
                NodeKind::Other(vord_ast::intern(kind)),
                Span::new(line, 1, line, 2),
                "",
                vec![],
            )
        };
        let body = vec![
            other("if_statement", 2),
            other("if_statement", 3),
            other("while_statement", 4),
            other("catch_clause", 5),
        ];
        let function = AstNode::new(NodeKind::FunctionDef, Span::new(1, 1, 6, 1), "", body);

        let results = compute(&function);
        assert_eq!(results.len(), 1);
        let fc = results[0];
        assert_eq!(fc.breakdown.branches, 2);
        assert_eq!(fc.breakdown.loops, 1);
        assert_eq!(fc.breakdown.exceptions, 1);
        assert_eq!(fc.breakdown.total(), 4);
        assert_eq!(fc.cyclomatic, 5);
    }
}
