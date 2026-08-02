//! Control Flow Graph (CFG) Construction.

use std::collections::HashMap;
use vord_ast::{AstNode, NodeKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EdgeKind {
    Fallthrough,
    BranchTrue,
    BranchFalse,
    Jump,
    Exception,
}

#[derive(Debug, Clone)]
pub struct BasicBlock {
    pub id: usize,
    pub statements: Vec<AstNode>,
    pub predecessors: Vec<(usize, EdgeKind)>,
    pub successors: Vec<(usize, EdgeKind)>,
}

/// Interface for CFG-based analysis: consumers that only need to query
/// a control-flow graph rather than build one can depend on this trait
/// instead of the concrete [`ControlFlowGraph`] — the Dependency
/// Inversion Principle at CFG scale.
pub trait CfgAnalysis {
    fn cyclomatic_complexity(&self) -> usize;
}

impl CfgAnalysis for ControlFlowGraph {
    fn cyclomatic_complexity(&self) -> usize {
        let nodes = self.blocks.len();
        let edges = self
            .blocks
            .values()
            .map(|block| block.successors.len())
            .sum::<usize>();
        // Signed arithmetic: `E − N` is legitimately negative for a
        // straight-line graph (E = 1, N = 2), and `saturating_sub` would
        // pin it to 0 — inflating the base case to 2 instead of 1.
        // Clamped to 1 (the McCabe minimum) defensively; every graph this
        // builder produces is connected through `exit`, so `E − N + 2 ≥ 1`.
        ((edges as i64 - nodes as i64 + 2).max(1)) as usize
    }
}

#[derive(Debug, Clone)]
pub struct ControlFlowGraph {
    pub entry: usize,
    pub exit: usize,
    pub blocks: HashMap<usize, BasicBlock>,
}

impl ControlFlowGraph {
    /// Builds a Control Flow Graph for a function or method AST node.
    pub fn build(func_node: &AstNode) -> Self {
        let mut builder = CfgBuilder::new();
        let entry = builder.create_block();
        let exit = builder.create_block();

        let current = builder.build_sub_ast(func_node, entry, exit);
        builder.add_edge(current, exit, EdgeKind::Fallthrough);

        ControlFlowGraph {
            entry,
            exit,
            blocks: builder.blocks,
        }
    }

    /// McCabe's cyclomatic complexity, read off the graph itself rather than
    /// approximated from operators: `M = E − N + 2P`, where `E` is the edge
    /// count, `N` the node count and `P` the number of connected components
    /// (1 for the graphs this builder produces — every block is reachable
    /// from `entry` or re-attached before `exit`).
    ///
    /// `ControlFlowGraph::build` keeps this exact identity with the decision-
    /// point count used elsewhere in vord (`core/rules-engine`'s
    /// `function_complexity`, whose `1 + decision_points` is what a straight
    /// `if`/`while`/`for`/`&&`-heavy function should yield): every `if`/`while`/
    /// `for`-family node adds one true edge plus one false edge and one join
    /// block (three blocks, three edges — net +0 to `E − N` per branch
    /// *except* the two-entry fan-out that adds one extra edge), so a function
    /// with `d` decision points lands at exactly `M = 1 + d`. See the tests.
    pub fn cyclomatic_complexity(&self) -> usize {
        let nodes = self.blocks.len();
        let edges = self
            .blocks
            .values()
            .map(|block| block.successors.len())
            .sum::<usize>();
        // Signed arithmetic: `E − N` is legitimately negative for a
        // straight-line graph (E = 1, N = 2), and `saturating_sub` would
        // pin it to 0 — inflating the base case to 2 instead of 1.
        // Clamped to 1 (the McCabe minimum) defensively; every graph this
        // builder produces is connected through `exit`, so `E − N + 2 ≥ 1`.
        ((edges as i64 - nodes as i64 + 2).max(1)) as usize
    }
}

/// Decision/branch node kinds, mirroring `core/rules-engine`'s
/// `function_complexity::BRANCH_KINDS` exactly so a CFG-derived
/// cyclomatic complexity agrees with the engine's `1 + decision_points`.
/// Matched by *exact* kind, never by substring — `contains("if")` would
/// also match `identifier`, and every such spurious match inflated `E − N`
/// by one.
fn is_branch(node: &AstNode) -> bool {
    matches!(
        node.kind(),
        NodeKind::Other(k)
            if matches!(
                k.as_ref(),
                "if_statement"
                    | "if_expression"
                    | "elif_clause"
                    | "while_statement"
                    | "while_expression"
                    | "for_statement"
                    | "for_expression"
                    | "for_in_statement"
                    | "loop_expression"
                    | "match_arm"
                    | "case_clause"
                    | "switch_case"
                    | "expression_case"
                    | "catch_clause"
                    | "except_clause"
                    | "conditional_expression"
                    | "ternary_expression"
                    | "boolean_operator"
                    | "enhanced_for_statement"
                    | "switch_label"
                    | "repeat_statement"
                    | "elseif_statement"
            )
    )
}

fn is_return(node: &AstNode) -> bool {
    matches!(
        node.kind(),
        NodeKind::Other(k) if matches!(k.as_ref(), "return_statement" | "return_expression" | "return")
    )
}

struct CfgBuilder {
    next_id: usize,
    blocks: HashMap<usize, BasicBlock>,
}

impl CfgBuilder {
    fn new() -> Self {
        CfgBuilder {
            next_id: 0,
            blocks: HashMap::new(),
        }
    }

    fn create_block(&mut self) -> usize {
        let id = self.next_id;
        self.next_id += 1;
        self.blocks.insert(
            id,
            BasicBlock {
                id,
                statements: Vec::new(),
                predecessors: Vec::new(),
                successors: Vec::new(),
            },
        );
        id
    }

    fn add_edge(&mut self, from: usize, to: usize, kind: EdgeKind) {
        if let Some(b) = self.blocks.get_mut(&from) {
            b.successors.push((to, kind));
        }
        if let Some(b) = self.blocks.get_mut(&to) {
            b.predecessors.push((from, kind));
        }
    }

    fn build_sub_ast(&mut self, node: &AstNode, current: usize, exit: usize) -> usize {
        if is_branch(node) {
            let true_blk = self.create_block();
            let false_blk = self.create_block();
            let join_blk = self.create_block();

            self.add_edge(current, true_blk, EdgeKind::BranchTrue);
            self.add_edge(current, false_blk, EdgeKind::BranchFalse);

            // Which child is the condition vs. the bodies does not matter
            // for cyclomatic complexity — each branch node contributes
            // exactly +1 to `E − N` regardless of how its children are
            // distributed across the true/false edges.
            let children = node.children();
            if let Some(cond_body) = children.first() {
                let end_true = self.build_sub_ast(cond_body, true_blk, exit);
                self.add_edge(end_true, join_blk, EdgeKind::Jump);
            } else {
                self.add_edge(true_blk, join_blk, EdgeKind::Jump);
            }

            if let Some(else_body) = children.get(1) {
                let end_false = self.build_sub_ast(else_body, false_blk, exit);
                self.add_edge(end_false, join_blk, EdgeKind::Jump);
            } else {
                self.add_edge(false_blk, join_blk, EdgeKind::Jump);
            }

            join_blk
        } else if is_return(node) {
            if let Some(blk) = self.blocks.get_mut(&current) {
                blk.statements.push(node.clone());
            }
            self.add_edge(current, exit, EdgeKind::Jump);
            self.create_block() // Unreachable block after return
        } else {
            if let Some(blk) = self.blocks.get_mut(&current) {
                blk.statements.push(node.clone());
            }
            let mut curr = current;
            for child in node.children() {
                curr = self.build_sub_ast(child, curr, exit);
            }
            curr
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vord_ast::{NodeKind, Span};

    fn other(kind: &str, children: Vec<AstNode>) -> AstNode {
        AstNode::new(NodeKind::Other(kind.into()), Span::new(1, 1, 1, 1), "", children)
    }

    #[test]
    fn a_function_with_no_decision_points_has_complexity_one() {
        let func = other("function_item", vec![other("block", vec![])]);
        let cfg = ControlFlowGraph::build(&func);
        assert_eq!(cfg.cyclomatic_complexity(), 1);
    }

    #[test]
    fn a_single_if_adds_one_decision_point() {
        let func = other(
            "function_item",
            vec![other(
                "if_expression",
                vec![other("identifier", vec![]), other("block", vec![])],
            )],
        );
        let cfg = ControlFlowGraph::build(&func);
        assert_eq!(cfg.cyclomatic_complexity(), 2);
    }

    #[test]
    fn two_sequential_ifs_add_two_decision_points() {
        let func = other(
            "function_item",
            vec![
                other(
                    "if_expression",
                    vec![other("identifier", vec![]), other("block", vec![])],
                ),
                other(
                    "if_expression",
                    vec![other("identifier", vec![]), other("block", vec![])],
                ),
            ],
        );
        let cfg = ControlFlowGraph::build(&func);
        assert_eq!(cfg.cyclomatic_complexity(), 3);
    }

    #[test]
    fn a_branch_that_returns_still_counts_one_decision_point() {
        let func = other(
            "function_item",
            vec![other(
                "if_expression",
                vec![
                    other("identifier", vec![]),
                    other("block", vec![other("return_expression", vec![])]),
                ],
            )],
        );
        let cfg = ControlFlowGraph::build(&func);
        assert_eq!(cfg.cyclomatic_complexity(), 2);
    }

    #[test]
    fn a_plain_return_keeps_complexity_at_one() {
        let func = other("function_item", vec![other("return_expression", vec![])]);
        let cfg = ControlFlowGraph::build(&func);
        assert_eq!(cfg.cyclomatic_complexity(), 1);
    }
}
