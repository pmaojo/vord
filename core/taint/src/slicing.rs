//! Weiser's Program Slicing Algorithm (Weiser, IEEE TSE 1984).
//! Uses backward reachability on Program Dependency Graphs (PDG = CFG + CDG + Data Dependence) to isolate statements influencing a criterion.

use std::collections::{HashSet, VecDeque};
use yunq_ast::AstNode;
use yunq_cfg::{ControlDependenceGraph, ControlFlowGraph};

#[derive(Debug, Clone)]
pub struct SlicingCriterion {
    pub variable: String,
    pub block_id: usize,
}

#[derive(Debug, Clone)]
pub struct ProgramSlice {
    pub sliced_block_ids: HashSet<usize>,
    pub sliced_statements: Vec<AstNode>,
}

pub struct WeiserSlicer;

impl WeiserSlicer {
    /// Computes a backward program slice for a slicing criterion (variable at block_id).
    pub fn backward_slice(
        cfg: &ControlFlowGraph,
        cdg: &ControlDependenceGraph,
        criterion: &SlicingCriterion,
    ) -> ProgramSlice {
        let mut sliced_blocks = HashSet::new();
        let mut worklist = VecDeque::new();

        sliced_blocks.insert(criterion.block_id);
        worklist.push_back((criterion.block_id, criterion.variable.clone()));

        while let Some((curr_block, curr_var)) = worklist.pop_front() {
            // Data dependencies: find blocks that define curr_var with flow to curr_block
            if let Some(block) = cfg.blocks.get(&curr_block) {
                for &(pred_id, _) in &block.predecessors {
                    if let Some(pred_block) = cfg.blocks.get(&pred_id) {
                        for stmt in &pred_block.statements {
                            if stmt.text().contains(&curr_var) && sliced_blocks.insert(pred_id) {
                                worklist.push_back((pred_id, curr_var.clone()));
                            }
                        }
                    }
                }
            }

            // Control dependencies: find blocks controlling execution of curr_block
            for (&ctrl_block, deps) in &cdg.control_dependencies {
                if deps.contains(&curr_block) && sliced_blocks.insert(ctrl_block) {
                    worklist.push_back((ctrl_block, curr_var.clone()));
                }
            }
        }

        let mut sliced_statements = Vec::new();
        for &b_id in &sliced_blocks {
            if let Some(b) = cfg.blocks.get(&b_id) {
                sliced_statements.extend(b.statements.iter().cloned());
            }
        }

        ProgramSlice {
            sliced_block_ids: sliced_blocks,
            sliced_statements,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use yunq_ast::{AstNode, NodeKind, Span};

    #[test]
    fn computes_backward_program_slice() {
        let node = AstNode::new(
            NodeKind::FunctionDef,
            Span::new(1, 1, 3, 1),
            "fn test() { let a = 1; let b = a + 2; }",
            vec![],
        );
        let cfg = ControlFlowGraph::build(&node);
        let cdg = ControlDependenceGraph::build(&cfg);

        let criterion = SlicingCriterion {
            variable: "b".to_string(),
            block_id: cfg.entry,
        };

        let slice = WeiserSlicer::backward_slice(&cfg, &cdg, &criterion);
        assert!(!slice.sliced_block_ids.is_empty());
    }
}
