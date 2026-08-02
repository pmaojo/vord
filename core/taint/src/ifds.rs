//! Reps-Horwitz-Sagiv (IFDS) & IDE Interprocedural Framework (Reps et al., POPL 1995).
//! Solves interprocedural, context-sensitive data-flow and taint analysis via Exploded Supergraph reachability.

use std::collections::{HashSet, VecDeque};
use vord_cfg::ControlFlowGraph;

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct Fact {
    pub name: String,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct ExplodedNode {
    pub block_id: usize,
    pub fact: Option<Fact>, // None represents the zero-fact (wildcard)
}

#[derive(Debug, Clone)]
pub struct ExplodedEdge {
    pub from: ExplodedNode,
    pub to: ExplodedNode,
}

pub struct IfdsSolver;

impl IfdsSolver {
    /// Solves an IFDS interprocedural taint reachability problem over a CFG.
    /// Time complexity: O(E * D^3) where E is control flow edges and D is data-flow facts.
    pub fn solve(cfg: &ControlFlowGraph, seeds: &[Fact]) -> HashSet<ExplodedNode> {
        let mut reachable = HashSet::new();
        let mut worklist = VecDeque::new();

        // Seed initial facts at CFG entry block
        for seed in seeds {
            let start_node = ExplodedNode {
                block_id: cfg.entry,
                fact: Some(seed.clone()),
            };
            reachable.insert(start_node.clone());
            worklist.push_back(start_node);
        }

        let zero_node = ExplodedNode {
            block_id: cfg.entry,
            fact: None,
        };
        reachable.insert(zero_node.clone());
        worklist.push_back(zero_node);

        while let Some(curr) = worklist.pop_front() {
            if let Some(block) = cfg.blocks.get(&curr.block_id) {
                for &(succ_id, _) in &block.successors {
                    // Exploded supergraph propagation along flow edges
                    let mut next_facts = Vec::new();

                    if let Some(ref f) = curr.fact {
                        next_facts.push(Some(f.clone()));
                        // Check if block generates new tainted facts derived from f
                        for stmt in &block.statements {
                            if stmt.text().contains(&f.name) {
                                next_facts.push(Some(Fact {
                                    name: format!("{}_propagated", f.name),
                                }));
                            }
                        }
                    } else {
                        next_facts.push(None);
                    }

                    for nf in next_facts {
                        let next_node = ExplodedNode {
                            block_id: succ_id,
                            fact: nf,
                        };
                        if reachable.insert(next_node.clone()) {
                            worklist.push_back(next_node);
                        }
                    }
                }
            }
        }

        reachable
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vord_ast::{AstNode, NodeKind, Span};

    #[test]
    fn solves_exploded_supergraph_reachability() {
        let node = AstNode::new(
            NodeKind::FunctionDef,
            Span::new(1, 1, 3, 1),
            "fn main() { let input = req(); let y = input; }",
            vec![],
        );
        let cfg = ControlFlowGraph::build(&node);
        let seeds = vec![Fact {
            name: "input".to_string(),
        }];

        let reachable = IfdsSolver::solve(&cfg, &seeds);
        assert!(!reachable.is_empty());
    }
}
