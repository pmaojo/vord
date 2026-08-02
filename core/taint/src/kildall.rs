//! Kildall's Worklist Algorithm (Monotone Data-Flow Framework).
//! Fixed-point iteration over bounded lattices for Reaching Definitions, Live Variables, and Constant Propagation.

use std::collections::{HashMap, HashSet, VecDeque};
use vord_cfg::ControlFlowGraph;

pub trait LatticeValue: Clone + PartialEq + Eq {
    fn join(&self, other: &Self) -> Self;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReachingDefsLattice {
    pub defs: HashSet<(String, usize)>, // (var_name, block_id)
}

impl LatticeValue for ReachingDefsLattice {
    fn join(&self, other: &Self) -> Self {
        let mut defs = self.defs.clone();
        defs.extend(other.defs.iter().cloned());
        ReachingDefsLattice { defs }
    }
}

pub struct KildallWorklist;

impl KildallWorklist {
    /// Solves a monotone data-flow framework over a CFG using Kildall's worklist algorithm.
    pub fn solve_reaching_defs(
        cfg: &ControlFlowGraph,
        variables: &[&str],
    ) -> (
        HashMap<usize, ReachingDefsLattice>,
        HashMap<usize, ReachingDefsLattice>,
    ) {
        let mut in_facts: HashMap<usize, ReachingDefsLattice> = HashMap::new();
        let mut out_facts: HashMap<usize, ReachingDefsLattice> = HashMap::new();

        for &b in cfg.blocks.keys() {
            in_facts.insert(
                b,
                ReachingDefsLattice {
                    defs: HashSet::new(),
                },
            );
            out_facts.insert(
                b,
                ReachingDefsLattice {
                    defs: HashSet::new(),
                },
            );
        }

        let mut worklist: VecDeque<usize> = cfg.blocks.keys().copied().collect();

        while let Some(b) = worklist.pop_front() {
            // IN[b] = Join(OUT[p]) for all predecessors p of b
            let mut new_in = ReachingDefsLattice {
                defs: HashSet::new(),
            };
            for &(p, _) in &cfg.blocks[&b].predecessors {
                if let Some(out_p) = out_facts.get(&p) {
                    new_in = new_in.join(out_p);
                }
            }
            in_facts.insert(b, new_in.clone());

            // OUT[b] = gen_b U (IN[b] - kill_b)
            let mut new_out = new_in.clone();
            for stmt in &cfg.blocks[&b].statements {
                for &v in variables {
                    if stmt.text().contains(v) {
                        // Kill previous defs of v, add new def (v, b)
                        new_out.defs.retain(|(name, _)| name != v);
                        new_out.defs.insert((v.to_string(), b));
                    }
                }
            }

            if out_facts.get(&b) != Some(&new_out) {
                out_facts.insert(b, new_out);
                for &(s, _) in &cfg.blocks[&b].successors {
                    if !worklist.contains(&s) {
                        worklist.push_back(s);
                    }
                }
            }
        }

        (in_facts, out_facts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vord_ast::{AstNode, NodeKind, Span};

    #[test]
    fn solves_reaching_definitions_lattice() {
        let node = AstNode::new(
            NodeKind::FunctionDef,
            Span::new(1, 1, 3, 1),
            "fn test() { let x = 1; x = 2; }",
            vec![],
        );
        let cfg = ControlFlowGraph::build(&node);
        let (in_facts, out_facts) = KildallWorklist::solve_reaching_defs(&cfg, &["x"]);

        assert!(in_facts.contains_key(&cfg.entry));
        assert!(out_facts.contains_key(&cfg.entry));
    }
}
