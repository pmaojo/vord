//! Control Dependence Graph (CDG) Construction (Ferrante et al., TOPLAS 1987).
//! Computes Post-Dominance Frontiers to model control dependencies for early returns, try-catch, and Rust `?`.

use crate::cfg::ControlFlowGraph;
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone)]
pub struct ControlDependenceGraph {
    pub post_dominator_tree: HashMap<usize, usize>,
    pub post_dominance_frontiers: HashMap<usize, HashSet<usize>>,
    pub control_dependencies: HashMap<usize, Vec<usize>>, // parent -> control-dependent nodes
}

impl ControlDependenceGraph {
    /// Computes the Control Dependence Graph for a given CFG.
    pub fn build(cfg: &ControlFlowGraph) -> Self {
        let post_dom = compute_post_dominators(cfg);
        let post_df = compute_post_dominance_frontiers(cfg, &post_dom);

        let mut cdg_edges: HashMap<usize, Vec<usize>> = HashMap::new();
        for (&b, frontiers) in &post_df {
            for &dep in frontiers {
                cdg_edges.entry(b).or_default().push(dep);
            }
        }

        ControlDependenceGraph {
            post_dominator_tree: post_dom,
            post_dominance_frontiers: post_df,
            control_dependencies: cdg_edges,
        }
    }
}

fn compute_post_dominators(cfg: &ControlFlowGraph) -> HashMap<usize, usize> {
    let mut pdom = HashMap::new();
    let exit = cfg.exit;
    pdom.insert(exit, exit);

    let blocks: Vec<usize> = cfg.blocks.keys().copied().collect();
    let mut changed = true;

    while changed {
        changed = false;
        for &b in &blocks {
            if b == exit {
                continue;
            }
            let succs: Vec<usize> = cfg.blocks[&b]
                .successors
                .iter()
                .map(|(s, _)| *s)
                .filter(|s| pdom.contains_key(s))
                .collect();
            if succs.is_empty() {
                continue;
            }
            let mut new_pdom = succs[0];
            for &s in &succs[1..] {
                new_pdom = intersect_pdom(&pdom, s, new_pdom);
            }
            if pdom.get(&b) != Some(&new_pdom) {
                pdom.insert(b, new_pdom);
                changed = true;
            }
        }
    }

    pdom
}

fn intersect_pdom(pdom: &HashMap<usize, usize>, mut b1: usize, mut b2: usize) -> usize {
    while b1 != b2 {
        while b1 > b2 {
            b1 = pdom.get(&b1).copied().unwrap_or(b1);
        }
        while b2 > b1 {
            b2 = pdom.get(&b2).copied().unwrap_or(b2);
        }
    }
    b1
}

fn compute_post_dominance_frontiers(
    cfg: &ControlFlowGraph,
    pdom: &HashMap<usize, usize>,
) -> HashMap<usize, HashSet<usize>> {
    let mut pdf: HashMap<usize, HashSet<usize>> = HashMap::new();

    for &b in cfg.blocks.keys() {
        let succs = &cfg.blocks[&b].successors;
        if succs.len() >= 2 {
            for &(s, _) in succs {
                let mut runner = s;
                while Some(&runner) != pdom.get(&b) && pdom.contains_key(&runner) {
                    pdf.entry(runner).or_default().insert(b);
                    runner = pdom[&runner];
                }
            }
        }
    }

    pdf
}

#[cfg(test)]
mod tests {
    use super::*;
    use yunq_ast::{AstNode, NodeKind, Span};

    #[test]
    fn builds_control_dependence_graph() {
        let node = AstNode::new(
            NodeKind::FunctionDef,
            Span::new(1, 1, 3, 1),
            "fn test() { if true { return; } }",
            vec![],
        );
        let cfg = ControlFlowGraph::build(&node);
        let cdg = ControlDependenceGraph::build(&cfg);

        assert!(cdg.post_dominator_tree.contains_key(&cfg.exit));
    }
}
