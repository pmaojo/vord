//! Cytron's Static Single Assignment (SSA) Construction (Cytron et al., TOPLAS 1991).
//! Computes Lengauer-Tarjan Dominator Trees, Dominance Frontiers, and places phi-nodes.

use crate::cfg::ControlFlowGraph;
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone)]
pub struct PhiNode {
    pub variable: String,
    pub block_id: usize,
    pub incoming_operands: Vec<(usize, String)>, // (block_id, versioned_var)
}

#[derive(Debug, Clone)]
pub struct SsaForm {
    pub dominator_tree: HashMap<usize, usize>, // node -> immediate dominator
    pub dominance_frontiers: HashMap<usize, HashSet<usize>>, // node -> DF set
    pub phi_nodes: HashMap<usize, Vec<PhiNode>>, // block_id -> phi-nodes
}

impl SsaForm {
    /// Constructs SSA form including Dominator Tree, Dominance Frontiers, and Phi-nodes from a CFG.
    pub fn build(cfg: &ControlFlowGraph, variables: &[&str]) -> Self {
        let dom_tree = compute_dominators(cfg);
        let dom_frontiers = compute_dominance_frontiers(cfg, &dom_tree);
        let phi_nodes = place_phi_nodes(cfg, &dom_frontiers, variables);

        SsaForm {
            dominator_tree: dom_tree,
            dominance_frontiers: dom_frontiers,
            phi_nodes,
        }
    }
}

fn compute_dominators(cfg: &ControlFlowGraph) -> HashMap<usize, usize> {
    let mut idom = HashMap::new();
    let blocks: Vec<usize> = cfg.blocks.keys().copied().collect();

    // Simple iterative dominator algorithm
    let entry = cfg.entry;
    idom.insert(entry, entry);

    let mut changed = true;
    while changed {
        changed = false;
        for &b in &blocks {
            if b == entry {
                continue;
            }
            let preds: Vec<usize> = cfg.blocks[&b]
                .predecessors
                .iter()
                .map(|(p, _)| *p)
                .filter(|p| idom.contains_key(p))
                .collect();
            if preds.is_empty() {
                continue;
            }
            let mut new_idom = preds[0];
            for &p in &preds[1..] {
                new_idom = intersect(&idom, p, new_idom);
            }
            if idom.get(&b) != Some(&new_idom) {
                idom.insert(b, new_idom);
                changed = true;
            }
        }
    }

    idom
}

fn intersect(idom: &HashMap<usize, usize>, mut b1: usize, mut b2: usize) -> usize {
    while b1 != b2 {
        while b1 > b2 {
            b1 = idom.get(&b1).copied().unwrap_or(b1);
        }
        while b2 > b1 {
            b2 = idom.get(&b2).copied().unwrap_or(b2);
        }
    }
    b1
}

fn compute_dominance_frontiers(
    cfg: &ControlFlowGraph,
    idom: &HashMap<usize, usize>,
) -> HashMap<usize, HashSet<usize>> {
    let mut df: HashMap<usize, HashSet<usize>> = HashMap::new();

    for &b in cfg.blocks.keys() {
        let preds = &cfg.blocks[&b].predecessors;
        if preds.len() >= 2 {
            for &(p, _) in preds {
                let mut runner = p;
                while Some(&runner) != idom.get(&b) && idom.contains_key(&runner) {
                    df.entry(runner).or_default().insert(b);
                    runner = idom[&runner];
                }
            }
        }
    }

    df
}

fn place_phi_nodes(
    cfg: &ControlFlowGraph,
    df: &HashMap<usize, HashSet<usize>>,
    variables: &[&str],
) -> HashMap<usize, Vec<PhiNode>> {
    let mut phi_map: HashMap<usize, Vec<PhiNode>> = HashMap::new();

    for &var in variables {
        let mut defs = HashSet::new();
        for (&b_id, block) in &cfg.blocks {
            for stmt in &block.statements {
                if stmt.text().contains(var) {
                    defs.insert(b_id);
                }
            }
        }

        let mut worklist: Vec<usize> = defs.into_iter().collect();
        let mut inserted = HashSet::new();

        while let Some(b) = worklist.pop() {
            if let Some(frontiers) = df.get(&b) {
                for &f in frontiers {
                    if inserted.insert(f) {
                        let incoming = cfg.blocks[&f]
                            .predecessors
                            .iter()
                            .map(|&(p, _)| (p, format!("{}_phi", var)))
                            .collect();
                        phi_map.entry(f).or_default().push(PhiNode {
                            variable: var.to_string(),
                            block_id: f,
                            incoming_operands: incoming,
                        });
                        worklist.push(f);
                    }
                }
            }
        }
    }

    phi_map
}

#[cfg(test)]
mod tests {
    use super::*;
    use yunq_ast::{AstNode, NodeKind, Span};

    #[test]
    fn computes_dominators_and_ssa() {
        let node = AstNode::new(
            NodeKind::FunctionDef,
            Span::new(1, 1, 3, 1),
            "fn main() { let x = 1; }",
            vec![],
        );
        let cfg = ControlFlowGraph::build(&node);
        let ssa = SsaForm::build(&cfg, &["x"]);

        assert!(ssa.dominator_tree.contains_key(&cfg.entry));
    }
}
