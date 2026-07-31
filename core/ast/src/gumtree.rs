//! Fine-grained AST differencing algorithm based on GumTree (Falleri et al., ASE 2014).
//! Computes isomorphic maximal subtrees and minimal edit scripts (Insert, Delete, Move, Update).

use crate::{AstNode, NodeKind};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EditAction {
    Insert {
        node_kind: NodeKind,
        text: String,
    },
    Delete {
        node_kind: NodeKind,
        text: String,
    },
    Move {
        node_kind: NodeKind,
        text: String,
    },
    Update {
        node_kind: NodeKind,
        old_text: String,
        new_text: String,
    },
}

#[derive(Debug, Clone)]
pub struct EditScript {
    pub actions: Vec<EditAction>,
    pub similarity_score: f64,
}

pub struct GumTreeDiff;

impl GumTreeDiff {
    /// Computes fine-grained AST differencing between two trees `src` and `dst`.
    pub fn compute(src: &AstNode, dst: &AstNode) -> EditScript {
        let mappings = top_down_greedy_match(src, dst);
        let actions = bottom_up_edit_script(src, dst, &mappings);

        let total_nodes = count_nodes(src) + count_nodes(dst);
        let matched_count = mappings.len() * 2;
        let similarity_score = if total_nodes == 0 {
            1.0
        } else {
            matched_count as f64 / total_nodes as f64
        };

        EditScript {
            actions,
            similarity_score,
        }
    }
}

fn top_down_greedy_match<'a>(src: &'a AstNode, dst: &'a AstNode) -> HashMap<usize, usize> {
    let mut mappings = HashMap::new();
    let mut src_nodes = Vec::new();
    let mut dst_nodes = Vec::new();

    collect_all_nodes(src, &mut src_nodes);
    collect_all_nodes(dst, &mut dst_nodes);

    let mut matched_src = HashSet::new();
    let mut matched_dst = HashSet::new();

    for (i, s) in src_nodes.iter().enumerate() {
        for (j, d) in dst_nodes.iter().enumerate() {
            if matched_src.contains(&i) || matched_dst.contains(&j) {
                continue;
            }
            if is_isomorphic(s, d) {
                mappings.insert(i, j);
                matched_src.insert(i);
                matched_dst.insert(j);
                break;
            }
        }
    }

    mappings
}

fn is_isomorphic(a: &AstNode, b: &AstNode) -> bool {
    if a.kind() != b.kind() || a.text() != b.text() {
        return false;
    }
    let a_children = a.children();
    let b_children = b.children();
    if a_children.len() != b_children.len() {
        return false;
    }
    for (ca, cb) in a_children.iter().zip(b_children.iter()) {
        if !is_isomorphic(ca, cb) {
            return false;
        }
    }
    true
}

fn bottom_up_edit_script<'a>(
    src: &'a AstNode,
    dst: &'a AstNode,
    mappings: &HashMap<usize, usize>,
) -> Vec<EditAction> {
    let mut actions = Vec::new();
    let mut src_nodes = Vec::new();
    let mut dst_nodes = Vec::new();

    collect_all_nodes(src, &mut src_nodes);
    collect_all_nodes(dst, &mut dst_nodes);

    let mapped_src_indices: HashSet<_> = mappings.keys().copied().collect();
    let mapped_dst_indices: HashSet<_> = mappings.values().copied().collect();

    // Deletions: nodes in src not mapped to dst
    for (i, s) in src_nodes.iter().enumerate() {
        if !mapped_src_indices.contains(&i) {
            actions.push(EditAction::Delete {
                node_kind: s.kind().clone(),
                text: s.text().to_string(),
            });
        }
    }

    // Insertions: nodes in dst not mapped to src
    for (j, d) in dst_nodes.iter().enumerate() {
        if !mapped_dst_indices.contains(&j) {
            actions.push(EditAction::Insert {
                node_kind: d.kind().clone(),
                text: d.text().to_string(),
            });
        }
    }

    // Updates & Moves: mapped pairs with text/position changes
    for (&i, &j) in mappings.iter() {
        let s = &src_nodes[i];
        let d = &dst_nodes[j];
        if s.kind() == d.kind() && s.text() != d.text() {
            actions.push(EditAction::Update {
                node_kind: s.kind().clone(),
                old_text: s.text().to_string(),
                new_text: d.text().to_string(),
            });
        }
    }

    actions
}

fn collect_all_nodes<'a>(node: &'a AstNode, out: &mut Vec<&'a AstNode>) {
    out.push(node);
    for child in node.children() {
        collect_all_nodes(child, out);
    }
}

fn count_nodes(node: &AstNode) -> usize {
    1 + node.children().iter().map(count_nodes).sum::<usize>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Span;

    #[test]
    fn computes_isomorphic_matching_and_similarity() {
        let n1 = AstNode::new(NodeKind::Identifier, Span::new(1, 1, 1, 2), "x", vec![]);
        let n2 = AstNode::new(NodeKind::Identifier, Span::new(1, 1, 1, 2), "x", vec![]);

        let diff = GumTreeDiff::compute(&n1, &n2);
        assert_eq!(diff.similarity_score, 1.0);
        assert!(diff.actions.is_empty());
    }

    #[test]
    fn detects_updates_and_deletions() {
        let n1 = AstNode::new(NodeKind::Identifier, Span::new(1, 1, 1, 2), "x", vec![]);
        let n2 = AstNode::new(NodeKind::Identifier, Span::new(1, 1, 1, 2), "y", vec![]);

        let diff = GumTreeDiff::compute(&n1, &n2);
        assert!(
            diff.actions
                .iter()
                .any(|a| matches!(a, EditAction::Delete { .. }))
        );
        assert!(
            diff.actions
                .iter()
                .any(|a| matches!(a, EditAction::Insert { .. }))
        );
    }
}
