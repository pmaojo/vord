//! Dynamic programming tree edit distance algorithms (Zhang-Shasha & Chawathe).
//! Computes node edit distance and structural similarity matrices for AST clone detection.

use crate::AstNode;
use std::cmp::min;

#[derive(Debug, Clone)]
pub struct TreeEditDistance;

impl TreeEditDistance {
    /// Computes the Zhang-Shasha tree edit distance between two AST nodes using dynamic programming.
    pub fn zhang_shasha(tree1: &AstNode, tree2: &AstNode) -> usize {
        let nodes1 = post_order_traversal(tree1);
        let nodes2 = post_order_traversal(tree2);

        let l1 = compute_leftmost_leaf_indices(&nodes1);
        let l2 = compute_leftmost_leaf_indices(&nodes2);

        let key_roots1 = compute_key_roots(&l1);
        let key_roots2 = compute_key_roots(&l2);

        let n1 = nodes1.len();
        let n2 = nodes2.len();
        let mut td = vec![vec![0; n2 + 1]; n1 + 1];

        for &i in &key_roots1 {
            for &j in &key_roots2 {
                tree_edit_distance_sub(i, j, &l1, &l2, &nodes1, &nodes2, &mut td);
            }
        }

        td[n1][n2]
    }

    /// Computes structural similarity ratio between two AST nodes [0.0, 1.0].
    pub fn similarity(tree1: &AstNode, tree2: &AstNode) -> f64 {
        let len1 = count_tree_size(tree1);
        let len2 = count_tree_size(tree2);
        if len1 == 0 && len2 == 0 {
            return 1.0;
        }
        let dist = Self::zhang_shasha(tree1, tree2);
        let max_len = len1.max(len2);
        (1.0 - (dist as f64 / max_len as f64)).max(0.0)
    }
}

fn tree_edit_distance_sub(
    i: usize,
    j: usize,
    l1: &[usize],
    l2: &[usize],
    nodes1: &[&AstNode],
    nodes2: &[&AstNode],
    td: &mut [Vec<usize>],
) {
    let sub_len1 = i - l1[i - 1] + 1;
    let sub_len2 = j - l2[j - 1] + 1;

    let mut fd = vec![vec![0; sub_len2 + 1]; sub_len1 + 1];

    let off1 = l1[i - 1];
    let off2 = l2[j - 1];

    for m in 1..=sub_len1 {
        fd[m][0] = fd[m - 1][0] + 1;
    }
    for n in 1..=sub_len2 {
        fd[0][n] = fd[0][n - 1] + 1;
    }

    for m in 1..=sub_len1 {
        for n in 1..=sub_len2 {
            let node_i = nodes1[off1 + m - 2];
            let node_j = nodes2[off2 + n - 2];

            if l1[off1 + m - 2] == off1 && l2[off2 + n - 2] == off2 {
                let cost = node_rename_cost(node_i, node_j);
                fd[m][n] = min(
                    min(fd[m - 1][n] + 1, fd[m][n - 1] + 1),
                    fd[m - 1][n - 1] + cost,
                );
                td[off1 + m - 1][off2 + n - 1] = fd[m][n];
            } else {
                let p1 = l1[off1 + m - 2] - off1;
                let p2 = l2[off2 + n - 2] - off2;
                fd[m][n] = min(
                    min(fd[m - 1][n] + 1, fd[m][n - 1] + 1),
                    fd[p1][p2] + td[off1 + m - 1][off2 + n - 1],
                );
            }
        }
    }
}

fn node_rename_cost(n1: &AstNode, n2: &AstNode) -> usize {
    if n1.kind() == n2.kind() && n1.text() == n2.text() {
        0
    } else if n1.kind() == n2.kind() {
        1
    } else {
        2
    }
}

fn post_order_traversal(node: &AstNode) -> Vec<&AstNode> {
    let mut result = Vec::new();
    fn recurse<'a>(n: &'a AstNode, res: &mut Vec<&'a AstNode>) {
        for child in n.children() {
            recurse(child, res);
        }
        res.push(n);
    }
    recurse(node, &mut result);
    result
}

fn compute_leftmost_leaf_indices(nodes: &[&AstNode]) -> Vec<usize> {
    let n = nodes.len();
    let mut l = vec![0; n];
    for i in 0..n {
        let mut curr = nodes[i];
        while !curr.children().is_empty() {
            curr = &curr.children()[0];
        }
        // find index of curr in nodes
        let idx = nodes
            .iter()
            .position(|&x| std::ptr::eq(x, curr))
            .unwrap_or(0);
        l[i] = idx + 1;
    }
    l
}

fn compute_key_roots(l: &[usize]) -> Vec<usize> {
    let n = l.len();
    let mut is_key_root = vec![true; n];
    for i in 0..n {
        for j in 0..n {
            if i != j && l[i] == l[j] && j > i {
                is_key_root[i] = false;
                break;
            }
        }
    }
    (1..=n).filter(|&k| is_key_root[k - 1]).collect()
}

fn count_tree_size(node: &AstNode) -> usize {
    1 + node.children().iter().map(count_tree_size).sum::<usize>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{NodeKind, Span};

    #[test]
    fn calculates_zero_edit_distance_for_identical_trees() {
        let n1 = AstNode::new(NodeKind::Identifier, Span::new(1, 1, 1, 2), "var", vec![]);
        let n2 = AstNode::new(NodeKind::Identifier, Span::new(1, 1, 1, 2), "var", vec![]);

        let dist = TreeEditDistance::zhang_shasha(&n1, &n2);
        assert_eq!(dist, 0);

        let sim = TreeEditDistance::similarity(&n1, &n2);
        assert_eq!(sim, 1.0);
    }

    #[test]
    fn calculates_non_zero_distance_for_distinct_nodes() {
        let n1 = AstNode::new(NodeKind::Identifier, Span::new(1, 1, 1, 2), "foo", vec![]);
        let n2 = AstNode::new(
            NodeKind::StringLiteral,
            Span::new(1, 1, 1, 2),
            "bar",
            vec![],
        );

        let dist = TreeEditDistance::zhang_shasha(&n1, &n2);
        assert!(dist > 0);
    }
}
