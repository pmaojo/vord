//! A behaviour fingerprint for "is this edit a pure refactor?".
//!
//! A refactor moves, renames, extracts and inlines code; it does not invent a
//! constant, flip a comparison or add a branch. So what a refactor must
//! preserve can be read off the tree as a multiset of *semantic atoms*:
//!
//! - **literals** (`lit:<text>`) — strings, numbers, booleans, null/nil;
//! - **operators** (`op:<token>`) — the anonymous token between a binary
//!   expression's operands, or around a unary one's single operand;
//! - **control flow** (`ctl:<shape>`) — `if`, loops, `match`/`switch`,
//!   `catch`, `throw`/`raise`.
//!
//! Identifiers are deliberately absent (renaming is the most common refactor
//! there is), and so is `return` (extracting a method adds one).
//!
//! [`SemanticFingerprint::drift`] compares two fingerprints of the *same
//! scope* — usually every file a task may touch, merged, so a function moved
//! across files still matches. It is intentionally asymmetric:
//!
//! - an atom that **appears** (absent before, present after) or **vanishes**
//!   (present before, absent after) is drift — a new constant, a changed
//!   operator, a deleted guard;
//! - a literal or operator whose *count* merely changes is not — removing
//!   duplicated code lowers counts, inlining raises them, and both are
//!   refactors;
//! - a control-flow atom whose count **rises** is drift — a new branch is new
//!   behaviour — while a fall is allowed, for the same deduplication reason.
//!
//! This is a heuristic over syntax, not a proof of equivalence: `a > b`
//! rewritten as `b < a` reads as drift, and swapping two existing constants
//! does not. It errs toward reporting, which in a refactor-only task is the
//! side a reviewer wants it to err on.

use std::collections::BTreeMap;

use crate::{AstNode, NodeKind};

/// Multiset of semantic atoms — see the module docs.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SemanticFingerprint {
    atoms: BTreeMap<String, usize>,
}

/// What changed between two fingerprints that a pure refactor would not
/// change. Every list is sorted, for deterministic output.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SemanticDrift {
    /// Atoms present after the edit that were nowhere before it.
    pub appeared: Vec<String>,
    /// Atoms present before the edit that are nowhere after it.
    pub vanished: Vec<String>,
    /// Control-flow atoms whose count rose: `(atom, before, after)`.
    pub added_control: Vec<(String, usize, usize)>,
}

impl SemanticDrift {
    pub fn is_empty(&self) -> bool {
        self.appeared.is_empty() && self.vanished.is_empty() && self.added_control.is_empty()
    }
}

impl SemanticFingerprint {
    /// The fingerprint of one parsed file.
    pub fn of(root: &AstNode) -> Self {
        let mut fingerprint = Self::default();
        fingerprint.visit(root);
        fingerprint
    }

    /// Folds `other` into this fingerprint, so a scope spanning many files is
    /// compared as one — a function moved between files is not drift.
    pub fn merge(&mut self, other: &SemanticFingerprint) {
        for (atom, count) in &other.atoms {
            *self.atoms.entry(atom.clone()).or_insert(0) += count;
        }
    }

    pub fn count(&self, atom: &str) -> usize {
        self.atoms.get(atom).copied().unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.atoms.is_empty()
    }

    /// Everything `after` changed that a pure refactor of `self` would not.
    pub fn drift(&self, after: &SemanticFingerprint) -> SemanticDrift {
        let mut drift = SemanticDrift::default();
        for (atom, &now) in &after.atoms {
            let before = self.count(atom);
            if before == 0 {
                drift.appeared.push(atom.clone());
            } else if atom.starts_with("ctl:") && now > before {
                drift.added_control.push((atom.clone(), before, now));
            }
        }
        for atom in self.atoms.keys() {
            if after.count(atom) == 0 {
                drift.vanished.push(atom.clone());
            }
        }
        drift
    }

    fn record(&mut self, atom: String) {
        *self.atoms.entry(atom).or_insert(0) += 1;
    }

    fn visit(&mut self, node: &AstNode) {
        if matches!(node.kind(), NodeKind::Comment) {
            return;
        }
        if is_literal(node.kind()) {
            // A literal's own children (string fragments, escapes) are
            // part of the one value, not separate atoms.
            self.record(format!("lit:{}", node.text().trim()));
            return;
        }
        if let NodeKind::Other(kind) = node.kind() {
            if let Some(shape) = control_shape(kind) {
                self.record(format!("ctl:{shape}"));
            }
            if is_operator_expression(kind)
                && let Some(op) = operator_of(node)
            {
                self.record(format!("op:{op}"));
            }
        }
        for child in node.children() {
            self.visit(child);
        }
    }
}

fn is_literal(kind: &NodeKind) -> bool {
    match kind {
        NodeKind::StringLiteral => true,
        NodeKind::Other(kind) => {
            let kind = kind.as_ref();
            kind.ends_with("_literal")
                || kind.ends_with("string")
                || matches!(
                    kind,
                    "number"
                        | "integer"
                        | "float"
                        | "true"
                        | "false"
                        | "none"
                        | "null"
                        | "nil"
                        | "undefined"
                        | "boolean"
                )
        }
        _ => false,
    }
}

fn control_shape(kind: &str) -> Option<&'static str> {
    let shape = if kind == "if" || kind.starts_with("if_") {
        "if"
    } else if kind.starts_with("while")
        || kind.starts_with("for_")
        || kind.starts_with("loop_")
        || kind == "do_statement"
    {
        "loop"
    } else if kind.starts_with("switch") || kind.starts_with("match_") || kind == "case" {
        "branch"
    } else if kind.starts_with("catch") || kind.starts_with("except") || kind.starts_with("rescue")
    {
        "catch"
    } else if kind.starts_with("throw") || kind.starts_with("raise") {
        "throw"
    } else {
        return None;
    };
    Some(shape)
}

fn is_operator_expression(kind: &str) -> bool {
    kind.contains("binary")
        || kind.contains("unary")
        || kind.contains("comparison")
        || kind == "boolean_operator"
        || kind == "not_operator"
        || kind.contains("compound_assignment")
        || kind.contains("augmented_assignment")
        || kind == "update_expression"
}

/// The anonymous operator token: the gap between the first two operands, or
/// what surrounds the only operand of a unary expression.
fn operator_of(node: &AstNode) -> Option<String> {
    let children = node.children();
    let raw = match children {
        [first, second, ..] => node.text_between(first, second)?.to_string(),
        [only] => {
            let text = node.text();
            let inner = only.text();
            text.strip_prefix(inner)
                .or_else(|| text.strip_suffix(inner))?
                .to_string()
        }
        [] => return None,
    };
    let op = raw.split_whitespace().collect::<Vec<_>>().join(" ");
    (!op.is_empty()).then_some(op)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Span, intern};
    use std::sync::Arc;

    fn span() -> Span {
        Span::new(1, 1, 1, 1)
    }

    fn other(kind: &str) -> NodeKind {
        NodeKind::Other(intern(kind))
    }

    /// `if a > 10 { throw }` over one shared buffer, the way parsers build
    /// trees, so `text_between` can recover the operator.
    fn guard(source: &str) -> AstNode {
        let src: Arc<str> = Arc::from(source);
        let at = |needle: &str| {
            let start = source.find(needle).expect("needle in source");
            start..start + needle.len()
        };
        let (lhs, op_rhs) = source
            .split_once(' ')
            .map(|(_, rest)| rest.split_once(' ').expect("lhs"))
            .expect("if");
        let (_, rest) = op_rhs.split_once(' ').expect("operator");
        let rhs = rest.split_whitespace().next().expect("rhs");
        let lhs_node =
            AstNode::from_source(other("identifier"), span(), src.clone(), at(lhs), vec![]);
        let rhs_start = source.rfind(rhs).expect("rhs in source");
        let rhs_node = AstNode::from_source(
            other("integer_literal"),
            span(),
            src.clone(),
            rhs_start..rhs_start + rhs.len(),
            vec![],
        );
        let condition_end = rhs_start + rhs.len();
        let condition = AstNode::from_source(
            other("binary_expression"),
            span(),
            src.clone(),
            at(lhs).start..condition_end,
            vec![lhs_node, rhs_node],
        );
        let throw = AstNode::from_source(
            other("throw_statement"),
            span(),
            src.clone(),
            at("throw"),
            vec![],
        );
        AstNode::from_source(
            other("if_expression"),
            span(),
            src.clone(),
            0..source.len(),
            vec![condition, throw],
        )
    }

    #[test]
    fn reads_literals_operators_and_control_flow() {
        let fingerprint = SemanticFingerprint::of(&guard("if a > 10 { throw }"));
        assert_eq!(fingerprint.count("lit:10"), 1);
        assert_eq!(fingerprint.count("op:>"), 1);
        assert_eq!(fingerprint.count("ctl:if"), 1);
        assert_eq!(fingerprint.count("ctl:throw"), 1);
    }

    #[test]
    fn renaming_an_identifier_is_not_drift() {
        let before = SemanticFingerprint::of(&guard("if a > 10 { throw }"));
        let after = SemanticFingerprint::of(&guard("if limit > 10 { throw }"));
        assert!(before.drift(&after).is_empty());
    }

    #[test]
    fn flipping_a_comparison_is_drift() {
        let before = SemanticFingerprint::of(&guard("if a > 10 { throw }"));
        let after = SemanticFingerprint::of(&guard("if a >= 10 { throw }"));
        let drift = before.drift(&after);
        assert_eq!(drift.appeared, vec!["op:>=".to_string()]);
        assert_eq!(drift.vanished, vec!["op:>".to_string()]);
    }

    #[test]
    fn changing_a_constant_is_drift() {
        let before = SemanticFingerprint::of(&guard("if a > 10 { throw }"));
        let after = SemanticFingerprint::of(&guard("if a > 11 { throw }"));
        let drift = before.drift(&after);
        assert_eq!(drift.appeared, vec!["lit:11".to_string()]);
        assert_eq!(drift.vanished, vec!["lit:10".to_string()]);
    }

    #[test]
    fn removing_a_duplicate_is_not_drift_but_adding_a_branch_is() {
        let one = SemanticFingerprint::of(&guard("if a > 10 { throw }"));
        let mut two = one.clone();
        two.merge(&one);
        assert!(two.drift(&one).is_empty(), "deduplication is a refactor");
        let drift = one.drift(&two);
        assert!(drift.appeared.is_empty() && drift.vanished.is_empty());
        assert_eq!(
            drift.added_control,
            vec![
                ("ctl:if".to_string(), 1, 2),
                ("ctl:throw".to_string(), 1, 2)
            ]
        );
    }

    #[test]
    fn comments_are_ignored() {
        let comment = AstNode::new(NodeKind::Comment, span(), "// 42 > 7", vec![]);
        assert!(SemanticFingerprint::of(&comment).is_empty());
    }
}
