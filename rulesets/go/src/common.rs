//! Shared AST helpers for Go rules.

use yunq_ast::{AstNode, NodeKind};

pub(crate) fn is_other(kind: &NodeKind, name: &str) -> bool {
    matches!(kind, NodeKind::Other(k) if k.as_ref() == name)
}

/// A `Call`'s callee is always its first child in tree-sitter-go's grammar
/// (`call_expression` → `[function, argument_list]`, verified against real
/// parses — unlike PHP's flattened method-call shape, Go never needs a
/// positional search for it).
pub(crate) fn callee(call: &AstNode) -> Option<&AstNode> {
    call.children().first()
}

pub(crate) fn arguments(call: &AstNode) -> Option<&[AstNode]> {
    call.children()
        .get(1)
        .and_then(|args| is_other(args.kind(), "argument_list").then_some(args.children()))
}

/// The field name of a `selector_expression` (`db.Query` → `"Query"`), or
/// the bare name of a plain identifier callee (`close` → `"close"`).
pub(crate) fn callee_name(callee: &AstNode) -> Option<&str> {
    match callee.kind() {
        NodeKind::Identifier => Some(callee.text()),
        NodeKind::MemberAccess => callee.children().get(1).map(AstNode::text),
        _ => None,
    }
}

/// The two named children of a `binary_expression` are its operands; the
/// operator token itself is anonymous in tree-sitter-go's grammar (same gap
/// `rulesets/rust`/`rulesets/php` hit), so it's read back out of the raw
/// source between the two operand spans.
pub(crate) fn operator_between<'a>(source: &'a str, left: &AstNode, right: &AstNode) -> &'a str {
    source.get(left.byte_range().end..right.byte_range().start).unwrap_or("").trim()
}

/// A `for_statement`'s body is always its last child, after the
/// `for_clause`/`range_clause` (verified against real parses).
pub(crate) fn loop_body(loop_node: &AstNode) -> Option<&AstNode> {
    let body = loop_node.children().last()?;
    is_other(body.kind(), "block").then_some(body)
}

/// Collects every descendant of `node` matching `is_target`, without
/// descending into a nested `for_statement` or a nested `FunctionDef`
/// (func literal/declaration) — both open an independent scope for the
/// category these rules check (a nested loop reports its own findings when
/// `ast.descendants()` reaches it directly, and a nested function's `defer`/
/// closure-capture semantics belong to that function, not the enclosing
/// one), mirroring `smells::db_call_in_loop`'s same-shaped skip logic.
pub(crate) fn collect_bounded<'a>(
    node: &'a AstNode,
    is_target: impl Fn(&AstNode) -> bool + Copy,
    out: &mut Vec<&'a AstNode>,
) {
    for child in node.children() {
        if is_target(child) {
            out.push(child);
            continue;
        }
        if is_other(child.kind(), "for_statement") || *child.kind() == NodeKind::FunctionDef {
            continue;
        }
        collect_bounded(child, is_target, out);
    }
}
