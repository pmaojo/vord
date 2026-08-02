//! Shared AST helpers for PHP rules.

use vord_ast::AstNode;

pub(crate) fn is_other(kind: &vord_ast::NodeKind, name: &str) -> bool {
    matches!(kind, vord_ast::NodeKind::Other(k) if k.as_ref() == name)
}

/// The superglobal arrays PHP populates from request data — anything that
/// flows out of one of these without validation is attacker-controlled.
pub(crate) const SUPERGLOBALS: &[&str] = &[
    "$_GET",
    "$_POST",
    "$_REQUEST",
    "$_COOKIE",
    "$_SERVER",
    "$_FILES",
    "$_ENV",
];

/// A `Call` node's callee, regardless of whether it's a bare function call
/// (`eval(...)`), a method call (tree-sitter-php's `member_call_expression`
/// flattens to a `Call` with `[receiver, method_name, arguments]` rather
/// than a receiver + a `MemberAccess` callee), or a dynamic call
/// (`$_GET['f'](...)`, callee is a `subscript_expression`) — in every case
/// it's the named child directly before `arguments`.
pub(crate) fn callee_node(call: &AstNode) -> Option<&AstNode> {
    let children = call.children();
    let args_idx = children
        .iter()
        .position(|c| is_other(c.kind(), "arguments"))?;
    args_idx.checked_sub(1).map(|i| &children[i])
}

/// The two named children of a `binary_expression` are its operands; the
/// operator token itself is anonymous in tree-sitter-php's grammar and
/// doesn't survive conversion to this neutral AST as a node, so it's read
/// back out of the raw source between the two operand spans.
pub(crate) fn operator_between<'a>(source: &'a str, left: &AstNode, right: &AstNode) -> &'a str {
    source
        .get(left.byte_range().end..right.byte_range().start)
        .unwrap_or("")
        .trim()
}
