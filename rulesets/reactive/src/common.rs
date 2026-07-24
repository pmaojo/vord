//! Shared helpers for reactive-stream (RxJS-shaped) rules: recognizing a
//! `.method(...)` call by its callee's last identifier segment (the same
//! pattern `rulesets/react::common::map_callback_functions` uses for
//! `.map`), and matching an assignment/declaration target against a later
//! call's receiver by comparing source text directly.

use yunq_ast::{AstNode, NodeKind};

/// A bindable assignment/declaration target: a plain identifier (`sub`), or
/// a `this.field`/`self.field` member access. Both are textually canonical
/// enough to match a later call's receiver by comparing `.text()` — the
/// exact same source span shape appears whether `this.sub` is the target of
/// `this.sub = ...` or the base of `this.sub.unsubscribe()`.
pub(crate) fn bindable_target(node: &AstNode) -> Option<&AstNode> {
    let target = node.first_child()?;
    matches!(target.kind(), NodeKind::Identifier | NodeKind::MemberAccess).then_some(target)
}

pub(crate) fn is_method_call(node: &AstNode, method: &str) -> bool {
    if *node.kind() != NodeKind::Call {
        return false;
    }
    node.first_child().is_some_and(|callee| {
        *callee.kind() == NodeKind::MemberAccess
            && callee.children().last().is_some_and(|p| *p.kind() == NodeKind::Identifier && p.text() == method)
    })
}

/// The `Call` node among `node`'s non-target children whose callee is a
/// `.method(...)` call, possibly chained after other calls
/// (`source.pipe(...).subscribe(...)`'s outer call is still recognized by
/// its own callee's last segment regardless of what its base expression is).
pub(crate) fn rhs_method_call<'a>(node: &'a AstNode, method: &str) -> Option<&'a AstNode> {
    node.children().iter().skip(1).find(|value| is_method_call(value, method))
}

/// Whether some `<receiver_text>.<method>(...)` call exists anywhere in
/// `scope`.
pub(crate) fn has_call_on_receiver(scope: &AstNode, receiver_text: &str, method: &str) -> bool {
    scope.descendants().any(|call| {
        is_method_call(call, method)
            && call
                .first_child()
                .and_then(|callee| callee.first_child())
                .is_some_and(|base| base.text() == receiver_text)
    })
}
