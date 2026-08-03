//! Shared AST helpers for WordPress rules. Mirrors `rulesets/php/src/common.rs`
//! (each ruleset crate owns its own copy rather than sharing one, matching
//! this workspace's existing php/go split) plus the extra shapes WordPress's
//! `$wpdb`/escaping/i18n API needs: unwrapping `arguments`/`argument`
//! wrapper nodes and a bounded walk that recognizes a value as "handled"
//! once it passes through an escaping/sanitizing function.

use vord_ast::{AstNode, NodeKind};

pub(crate) fn is_other(kind: &vord_ast::NodeKind, name: &str) -> bool {
    matches!(kind, vord_ast::NodeKind::Other(k) if k.as_ref() == name)
}

/// The request-data superglobals — the same list `rulesets/php` uses to
/// scope its own sink rules to attacker-controllable input.
pub(crate) const SUPERGLOBALS: &[&str] = &[
    "$_GET",
    "$_POST",
    "$_REQUEST",
    "$_COOKIE",
    "$_SERVER",
    "$_FILES",
];

/// See `rulesets/php/src/common.rs::callee_node` — identical shape, since
/// tree-sitter-php flattens both bare and method calls to `Call` with the
/// callee as the named child directly before `arguments`.
pub(crate) fn callee_node(call: &AstNode) -> Option<&AstNode> {
    let children = call.children();
    let args_idx = children
        .iter()
        .position(|c| is_other(c.kind(), "arguments"))?;
    args_idx.checked_sub(1).map(|i| &children[i])
}

/// The `arguments` node's `argument` children, one per call argument —
/// `$wpdb->prepare($sql, $id)` yields `[$sql, $id]` regardless of the
/// `argument` wrapper tree-sitter-php inserts around each one.
pub(crate) fn call_arguments(call: &AstNode) -> Option<&[AstNode]> {
    call.children()
        .iter()
        .find(|c| is_other(c.kind(), "arguments"))
        .map(|args| args.children())
}

/// The two named children of a `binary_expression` are its operands; see
/// `rulesets/php/src/common.rs::operator_between` for why the operator
/// itself has to be read back out of the source text.
pub(crate) fn operator_between<'a>(source: &'a str, left: &AstNode, right: &AstNode) -> &'a str {
    source
        .get(left.byte_range().end..right.byte_range().start)
        .unwrap_or("")
        .trim()
}

/// Checking existence doesn't use the value — `isset( $_GET['x'] )` isn't a
/// read of `$_GET['x']`, so it can't be the thing a sanitizer/escaper was
/// missing from. Recognized unconditionally, on top of whatever
/// rule-specific wrapper list `subtree_has_unwrapped_superglobal` is given.
const NON_TAINTING_FUNCTIONS: &[&str] = &["isset", "empty", "array_key_exists"];

fn call_callee_name(node: &AstNode) -> Option<&str> {
    if *node.kind() != NodeKind::Call {
        return None;
    }
    callee_node(node)
        .filter(|c| *c.kind() == NodeKind::Identifier)
        .map(|c| c.text())
}

/// `array_map()`/`array_filter()` apply their first argument as a callback
/// to every element of the array in the rest of their arguments —
/// `array_map( 'absint', $_GET['ids'] )` sanitizes every element the same
/// way `absint( $_GET['id'] )` would one, so it needs the same recognition
/// as a direct call, just one level removed. `array_walk()` isn't included:
/// it mutates its array argument by reference instead of returning a new
/// one, so a callback there isn't "wrapping" the value being read out of
/// the array at all.
const ELEMENTWISE_APPLY_FUNCTIONS: &[&str] = &["array_map", "array_filter"];

/// The bare function name passed as `node`'s first argument, if it's a
/// string literal — `call_arguments` returns the `argument` wrapper node
/// tree-sitter-php inserts, not the `StringLiteral` inside, so this looks
/// one level deeper rather than requiring an exact kind match.
fn first_argument_function_name(node: &AstNode) -> Option<&str> {
    let first_arg = call_arguments(node)?.first()?;
    first_arg
        .descendants()
        .find(|n| *n.kind() == NodeKind::StringLiteral)
        .map(|s| s.children().first().map_or("", |c| c.text()))
}

/// Walks `node` looking for a superglobal reference, stopping at any call to
/// one of `safe_wrapper_functions` (an escaper, a sanitizer — whichever list
/// the calling rule cares about) or to `isset()`/`empty()`/
/// `array_key_exists()` rather than looking inside it: once a value has
/// passed through one of those, or was only ever probed for existence, this
/// expression is done needing scrutiny. This is what lets
/// `wordpress:unescaped-superglobal-output`/`wordpress:unsanitized-
/// superglobal-input` see through the ternary/concatenation shapes real WP
/// code actually uses (`isset( $_GET['x'] ) ? esc_html( $_GET['x'] ) : ''`)
/// instead of only recognizing "the whole printed/assigned expression is one
/// direct call" — still no cross-statement taint tracking, the same
/// call-site-shape scope every rule in this workspace that isn't a full
/// taint analysis documents for itself.
pub(crate) fn subtree_has_unwrapped_superglobal(
    node: &AstNode,
    safe_wrapper_functions: &[&str],
) -> bool {
    if let Some(name) = call_callee_name(node) {
        if safe_wrapper_functions.contains(&name) || NON_TAINTING_FUNCTIONS.contains(&name) {
            return false;
        }
        if ELEMENTWISE_APPLY_FUNCTIONS.contains(&name)
            && first_argument_function_name(node).is_some_and(|cb| safe_wrapper_functions.contains(&cb))
        {
            return false;
        }
    }
    if *node.kind() == NodeKind::Identifier && SUPERGLOBALS.contains(&node.text()) {
        return true;
    }
    node.children()
        .iter()
        .any(|c| subtree_has_unwrapped_superglobal(c, safe_wrapper_functions))
}
