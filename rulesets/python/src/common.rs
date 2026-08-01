//! Helpers shared across Python rules — eliminates duplicated
//! utility functions and guard patterns that the clone detector
//! otherwise flags as copy-paste.

use yunq_ast::{AstNode, NodeKind};

/// Returns the inner grammar-kind name for a `NodeKind::Other` node,
/// or `None` for neutral-AST node kinds. Every Python rule that
/// inspects argument lists or keyword arguments needs this.
pub fn other_kind_name(node: &AstNode) -> Option<&str> {
    match node.kind() {
        NodeKind::Other(name) => Some(name.as_ref()),
        _ => None,
    }
}

/// True when `path` belongs to a test-only file (test fixtures,
/// `_test.py` / `_test.rs`, or paths under `tests/` or `__test__/`).
/// Rules should call this before inspecting a file's AST to avoid
/// flagging test helpers as production issues.
pub fn is_test_file(path: &str) -> bool {
    yunq_rules_engine::is_test_only_path(path)
}
