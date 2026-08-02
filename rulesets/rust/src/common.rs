//! Shared AST helpers for Rust rules.

use vord_ast::AstNode;

pub(crate) fn is_other(kind: &vord_ast::NodeKind, name: &str) -> bool {
    matches!(kind, vord_ast::NodeKind::Other(k) if k.as_ref() == name)
}

/// An `impl`'s non-body, non-generics children, in source order:
/// `[self_type]` for an inherent impl, `[trait, self_type]` for a trait impl.
/// tree-sitter-rust's `impl_item` exposes no field distinguishing "trait"
/// from "self type" in this neutral AST's positional children, but the
/// shapes are unambiguous once `type_parameters`/`declaration_list`/
/// `where_clause` are filtered out.
fn impl_heads(node: &AstNode) -> Vec<&AstNode> {
    node.children()
        .iter()
        .filter(|c| {
            !is_other(c.kind(), "declaration_list")
                && !is_other(c.kind(), "where_clause")
                && !is_other(c.kind(), "type_parameters")
        })
        .collect()
}

/// The trait an `impl` names, if any (`None` for an inherent impl).
pub(crate) fn trait_of_impl(node: &AstNode) -> Option<&AstNode> {
    let heads = impl_heads(node);
    (heads.len() == 2).then(|| heads[0])
}

/// The type an `impl` is written against — the self type of `impl Trait for
/// Self`, or the sole type of an inherent `impl Self`.
pub(crate) fn self_type_of_impl(node: &AstNode) -> Option<&AstNode> {
    impl_heads(node).last().copied()
}

/// Whether `impl`'s named trait matches `name` (bare or path-qualified, e.g.
/// `Drop` or `std::ops::Drop`), ignoring any generic arguments.
pub(crate) fn impl_trait_is(node: &AstNode, name: &str) -> bool {
    trait_of_impl(node).is_some_and(|t| {
        let base = t.text().split('<').next().unwrap_or(t.text());
        base == name || base.ends_with(&format!("::{name}"))
    })
}

/// The two named children of a `binary_expression` are its operands; the
/// operator token itself is anonymous in tree-sitter-rust's grammar and
/// doesn't survive conversion to this neutral AST as a node, so it's read
/// back out of the raw source between the two operand spans.
pub(crate) fn operator_between<'a>(source: &'a str, left: &AstNode, right: &AstNode) -> &'a str {
    source
        .get(left.byte_range().end..right.byte_range().start)
        .unwrap_or("")
        .trim()
}

/// Whether the contiguous run of comment lines directly above `start_line`
/// (1-based) mentions `SAFETY`. Stops at the first line that is neither a
/// `//` comment nor blank, so an unrelated `SAFETY` comment documenting an
/// earlier, different block doesn't count for this one.
pub(crate) fn has_safety_comment_directly_above(lines: &[&str], start_line: u32) -> bool {
    let mut found = false;
    for line in lines[..start_line.saturating_sub(1) as usize].iter().rev() {
        let trimmed = line.trim();
        if !trimmed.starts_with("//") {
            break;
        }
        if trimmed.to_ascii_lowercase().contains("safety") {
            found = true;
        }
    }
    found
}
