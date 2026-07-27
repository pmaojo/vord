//! Shared AST helpers for Rust rules.

use yunq_ast::AstNode;

pub(crate) fn is_other(kind: &yunq_ast::NodeKind, name: &str) -> bool {
    matches!(kind, yunq_ast::NodeKind::Other(k) if k.as_ref() == name)
}

/// The trait an `impl` names, if any: tree-sitter-rust's `impl_item` exposes
/// no field distinguishing "trait" from "self type" in this neutral AST's
/// positional children, but the shapes are unambiguous — an optional leading
/// `type_parameters`, then either just the self type (inherent impl) or the
/// trait followed by the self type (trait impl), then the body.
pub(crate) fn trait_of_impl(node: &AstNode) -> Option<&AstNode> {
    let heads: Vec<&AstNode> = node
        .children()
        .iter()
        .filter(|c| {
            !is_other(c.kind(), "declaration_list")
                && !is_other(c.kind(), "where_clause")
                && !is_other(c.kind(), "type_parameters")
        })
        .collect();
    (heads.len() == 2).then(|| heads[0])
}

/// Whether `impl`'s named trait matches `name` (bare or path-qualified, e.g.
/// `Drop` or `std::ops::Drop`), ignoring any generic arguments.
pub(crate) fn impl_trait_is(node: &AstNode, name: &str) -> bool {
    trait_of_impl(node).is_some_and(|t| {
        let base = t.text().split('<').next().unwrap_or(t.text());
        base == name || base.ends_with(&format!("::{name}"))
    })
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
