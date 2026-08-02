//! Shared AST helpers for React/JSX rules: hook-call recognition and JSX
//! element/attribute inspection. `NodeKind` has no dedicated JSX variants
//! (see `vord_ast::NodeKind`), so every JSX concept here is matched by its
//! raw tree-sitter-typescript grammar name via `NodeKind::Other`.

use vord_ast::{AstNode, NodeKind};

pub(crate) fn is_other(node: &AstNode, kind: &str) -> bool {
    matches!(node.kind(), NodeKind::Other(k) if k.as_ref() == kind)
}

/// True for any of the JSX element shapes a `.map()` callback or a plain
/// return statement might produce.
pub(crate) fn is_jsx_kind(node: &AstNode) -> bool {
    matches!(
        node.kind(),
        NodeKind::Other(k) if matches!(k.as_ref(), "jsx_element" | "jsx_self_closing_element" | "jsx_fragment")
    )
}

/// The opening tag node that carries the attributes: `jsx_element` delegates
/// to its `jsx_opening_element` child; `jsx_self_closing_element` carries its
/// attributes directly; a shorthand `jsx_fragment` (`<>...</>`) has none.
pub(crate) fn opening_tag(el: &AstNode) -> Option<&AstNode> {
    if is_other(el, "jsx_self_closing_element") {
        return Some(el);
    }
    if is_other(el, "jsx_element") {
        return el.children().first().filter(|c| is_other(c, "jsx_opening_element"));
    }
    None
}

/// The element's tag name (`div`, `Foo`, ...), if it's a plain identifier
/// (namespaced `<a.b>` / `<ns:tag>` names are left unhandled — rare in
/// practice and not worth the false-negative risk of guessing wrong).
pub(crate) fn tag_name(el: &AstNode) -> Option<&str> {
    let tag = opening_tag(el)?;
    let name_node = tag.first_child()?;
    (*name_node.kind() == NodeKind::Identifier).then(|| name_node.text())
}

pub(crate) fn attributes(el: &AstNode) -> Vec<&AstNode> {
    let Some(tag) = opening_tag(el) else { return Vec::new() };
    tag.children().iter().filter(|c| is_other(c, "jsx_attribute")).collect()
}

pub(crate) fn attribute_name(attr: &AstNode) -> Option<&str> {
    let name_node = attr.first_child()?;
    (*name_node.kind() == NodeKind::Identifier).then(|| name_node.text())
}

pub(crate) fn find_attribute<'a>(el: &'a AstNode, name: &str) -> Option<&'a AstNode> {
    attributes(el).into_iter().find(|a| attribute_name(a) == Some(name))
}

/// The attribute's value node: `None` for a bare boolean attribute
/// (`<input disabled />`), otherwise the `string` or `jsx_expression` child.
pub(crate) fn attribute_value(attr: &AstNode) -> Option<&AstNode> {
    attr.children().get(1)
}

/// The single expression a `jsx_expression` (`{...}`) wraps, if it has
/// exactly one — the common case for prop values.
pub(crate) fn jsx_expression_inner(node: &AstNode) -> Option<&AstNode> {
    is_other(node, "jsx_expression").then(|| node.children().first()).flatten()
}

/// Every non-`function_declaration`/`function_expression`/`arrow_function`
/// descendant of `node`, stopping at (but not descending past) a nested
/// `FunctionDef` boundary — the same "don't attribute an inner closure's
/// behavior to its enclosing function" rule `smells:cognitive-complexity`
/// uses to score nested functions independently.
pub(crate) fn own_scope_descendants(node: &AstNode) -> Vec<&AstNode> {
    fn walk<'a>(node: &'a AstNode, out: &mut Vec<&'a AstNode>) {
        for child in node.children() {
            out.push(child);
            if *child.kind() != NodeKind::FunctionDef {
                walk(child, out);
            }
        }
    }
    let mut out = Vec::new();
    walk(node, &mut out);
    out
}

/// The actual argument expressions of a `Call` node. tree-sitter-typescript
/// nests a single unnamed-in-the-neutral-vocabulary `arguments` wrapper
/// between the callee and the argument list (unlike e.g. Rust, which
/// flattens them as direct siblings), so `Call`'s own children are just
/// `[callee, arguments-wrapper]`.
pub(crate) fn call_arguments(call: &AstNode) -> &[AstNode] {
    call.children().get(1).map(|args| args.children()).unwrap_or(&[])
}

/// Every `.map(...)` call's inline callback function, for the rules that
/// inspect what a list-rendering callback returns
/// (`react:array-index-key`, `react:missing-list-key`).
pub(crate) fn map_callback_functions(ast: &AstNode) -> Vec<&AstNode> {
    ast.descendants()
        .filter(|n| *n.kind() == NodeKind::Call)
        .filter(|call| {
            call.first_child().is_some_and(|callee| {
                *callee.kind() == NodeKind::MemberAccess
                    && callee
                        .children()
                        .last()
                        .is_some_and(|p| *p.kind() == NodeKind::Identifier && p.text() == "map")
            })
        })
        .filter_map(|call| call_arguments(call).first().filter(|a| *a.kind() == NodeKind::FunctionDef))
        .collect()
}

/// The "logical" callee name of a call: the identifier itself for
/// `useState(...)`, or the accessed property for `React.useState(...)`.
pub(crate) fn callee_name(call: &AstNode) -> Option<&str> {
    let callee = call.first_child()?;
    match callee.kind() {
        NodeKind::Identifier => Some(callee.text()),
        NodeKind::MemberAccess => {
            let prop = callee.children().last()?;
            (*prop.kind() == NodeKind::Identifier).then(|| prop.text())
        }
        _ => None,
    }
}

/// The Hooks naming convention (`useState`, `useMyThing`, ...): `use`
/// followed by an uppercase letter or digit, per the same regex
/// `eslint-plugin-react-hooks` uses to recognize a hook by name alone.
pub(crate) fn is_hook_name(name: &str) -> bool {
    let rest = match name.strip_prefix("use") {
        Some(rest) => rest,
        None => return false,
    };
    rest.chars().next().is_some_and(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
}

/// If `node` is a call to something named like a hook, its name.
pub(crate) fn hook_call_name(node: &AstNode) -> Option<&str> {
    if *node.kind() != NodeKind::Call {
        return None;
    }
    callee_name(node).filter(|name| is_hook_name(name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use vord_ast::{LanguageIdentifier, SourceFile};
    use vord_rules_engine::AstParser;

    pub(crate) fn parse_tsx(code: &str) -> AstNode {
        let file = SourceFile::new("t.tsx", code, LanguageIdentifier::typescript()).unwrap();
        vord_parser_typescript::TypeScriptParser::new().parse(&file).unwrap()
    }

    #[test]
    fn recognizes_hook_names() {
        assert!(is_hook_name("useState"));
        assert!(is_hook_name("useEffect"));
        assert!(is_hook_name("use2FA"));
        assert!(!is_hook_name("user"));
        assert!(!is_hook_name("used"));
        assert!(!is_hook_name("use"));
        assert!(!is_hook_name("usefulThing"));
    }

    #[test]
    fn finds_jsx_attributes() {
        let ast = parse_tsx("const el = <img src=\"x.png\" alt=\"x\" />;\n");
        let img = ast.descendants().find(|n| is_jsx_kind(n)).unwrap();
        assert_eq!(tag_name(img), Some("img"));
        assert!(find_attribute(img, "alt").is_some());
        assert!(find_attribute(img, "missing").is_none());
    }

    #[test]
    fn call_arguments_unwraps_the_arguments_node() {
        let ast = parse_tsx("useEffect(() => {}, [a, b]);\n");
        let call = ast.descendants().find(|n| *n.kind() == NodeKind::Call).unwrap();
        assert_eq!(callee_name(call), Some("useEffect"));
        assert_eq!(call_arguments(call).len(), 2);
    }
}
