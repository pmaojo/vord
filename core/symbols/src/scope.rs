//! Same-file lexical scope resolution: which identifiers are bound within a
//! function's own scope (parameters, local declarations, destructured
//! patterns), and — building on that — which identifiers referenced inside a
//! nested function are *free* (captured from an enclosing scope) rather than
//! locally bound. This is the minimal piece of "symbol table" needed by
//! `react:exhaustive-deps`: no type information, just binding sites.
//!
//! Deliberately not a full scope-chain implementation (no block scoping,
//! no shadowing detection beyond "nearest enclosing binder wins"): a lint
//! support structure, not a compiler's resolver.

use std::collections::BTreeSet;

use vord_ast::{AstNode, NodeKind};

/// Grammar node kinds (`NodeKind::Other`) that wrap a destructuring pattern
/// whose leaf identifiers are all newly bound names, not references to
/// existing bindings. Both object (`{a, b}`) and array (`[a, b]`) patterns,
/// across the TS/JS grammar (the only grammar this module currently serves).
const PATTERN_KINDS: &[&str] = &[
    "object_pattern",
    "array_pattern",
    "pair_pattern",
    "rest_pattern",
    "assignment_pattern",
];

/// Every name bound directly by one declaration/parameter node — handles
/// plain identifiers and (TS/JS) destructuring patterns.
fn bound_names(node: &AstNode, out: &mut BTreeSet<String>) {
    match node.kind() {
        NodeKind::Identifier => {
            out.insert(node.text().to_string());
        }
        NodeKind::Other(kind) if PATTERN_KINDS.contains(&kind.as_ref()) => {
            for child in node.children() {
                bound_names(child, out);
            }
        }
        _ => {}
    }
}

/// The set of names a `FunctionDef` node itself binds: its parameters, plus
/// every local declaration in its own scope (not descending into a nested
/// `FunctionDef` — that's a separate scope with its own binding set).
///
/// `params_container_kinds` matches the wrapper node (`formal_parameters`,
/// `parameters`, ...) tree-sitter grammars use to group a function's
/// parameter list; every identifier/pattern found in it is a binding.
pub fn own_bindings(function: &AstNode) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    for child in function.children() {
        match child.kind() {
            NodeKind::Other(kind) if kind.as_ref().contains("parameter") => {
                collect_pattern_leaves(child, &mut names);
            }
            _ => {}
        }
    }
    walk_own_scope(function, true, &mut names);
    names
}

/// Descends `node`'s children collecting declaration/pattern bindings,
/// stopping at (not descending past) a nested `FunctionDef` boundary.
/// `is_root` skips re-processing the function's own parameter list (already
/// handled by the caller) on the first call.
fn walk_own_scope(node: &AstNode, is_root: bool, out: &mut BTreeSet<String>) {
    for child in node.children() {
        if !is_root {
            match child.kind() {
                NodeKind::VariableDecl => {
                    if let Some(target) = child.first_child() {
                        bound_names(target, out);
                    }
                }
                NodeKind::Other(kind) if kind.as_ref().contains("parameter") => {
                    collect_pattern_leaves(child, out);
                }
                _ => {}
            }
        }
        if *child.kind() != NodeKind::FunctionDef {
            walk_own_scope(child, false, out);
        } else if !is_root {
            // A nested function's *name* (if it's a named declaration, not
            // an anonymous arrow/closure) is itself a binding visible in the
            // outer scope.
            if let Some(name) = child
                .first_child()
                .filter(|n| *n.kind() == NodeKind::Identifier)
            {
                out.insert(name.text().to_string());
            }
        }
    }
}

/// Collects every identifier leaf under a parameter/pattern wrapper as a
/// bound name (handles plain params, typed params, and destructured params).
fn collect_pattern_leaves(node: &AstNode, out: &mut BTreeSet<String>) {
    if *node.kind() == NodeKind::Identifier {
        out.insert(node.text().to_string());
        return;
    }
    bound_names(node, out);
    for child in node.children() {
        collect_pattern_leaves(child, out);
    }
}

/// Every free identifier referenced in `body` (typically a hook callback's
/// `FunctionDef`): names used but not bound by `body`'s own scope. Skips
/// identifiers that are themselves declaration targets, member-access
/// property names (`obj.prop`'s `prop`, not a reference to a `prop`
/// binding), and call callees that are never treated as data dependencies by
/// convention — callers filter those further as needed.
pub fn free_identifiers(body: &AstNode) -> BTreeSet<String> {
    let own = own_bindings(body);
    let mut free = BTreeSet::new();
    collect_free(body, &own, &mut free, true);
    free
}

fn collect_free(
    node: &AstNode,
    own: &BTreeSet<String>,
    free: &mut BTreeSet<String>,
    is_root: bool,
) {
    match node.kind() {
        NodeKind::Identifier if !is_root => {
            if !own.contains(node.text()) {
                free.insert(node.text().to_string());
            }
            return;
        }
        NodeKind::VariableDecl => {
            // Skip the declaration target(s); only the initializer(s) can
            // reference free variables.
            for value in &node.children()[1..] {
                collect_free(value, own, free, false);
            }
            return;
        }
        NodeKind::MemberAccess => {
            // Only the base of a member chain can be a free reference; the
            // property name(s) are not identifier lookups.
            if let Some(base) = node.first_child() {
                collect_free(base, own, free, false);
            }
            return;
        }
        NodeKind::FunctionDef if !is_root => {
            // A nested closure's free variables are still free with respect
            // to `body` unless bound by `body`'s own scope (already unioned
            // into `own` is wrong for closures declared *inside* body with
            // their own params — but those params shadow, so recurse with
            // the same `own` plus the closure's own bindings).
            let mut nested_own = own.clone();
            nested_own.extend(own_bindings(node));
            for child in node.children() {
                collect_free(child, &nested_own, free, false);
            }
            return;
        }
        _ => {}
    }
    for child in node.children() {
        collect_free(child, own, free, false);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vord_ast::{LanguageIdentifier, SourceFile};
    use vord_rules_engine::AstParser;

    fn parse(code: &str) -> AstNode {
        let file = SourceFile::new("t.tsx", code, LanguageIdentifier::typescript()).unwrap();
        vord_parser_typescript::TypeScriptParser::new()
            .parse(&file)
            .unwrap()
    }

    fn first_function<'a>(ast: &'a AstNode, name: &str) -> &'a AstNode {
        ast.descendants()
            .find(|n| {
                *n.kind() == NodeKind::FunctionDef
                    && n.first_child()
                        .is_some_and(|c| *c.kind() == NodeKind::Identifier && c.text() == name)
            })
            .unwrap()
    }

    #[test]
    fn own_bindings_includes_params_and_locals() {
        let ast = parse("function f(a, b) {\n  const c = a + b;\n  let [d, e] = [1, 2];\n}\n");
        let f = first_function(&ast, "f");
        let bindings = own_bindings(f);
        assert!(bindings.contains("a"));
        assert!(bindings.contains("b"));
        assert!(bindings.contains("c"));
        assert!(bindings.contains("d"));
        assert!(bindings.contains("e"));
    }

    #[test]
    fn own_bindings_excludes_nested_function_locals() {
        let ast = parse("function f() {\n  function inner() {\n    const x = 1;\n  }\n}\n");
        let f = first_function(&ast, "f");
        let bindings = own_bindings(f);
        assert!(!bindings.contains("x"));
        assert!(bindings.contains("inner"));
    }

    #[test]
    fn free_identifiers_finds_captured_outer_names() {
        // Simulates a useEffect callback: `count` and `other` are free
        // (from the enclosing component), `local` is bound inside.
        let ast = parse(
            "function comp() {\n  const cb = () => {\n    const local = 1;\n    doThing(count, other, local);\n  };\n}\n",
        );
        // Locate the arrow function assigned to `cb`.
        let arrow = ast
            .descendants()
            .find(|n| *n.kind() == NodeKind::FunctionDef && n.text().starts_with("() =>"))
            .unwrap();
        let free = free_identifiers(arrow);
        assert!(free.contains("count"), "{free:?}");
        assert!(free.contains("other"), "{free:?}");
        assert!(free.contains("doThing"), "{free:?}");
        assert!(!free.contains("local"), "{free:?}");
    }

    #[test]
    fn free_identifiers_excludes_member_access_property_names() {
        let arrow = {
            let ast = parse("const cb = () => { console.log(x); };\n");
            ast.descendants()
                .find(|n| *n.kind() == NodeKind::FunctionDef)
                .cloned()
                .unwrap()
        };
        let free = free_identifiers(&arrow);
        assert!(free.contains("console"));
        assert!(!free.contains("log"));
        assert!(free.contains("x"));
    }
}
