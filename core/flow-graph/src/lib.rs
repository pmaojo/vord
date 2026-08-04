//! Same-file function call graph over the neutral AST: which named function
//! calls which other named function, by textual name resolution — no
//! cross-file linking, no type information, no dynamic dispatch. This is
//! the minimal building block `vord-flow-risk` needs to walk *sequences* of
//! functions (`A` calls `B` calls `C`) rather than scoring one function at a
//! time the way `vord-crap` already does.
//!
//! Deliberately narrow, matching the honesty other same-file, name-based
//! heuristics in this codebase already commit to (see
//! `rulesets/code-smells::cognitive_complexity::is_recursive_call`'s own
//! doc comment): a call is only resolved when its callee name matches
//! another *named* function declared in the same file. Anonymous
//! functions/closures (no name in their own `FunctionDef` — the overwhelming
//! case for `const f = () => {}`-style JS/TS) are invisible to this graph,
//! both as callers and as callees, since there is no name to resolve them
//! by. A call to an imported or cross-file function is silently dropped for
//! the same reason `module_graph.rs`'s ES-module resolution exists as a
//! *separate*, taint-specific concern this crate does not pull in: cross-file
//! call resolution is real work, not something to bolt on as a side effect.

use std::collections::{HashMap, HashSet};

use vord_ast::{AstNode, NodeKind, Span};

/// One named function: its declared name and source span.
#[derive(Clone, Debug, PartialEq)]
pub struct FunctionSymbol {
    pub name: String,
    pub span: Span,
}

/// A same-file call edge: `functions[caller]` calls `functions[callee]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CallEdge {
    pub caller: usize,
    pub callee: usize,
}

/// One file's call graph: every named function found, plus every same-file
/// call edge resolved between them.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct CallGraph {
    pub functions: Vec<FunctionSymbol>,
    pub edges: Vec<CallEdge>,
}

impl CallGraph {
    /// Functions `caller` calls directly, in this file.
    pub fn callees(&self, caller: usize) -> impl Iterator<Item = usize> + '_ {
        self.edges
            .iter()
            .filter(move |e| e.caller == caller)
            .map(|e| e.callee)
    }

    /// Functions with no incoming same-file call edge — candidate entry
    /// points for flow detection. A function called only from another file
    /// (or only from a test) looks like a root too: this graph has no way
    /// to tell, since it never looks outside the one file it was built
    /// from. That is a source of false *candidates*, never a source of
    /// false untested-sequence findings — a root that turns out to have an
    /// external caller just means the reported chain's starting point is
    /// misleading, not that the coverage gap it found downstream is wrong.
    pub fn roots(&self) -> Vec<usize> {
        let called: HashSet<usize> = self.edges.iter().map(|e| e.callee).collect();
        (0..self.functions.len())
            .filter(|i| !called.contains(i))
            .collect()
    }
}

/// The declared name of a `FunctionDef`, if it has one — the first
/// `Identifier` among its direct children (parser adapters place a
/// function's own name there; parameters/generics/body are never bare
/// `Identifier` nodes at that level). Closures/lambdas have no such child.
fn function_name(function: &AstNode) -> Option<&str> {
    function
        .children()
        .iter()
        .find(|c| *c.kind() == NodeKind::Identifier)
        .map(|c| c.text())
}

/// The name a call's callee resolves to: a plain `foo()` call, or a
/// method-style `self.foo()`/`obj.foo()` call, resolved to its final
/// segment (`foo`).
fn callee_name(call: &AstNode) -> Option<&str> {
    let callee = call.first_child()?;
    match callee.kind() {
        NodeKind::Identifier => Some(callee.text()),
        NodeKind::MemberAccess => callee
            .children()
            .iter()
            .rev()
            .find(|c| *c.kind() == NodeKind::Identifier)
            .map(|c| c.text()),
        _ => None,
    }
}

/// Every `Call` node textually inside `node`, not recursing into a nested
/// `FunctionDef` — a call made inside a nested closure belongs to that
/// closure's own (possibly anonymous, possibly invisible-to-this-graph)
/// scope, not to the enclosing named function. Mirrors the same
/// nested-function exclusion `core/rules-engine`'s cyclomatic-complexity
/// walk already uses.
fn calls_in<'a>(node: &'a AstNode, out: &mut Vec<&'a AstNode>) {
    for child in node.children() {
        if *child.kind() == NodeKind::FunctionDef {
            continue;
        }
        if *child.kind() == NodeKind::Call {
            out.push(child);
        }
        calls_in(child, out);
    }
}

/// Builds `ast`'s call graph: every named `FunctionDef`, and every call
/// among them resolved by name. Duplicate names (two functions declared
/// with the same name in one file — unusual, but legal in some grammars for
/// overloads) resolve to whichever was encountered first, the same
/// first-definition-wins fallback `module_graph.rs` documents for its own
/// by-name resolution.
pub fn build(ast: &AstNode) -> CallGraph {
    let named: Vec<(&AstNode, String)> = ast
        .descendants()
        .filter(|n| *n.kind() == NodeKind::FunctionDef)
        .filter_map(|f| function_name(f).map(|name| (f, name.to_string())))
        .collect();

    let functions: Vec<FunctionSymbol> = named
        .iter()
        .map(|(node, name)| FunctionSymbol {
            name: name.clone(),
            span: node.span(),
        })
        .collect();

    let mut by_name: HashMap<&str, usize> = HashMap::new();
    for (index, function) in functions.iter().enumerate() {
        by_name.entry(function.name.as_str()).or_insert(index);
    }

    let mut edges = Vec::new();
    for (caller, (node, _)) in named.iter().enumerate() {
        let mut calls = Vec::new();
        calls_in(node, &mut calls);
        for call in calls {
            let Some(name) = callee_name(call) else {
                continue;
            };
            let Some(&callee) = by_name.get(name) else {
                continue;
            };
            if callee == caller {
                continue;
            }
            edges.push(CallEdge { caller, callee });
        }
    }
    edges.sort_by_key(|e| (e.caller, e.callee));
    edges.dedup();

    CallGraph { functions, edges }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ident(name: &str) -> AstNode {
        AstNode::new(NodeKind::Identifier, Span::new(1, 1, 1, 1), name, vec![])
    }

    fn call(callee: AstNode) -> AstNode {
        AstNode::new(NodeKind::Call, Span::new(1, 1, 1, 1), "", vec![callee])
    }

    fn function_def(name: &str, span: Span, body: Vec<AstNode>) -> AstNode {
        let mut children = vec![ident(name)];
        children.extend(body);
        AstNode::new(NodeKind::FunctionDef, span, "", children)
    }

    #[test]
    fn builds_edges_between_named_functions_in_call_order() {
        // fn a() { b(); } fn b() { c(); } fn c() {}
        let c = function_def("c", Span::new(3, 1, 3, 5), vec![]);
        let b = function_def("b", Span::new(2, 1, 2, 10), vec![call(ident("c"))]);
        let a = function_def("a", Span::new(1, 1, 1, 10), vec![call(ident("b"))]);
        let root = AstNode::new(NodeKind::SourceUnit, Span::new(1, 1, 3, 5), "", vec![a, b, c]);

        let graph = build(&root);

        assert_eq!(graph.functions.len(), 3);
        let index_of = |name: &str| {
            graph
                .functions
                .iter()
                .position(|f| f.name == name)
                .unwrap()
        };
        let (a_i, b_i, c_i) = (index_of("a"), index_of("b"), index_of("c"));
        assert!(graph.callees(a_i).eq([b_i]));
        assert!(graph.callees(b_i).eq([c_i]));
        assert_eq!(graph.roots(), vec![a_i]);
    }

    #[test]
    fn method_style_calls_resolve_by_their_final_segment() {
        let helper = function_def("helper", Span::new(2, 1, 2, 5), vec![]);
        let member_call = call(AstNode::new(
            NodeKind::MemberAccess,
            Span::new(1, 1, 1, 1),
            "",
            vec![ident("self"), ident("helper")],
        ));
        let entry = function_def("entry", Span::new(1, 1, 1, 10), vec![member_call]);
        let root = AstNode::new(
            NodeKind::SourceUnit,
            Span::new(1, 1, 2, 5),
            "",
            vec![entry, helper],
        );

        let graph = build(&root);

        let entry_i = graph.functions.iter().position(|f| f.name == "entry").unwrap();
        let helper_i = graph.functions.iter().position(|f| f.name == "helper").unwrap();
        assert!(graph.callees(entry_i).eq([helper_i]));
    }

    #[test]
    fn anonymous_functions_produce_no_node_and_no_edge() {
        // fn outer() { const f = () => { helper(); }; }  — the closure has
        // no name, so it never becomes a graph node, and its call to
        // `helper` is invisible (it's inside a nested FunctionDef).
        let closure_body = call(ident("helper"));
        let closure = AstNode::new(
            NodeKind::FunctionDef,
            Span::new(1, 2, 1, 9),
            "",
            vec![closure_body],
        );
        let outer = AstNode::new(
            NodeKind::FunctionDef,
            Span::new(1, 1, 1, 10),
            "",
            vec![ident("outer"), closure],
        );
        let helper = function_def("helper", Span::new(2, 1, 2, 5), vec![]);
        let root = AstNode::new(
            NodeKind::SourceUnit,
            Span::new(1, 1, 2, 5),
            "",
            vec![outer, helper],
        );

        let graph = build(&root);

        assert_eq!(graph.functions.len(), 2);
        let outer_i = graph.functions.iter().position(|f| f.name == "outer").unwrap();
        assert_eq!(graph.callees(outer_i).count(), 0);
    }

    #[test]
    fn self_recursive_calls_produce_no_edge() {
        let a = function_def("a", Span::new(1, 1, 1, 10), vec![call(ident("a"))]);
        let root = AstNode::new(NodeKind::SourceUnit, Span::new(1, 1, 1, 10), "", vec![a]);

        let graph = build(&root);

        let a_i = graph.functions.iter().position(|f| f.name == "a").unwrap();
        assert_eq!(graph.callees(a_i).count(), 0);
        assert_eq!(graph.roots(), vec![a_i]);
    }

    #[test]
    fn unresolved_callee_names_are_dropped() {
        let a = function_def("a", Span::new(1, 1, 1, 10), vec![call(ident("not_declared_here"))]);
        let root = AstNode::new(NodeKind::SourceUnit, Span::new(1, 1, 1, 10), "", vec![a]);

        let graph = build(&root);

        assert_eq!(graph.edges.len(), 0);
    }
}
