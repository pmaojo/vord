//! React Hook Dependency Graph Analysis.
//! Extracts free variables inside React hook closures (useEffect, useMemo, useCallback)
//! using scope tree resolution and compares them against the literal array AST node.

use std::collections::BTreeSet;
use vord_ast::{AstNode, NodeKind};
use vord_symbols::{free_identifiers, own_bindings};

#[derive(Debug, Clone)]
pub struct HookDepAnalysis {
    pub hook_name: String,
    pub closure_free_vars: BTreeSet<String>,
    pub declared_deps: BTreeSet<String>,
    pub missing_deps: BTreeSet<String>,
    pub unnecessary_deps: BTreeSet<String>,
}

pub struct ReactHookAnalyzer;

impl ReactHookAnalyzer {
    /// Analyzes a React hook call node (e.g. `useEffect(() => { ... }, [a, b])`).
    pub fn analyze(call_node: &AstNode) -> Option<HookDepAnalysis> {
        let callee = call_node.first_child()?;
        let hook_name = callee.text().to_string();

        if !is_react_hook_name(&hook_name) {
            return None;
        }

        let children = call_node.children();
        if children.len() < 2 {
            return None;
        }

        let closure_node = children
            .iter()
            .find(|c| *c.kind() == NodeKind::FunctionDef)?;

        let mut closure_free_vars = free_identifiers(closure_node);
        let own = own_bindings(closure_node);
        for bound in own {
            closure_free_vars.remove(&bound);
        }

        let mut declared_deps = BTreeSet::new();
        if let Some(deps_array) = children.iter().find(|c| {
            if let NodeKind::Other(k) = c.kind() {
                k.contains("array")
            } else {
                false
            }
        }) {
            for dep_elem in deps_array.children() {
                if *dep_elem.kind() == NodeKind::Identifier {
                    declared_deps.insert(dep_elem.text().to_string());
                }
            }
        }

        let missing_deps: BTreeSet<String> = closure_free_vars
            .difference(&declared_deps)
            .cloned()
            .collect();

        let unnecessary_deps: BTreeSet<String> = declared_deps
            .difference(&closure_free_vars)
            .cloned()
            .collect();

        Some(HookDepAnalysis {
            hook_name,
            closure_free_vars,
            declared_deps,
            missing_deps,
            unnecessary_deps,
        })
    }
}

fn is_react_hook_name(name: &str) -> bool {
    name == "useEffect" || name == "useMemo" || name == "useCallback" || name == "useLayoutEffect"
}

#[cfg(test)]
mod tests {
    use super::*;
    use vord_ast::Span;

    #[test]
    fn analyzes_missing_and_declared_hook_dependencies() {
        let fn_id = AstNode::new(
            NodeKind::Identifier,
            Span::new(1, 1, 1, 10),
            "useEffect",
            vec![],
        );
        let closure = AstNode::new(
            NodeKind::FunctionDef,
            Span::new(1, 1, 1, 30),
            "() => { console.log(count); }",
            vec![AstNode::new(
                NodeKind::Identifier,
                Span::new(1, 1, 1, 20),
                "count",
                vec![],
            )],
        );
        let deps_elem = AstNode::new(
            NodeKind::Identifier,
            Span::new(1, 1, 1, 35),
            "other",
            vec![],
        );
        let deps_arr = AstNode::new(
            NodeKind::Other("array_expression".into()),
            Span::new(1, 1, 1, 40),
            "[other]",
            vec![deps_elem],
        );

        let call_node = AstNode::new(
            NodeKind::Call,
            Span::new(1, 1, 1, 50),
            "useEffect(...)",
            vec![fn_id, closure, deps_arr],
        );

        let analysis = ReactHookAnalyzer::analyze(&call_node);
        assert!(analysis.is_some());
        let res = analysis.unwrap();
        assert!(res.missing_deps.contains("count"));
        assert!(res.unnecessary_deps.contains("other"));
    }
}
