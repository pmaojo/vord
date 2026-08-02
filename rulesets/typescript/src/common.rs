//! Shared AST helpers for vanilla TypeScript/JavaScript rules (no JSX — see
//! `rulesets/react` for that). `NodeKind` has no dedicated variant for most
//! grammar concepts these rules need (statements, expression wrappers,
//! regex literals, ...), so they're matched by their raw tree-sitter-
//! typescript kind name via `NodeKind::Other`, same convention
//! `rulesets/react::common` and `rulesets/reactive::common` use.

use vord_ast::{AstNode, NodeKind};

pub(crate) fn other_kind_name(node: &AstNode) -> Option<&str> {
    match node.kind() {
        NodeKind::Other(name) => Some(name.as_ref()),
        _ => None,
    }
}

pub(crate) fn is_other(node: &AstNode, kind: &str) -> bool {
    other_kind_name(node) == Some(kind)
}

/// The actual argument expressions of a `Call` node. tree-sitter-typescript
/// nests a single unnamed-in-the-neutral-vocabulary `arguments` wrapper
/// between the callee and the argument list, so `Call`'s own children are
/// just `[callee, arguments-wrapper]` (same layout `rulesets/react::common`
/// documents and relies on).
pub(crate) fn call_arguments(call: &AstNode) -> &[AstNode] {
    call.children()
        .get(1)
        .map(|args| args.children())
        .unwrap_or(&[])
}

#[cfg(test)]
mod tests {
    use super::*;
    use vord_ast::{LanguageIdentifier, SourceFile};
    use vord_rules_engine::AstParser;

    pub(crate) fn parse(code: &str) -> AstNode {
        let file = SourceFile::new("t.ts", code, LanguageIdentifier::typescript()).unwrap();
        vord_parser_typescript::TypeScriptParser::new()
            .parse(&file)
            .unwrap()
    }

    #[test]
    fn call_arguments_unwraps_the_arguments_node() {
        let ast = parse("f(a, b);\n");
        let call = ast
            .descendants()
            .find(|n| *n.kind() == NodeKind::Call)
            .unwrap();
        assert_eq!(call_arguments(call).len(), 2);
    }

    #[test]
    fn call_arguments_empty_for_no_args() {
        let ast = parse("f();\n");
        let call = ast
            .descendants()
            .find(|n| *n.kind() == NodeKind::Call)
            .unwrap();
        assert!(call_arguments(call).is_empty());
    }
}
