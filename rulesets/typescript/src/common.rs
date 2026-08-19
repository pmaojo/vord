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

/// Whether a `FunctionDef` node is a generator (`function* name() {}` /
/// `async function* name() {}`). Generators use `yield` instead of
/// `await`/`return` as their primary control-flow keyword and their real
/// return type is `(Async)Generator`/`(Async)IterableIterator`, not
/// `Promise<T>` — rules built around "async functions always return a
/// `Promise`" or "an async function should `await` something" must exclude
/// generators to avoid false positives on legitimate `async function*`.
/// Detected from the node's own text (no dedicated `NodeKind` for the `*`
/// token): the `*` appears right after the `function` keyword, before the
/// name and parameter list.
pub(crate) fn is_generator(func: &AstNode) -> bool {
    let text = func.text().trim_start();
    let text = text.strip_prefix("async").map(str::trim_start).unwrap_or(text);
    let Some(rest) = text.strip_prefix("function") else {
        return false;
    };
    rest.trim_start().starts_with('*')
}

/// Whether `word` occurs in `haystack` as a whole identifier (not as a
/// substring of a longer identifier) — a plain `str::contains` would also
/// match `T` inside `TFoo` or `NotT`.
pub(crate) fn contains_word(haystack: &str, word: &str) -> bool {
    if word.is_empty() {
        return false;
    }
    let bytes = haystack.as_bytes();
    let wbytes = word.as_bytes();
    let wlen = wbytes.len();
    if wlen > bytes.len() {
        return false;
    }
    (0..=bytes.len() - wlen).any(|i| {
        &bytes[i..i + wlen] == wbytes
            && (i == 0 || !is_ident_byte(bytes[i - 1]))
            && (i + wlen == bytes.len() || !is_ident_byte(bytes[i + wlen]))
    })
}

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'$'
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

    #[test]
    fn contains_word_matches_whole_identifier_only() {
        assert!(contains_word("value: T;", "T"));
        assert!(!contains_word("value: TFoo;", "T"));
        assert!(!contains_word("value: NotT;", "T"));
        assert!(contains_word("a, T, b", "T"));
    }
}
