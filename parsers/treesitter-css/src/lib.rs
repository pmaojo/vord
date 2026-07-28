//! Inbound adapter: CSS → neutral AST via tree-sitter.
//! CSS has no function-definition concept, but `calc()`/`rgb()`/`url()`
//! style invocations are real calls and `property: value;` declarations are
//! assignment-shaped, so those get mapped; everything else (selectors,
//! at-rules, blocks) falls through to `Other`.
//! tree-sitter types never escape this crate.

use yunq_ast::{LanguageIdentifier, NodeKind};

yunq_treesitter_adapter::declare_parser!(
    CssParser,
    LanguageIdentifier::css(),
    tree_sitter_css::LANGUAGE,
    map_kind
);

fn map_kind(kind: &str) -> NodeKind {
    match kind {
        "stylesheet" => NodeKind::SourceUnit,
        "call_expression" => NodeKind::Call,
        "string_value" => NodeKind::StringLiteral,
        "identifier" => NodeKind::Identifier,
        "declaration" => NodeKind::Assignment,
        "comment" | "js_comment" => NodeKind::Comment,
        other => NodeKind::Other(yunq_ast::intern(other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use yunq_ast::{AstNode, SourceFile};
    use yunq_rules_engine::AstParser;

    fn parse(code: &str) -> AstNode {
        let file = SourceFile::new("test.css", code, LanguageIdentifier::css()).unwrap();
        CssParser::new().parse(&file).unwrap()
    }

    #[test]
    fn maps_core_concepts() {
        let ast = parse(
            "/* TODO: refactor */\n.foo {\n  color: red;\n  background: url(\"bg.png\");\n}\n",
        );
        assert_eq!(ast.kind(), &NodeKind::SourceUnit);
        assert_eq!(ast.find_all(&NodeKind::Comment).len(), 1);
        assert!(!ast.find_all(&NodeKind::Assignment).is_empty());
        assert!(!ast.find_all(&NodeKind::StringLiteral).is_empty());
    }

    #[test]
    fn url_is_a_call() {
        let ast = parse(".foo { background: url(\"bg.png\"); }\n");
        let calls = ast.find_all(&NodeKind::Call);
        assert!(calls.iter().any(|c| c.text().starts_with("url")));
    }
}
