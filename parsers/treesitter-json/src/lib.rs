//! Inbound adapter: JSON → neutral AST via tree-sitter.
//! JSON is a pure data format with no function/call concept, so `SourceUnit`
//! plus `StringLiteral`/`Comment` is the appropriate mapping; everything
//! else (objects, arrays, numbers, booleans, null) falls through to
//! `Other`.
//! tree-sitter types never escape this crate.

use vord_ast::{LanguageIdentifier, NodeKind};

vord_treesitter_adapter::declare_parser!(
    JsonParser,
    LanguageIdentifier::json(),
    tree_sitter_json::LANGUAGE,
    map_kind
);

fn map_kind(kind: &str) -> NodeKind {
    match kind {
        "document" => NodeKind::SourceUnit,
        "string" => NodeKind::StringLiteral,
        "comment" => NodeKind::Comment,
        other => NodeKind::Other(vord_ast::intern(other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vord_ast::{AstNode, SourceFile};
    use vord_rules_engine::AstParser;

    fn parse(code: &str) -> AstNode {
        let file = SourceFile::new("test.json", code, LanguageIdentifier::json()).unwrap();
        JsonParser::new().parse(&file).unwrap()
    }

    #[test]
    fn maps_core_concepts() {
        let ast = parse("{\"name\": \"vord\", \"tags\": [\"a\", \"b\"]}");
        assert_eq!(ast.kind(), &NodeKind::SourceUnit);
        assert!(!ast.find_all(&NodeKind::StringLiteral).is_empty());
    }

    #[test]
    fn nested_object_parses_without_error() {
        let ast = parse("{\"a\": {\"b\": 1, \"c\": [true, false, null]}}");
        assert_eq!(ast.kind(), &NodeKind::SourceUnit);
        assert_eq!(ast.find_all(&NodeKind::StringLiteral).len(), 3);
    }
}
