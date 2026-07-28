//! Inbound adapter: HTML → neutral AST via tree-sitter.
//! HTML is a markup language, not a programming language, so most node
//! kinds fall through to `Other`; only concepts that map cleanly onto the
//! neutral AST (comments, string-ish attribute values, element/attribute
//! names) are mapped.
//! tree-sitter types never escape this crate.

use yunq_ast::{LanguageIdentifier, NodeKind};

yunq_treesitter_adapter::declare_parser!(
    HtmlParser,
    LanguageIdentifier::html(),
    tree_sitter_html::LANGUAGE,
    map_kind
);

fn map_kind(kind: &str) -> NodeKind {
    match kind {
        "document" => NodeKind::SourceUnit,
        "attribute_value" | "quoted_attribute_value" => NodeKind::StringLiteral,
        "tag_name" => NodeKind::Identifier,
        "comment" => NodeKind::Comment,
        other => NodeKind::Other(yunq_ast::intern(other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use yunq_ast::{AstNode, SourceFile};
    use yunq_rules_engine::AstParser;

    fn parse(code: &str) -> AstNode {
        let file = SourceFile::new("test.html", code, LanguageIdentifier::html()).unwrap();
        HtmlParser::new().parse(&file).unwrap()
    }

    #[test]
    fn maps_core_concepts() {
        let ast = parse(
            "<html>\n<!-- TODO: refactor -->\n<body class=\"main\"><p>hi</p></body>\n</html>\n",
        );
        assert_eq!(ast.kind(), &NodeKind::SourceUnit);
        assert_eq!(ast.find_all(&NodeKind::Comment).len(), 1);
        assert!(!ast.find_all(&NodeKind::StringLiteral).is_empty());
        assert!(!ast.find_all(&NodeKind::Identifier).is_empty());
    }
}
