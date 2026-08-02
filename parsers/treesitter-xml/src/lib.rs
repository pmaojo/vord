//! Inbound adapter: XML → neutral AST via tree-sitter.
//! `tree-sitter-xml` exports two grammars (XML and DTD); this adapter uses
//! the XML one. XML is a pure data/markup format with no function or call
//! concept, so most node kinds fall through to `Other`.
//! tree-sitter types never escape this crate.

use vord_ast::{LanguageIdentifier, NodeKind};

vord_treesitter_adapter::declare_parser!(
    XmlParser,
    LanguageIdentifier::xml(),
    tree_sitter_xml::LANGUAGE_XML,
    map_kind
);

fn map_kind(kind: &str) -> NodeKind {
    match kind {
        "document" => NodeKind::SourceUnit,
        "CharData" | "AttValue" => NodeKind::StringLiteral,
        "Name" => NodeKind::Identifier,
        "Comment" => NodeKind::Comment,
        other => NodeKind::Other(vord_ast::intern(other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vord_ast::{AstNode, SourceFile};
    use vord_rules_engine::AstParser;

    fn parse(code: &str) -> AstNode {
        let file = SourceFile::new("test.xml", code, LanguageIdentifier::xml()).unwrap();
        XmlParser::new().parse(&file).unwrap()
    }

    #[test]
    fn maps_core_concepts() {
        let ast = parse(
            "<!-- TODO: refactor -->\n<note>\n  <to>Tove</to>\n  <from>Jani</from>\n</note>\n",
        );
        assert_eq!(ast.kind(), &NodeKind::SourceUnit);
        assert_eq!(ast.find_all(&NodeKind::Comment).len(), 1);
        assert!(!ast.find_all(&NodeKind::Identifier).is_empty());
        assert!(!ast.find_all(&NodeKind::StringLiteral).is_empty());
    }
}
