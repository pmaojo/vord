//! Inbound adapter: XML → neutral AST via tree-sitter.
//! `tree-sitter-xml` exports two grammars (XML and DTD); this adapter uses
//! the XML one. XML is a pure data/markup format with no function or call
//! concept, so most node kinds fall through to `Other`.
//! tree-sitter types never escape this crate.

use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile, Span};
use yunq_rules_engine::{AstParser, ParseError};

pub struct XmlParser;

impl XmlParser {
    pub fn new() -> Self {
        Self
    }
}

impl Default for XmlParser {
    fn default() -> Self {
        Self::new()
    }
}

impl AstParser for XmlParser {
    fn language(&self) -> LanguageIdentifier {
        LanguageIdentifier::xml()
    }

    fn parse(&self, file: &SourceFile) -> Result<AstNode, ParseError> {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_xml::LANGUAGE_XML.into())
            .map_err(|e| ParseError::Backend(e.to_string()))?;
        let tree = parser.parse(file.content(), None).ok_or_else(|| ParseError::Syntax {
            file: file.path().to_string(),
            detail: "tree-sitter produced no tree".to_string(),
        })?;
        Ok(convert(tree.root_node(), &file.content_shared()))
    }

    fn tokenize_for_duplication(&self, file: &SourceFile) -> Vec<(u32, String)> {
        let mut parser = tree_sitter::Parser::new();
        if parser.set_language(&tree_sitter_xml::LANGUAGE_XML.into()).is_err() {
            return yunq_cpd::fallback_tokenize(file);
        }
        let Some(tree) = parser.parse(file.content(), None) else {
            return yunq_cpd::fallback_tokenize(file);
        };
        yunq_treesitter_tokens::statement_lines(&tree, file.content())
    }
}

fn convert(node: tree_sitter::Node<'_>, source: &std::sync::Arc<str>) -> AstNode {
    let mut cursor = node.walk();
    let children = node.named_children(&mut cursor).map(|c| convert(c, source)).collect();
    AstNode::from_source(
        map_kind(node.kind()),
        span_of(node),
        std::sync::Arc::clone(source),
        node.byte_range(),
        children,
    )
}

fn span_of(node: tree_sitter::Node<'_>) -> Span {
    let (start, end) = (node.start_position(), node.end_position());
    Span::new(start.row as u32 + 1, start.column as u32 + 1, end.row as u32 + 1, end.column as u32 + 1)
}

fn map_kind(kind: &str) -> NodeKind {
    match kind {
        "document" => NodeKind::SourceUnit,
        "CharData" | "AttValue" => NodeKind::StringLiteral,
        "Name" => NodeKind::Identifier,
        "Comment" => NodeKind::Comment,
        other => NodeKind::Other(yunq_ast::intern(other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
