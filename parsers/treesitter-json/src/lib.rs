//! Inbound adapter: JSON → neutral AST via tree-sitter.
//! JSON is a pure data format with no function/call concept, so `SourceUnit`
//! plus `StringLiteral`/`Comment` is the appropriate mapping; everything
//! else (objects, arrays, numbers, booleans, null) falls through to
//! `Other`.
//! tree-sitter types never escape this crate.

use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile, Span};
use yunq_rules_engine::{AstParser, ParseError};

pub struct JsonParser;

impl JsonParser {
    pub fn new() -> Self {
        Self
    }
}

impl Default for JsonParser {
    fn default() -> Self {
        Self::new()
    }
}

impl AstParser for JsonParser {
    fn language(&self) -> LanguageIdentifier {
        LanguageIdentifier::json()
    }

    fn parse(&self, file: &SourceFile) -> Result<AstNode, ParseError> {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_json::LANGUAGE.into())
            .map_err(|e| ParseError::Backend(e.to_string()))?;
        let tree = parser.parse(file.content(), None).ok_or_else(|| ParseError::Syntax {
            file: file.path().to_string(),
            detail: "tree-sitter produced no tree".to_string(),
        })?;
        Ok(convert(tree.root_node(), &file.content_shared()))
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
        "string" => NodeKind::StringLiteral,
        "comment" => NodeKind::Comment,
        other => NodeKind::Other(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(code: &str) -> AstNode {
        let file = SourceFile::new("test.json", code, LanguageIdentifier::json()).unwrap();
        JsonParser::new().parse(&file).unwrap()
    }

    #[test]
    fn maps_core_concepts() {
        let ast = parse("{\"name\": \"yunq\", \"tags\": [\"a\", \"b\"]}");
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
