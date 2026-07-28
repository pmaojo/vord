//! Inbound adapter: HTML → neutral AST via tree-sitter.
//! HTML is a markup language, not a programming language, so most node
//! kinds fall through to `Other`; only concepts that map cleanly onto the
//! neutral AST (comments, string-ish attribute values, element/attribute
//! names) are mapped.
//! tree-sitter types never escape this crate.

use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile, Span};
use yunq_rules_engine::{AstParser, ParseError};

pub struct HtmlParser;

impl HtmlParser {
    pub fn new() -> Self {
        Self
    }
}

impl Default for HtmlParser {
    fn default() -> Self {
        Self::new()
    }
}

impl AstParser for HtmlParser {
    fn language(&self) -> LanguageIdentifier {
        LanguageIdentifier::html()
    }

    fn parse(&self, file: &SourceFile) -> Result<AstNode, ParseError> {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_html::LANGUAGE.into())
            .map_err(|e| ParseError::Backend(e.to_string()))?;
        let tree = parser.parse(file.content(), None).ok_or_else(|| ParseError::Syntax {
            file: file.path().to_string(),
            detail: "tree-sitter produced no tree".to_string(),
        })?;
        Ok(convert(tree.root_node(), &file.content_shared()))
    }

    fn tokenize_for_duplication(
        &self,
        file: &SourceFile,
        normalization: yunq_cpd::TokenNormalization,
    ) -> Vec<(u32, String)> {
        let mut parser = tree_sitter::Parser::new();
        if parser.set_language(&tree_sitter_html::LANGUAGE.into()).is_err() {
            return yunq_cpd::fallback_tokenize(file);
        }
        let Some(tree) = parser.parse(file.content(), None) else {
            return yunq_cpd::fallback_tokenize(file);
        };
        yunq_treesitter_tokens::statement_lines_with(&tree, file.content(), normalization)
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
        "attribute_value" | "quoted_attribute_value" => NodeKind::StringLiteral,
        "tag_name" => NodeKind::Identifier,
        "comment" => NodeKind::Comment,
        other => NodeKind::Other(yunq_ast::intern(other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
