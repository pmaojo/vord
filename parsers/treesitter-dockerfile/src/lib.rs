//! Inbound adapter: Dockerfile → neutral AST via tree-sitter.
//! tree-sitter types never escape this crate.

use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile, Span};
use yunq_rules_engine::{AstParser, ParseError};

pub struct DockerfileParser;

impl DockerfileParser {
    pub fn new() -> Self {
        Self
    }
}

impl Default for DockerfileParser {
    fn default() -> Self {
        Self::new()
    }
}

impl AstParser for DockerfileParser {
    fn language(&self) -> LanguageIdentifier {
        LanguageIdentifier::dockerfile()
    }

    fn parse(&self, file: &SourceFile) -> Result<AstNode, ParseError> {
        let mut parser = tree_sitter::Parser::new();
        let lang: tree_sitter::Language = unsafe { std::mem::transmute(tree_sitter_dockerfile::language()) };
        parser
            .set_language(&lang)
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
        "source_file" => NodeKind::SourceUnit,
        "from_instruction" | "run_instruction" | "cmd_instruction" => NodeKind::FunctionDef,
        "comment" => NodeKind::Comment,
        other => NodeKind::Other(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(code: &str) -> AstNode {
        let file = SourceFile::new("Dockerfile", code, LanguageIdentifier::dockerfile()).unwrap();
        DockerfileParser::new().parse(&file).unwrap()
    }

    #[test]
    fn maps_dockerfile_concepts() {
        let ast = parse("# syntax=docker/dockerfile:1\nFROM alpine:3.18\nRUN echo hello\n");
        assert_eq!(ast.kind(), &NodeKind::SourceUnit);
        assert_eq!(ast.find_all(&NodeKind::Comment).len(), 1);
        assert_eq!(ast.find_all(&NodeKind::FunctionDef).len(), 2);
    }
}
