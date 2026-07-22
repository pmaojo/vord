//! Inbound adapter: C → neutral AST via tree-sitter.
//! tree-sitter types never escape this crate.

use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile, Span};
use yunq_rules_engine::{AstParser, ParseError};

pub struct CParser;

impl CParser {
    pub fn new() -> Self {
        Self
    }
}

impl Default for CParser {
    fn default() -> Self {
        Self::new()
    }
}

impl AstParser for CParser {
    fn language(&self) -> LanguageIdentifier {
        LanguageIdentifier::c()
    }

    fn parse(&self, file: &SourceFile) -> Result<AstNode, ParseError> {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_c::LANGUAGE.into())
            .map_err(|e| ParseError::Backend(e.to_string()))?;
        let tree = parser.parse(file.content(), None).ok_or_else(|| ParseError::Syntax {
            file: file.path().to_string(),
            detail: "tree-sitter produced no tree".to_string(),
        })?;
        Ok(convert(tree.root_node(), &file.content_shared()))
    }

    fn tokenize_for_duplication(&self, file: &SourceFile) -> Vec<(u32, String)> {
        let mut parser = tree_sitter::Parser::new();
        if parser.set_language(&tree_sitter_c::LANGUAGE.into()).is_err() {
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
        "translation_unit" => NodeKind::SourceUnit,
        "function_definition" => NodeKind::FunctionDef,
        "call_expression" => NodeKind::Call,
        "string_literal" | "system_lib_string" => NodeKind::StringLiteral,
        "identifier" | "field_identifier" => NodeKind::Identifier,
        "declaration" | "assignment_expression" => NodeKind::Assignment,
        "field_expression" | "pointer_expression" => NodeKind::MemberAccess,
        "comment" => NodeKind::Comment,
        other => NodeKind::Other(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(code: &str) -> AstNode {
        let file = SourceFile::new("test.c", code, LanguageIdentifier::c()).unwrap();
        CParser::new().parse(&file).unwrap()
    }

    #[test]
    fn maps_c_concepts() {
        let ast = parse("// TODO: refactor\nint main() {\n    printf(\"hello world\\n\");\n    return 0;\n}");
        assert_eq!(ast.kind(), &NodeKind::SourceUnit);
        assert_eq!(ast.find_all(&NodeKind::FunctionDef).len(), 1);
        assert_eq!(ast.find_all(&NodeKind::Comment).len(), 1);
        assert_eq!(ast.find_all(&NodeKind::Call).len(), 1);
    }
}
