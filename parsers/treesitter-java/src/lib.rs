//! Inbound adapter: Java → neutral AST via tree-sitter.
//! tree-sitter types never escape this crate.

use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile, Span};
use yunq_rules_engine::{AstParser, ParseError};

pub struct JavaParser;

impl JavaParser {
    pub fn new() -> Self {
        Self
    }
}

impl Default for JavaParser {
    fn default() -> Self {
        Self::new()
    }
}

impl AstParser for JavaParser {
    fn language(&self) -> LanguageIdentifier {
        LanguageIdentifier::java()
    }

    fn parse(&self, file: &SourceFile) -> Result<AstNode, ParseError> {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_java::LANGUAGE.into())
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
        if parser.set_language(&tree_sitter_java::LANGUAGE.into()).is_err() {
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
        "program" | "compilation_unit" => NodeKind::SourceUnit,
        "method_declaration" | "constructor_declaration" => NodeKind::FunctionDef,
        "method_invocation" | "object_creation_expression" => NodeKind::Call,
        "string_literal" => NodeKind::StringLiteral,
        "identifier" => NodeKind::Identifier,
        "local_variable_declaration" | "assignment_expression" => NodeKind::Assignment,
        "field_access" => NodeKind::MemberAccess,
        "line_comment" | "block_comment" => NodeKind::Comment,
        other => NodeKind::Other(yunq_ast::intern(other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(code: &str) -> AstNode {
        let file = SourceFile::new("Test.java", code, LanguageIdentifier::java()).unwrap();
        JavaParser::new().parse(&file).unwrap()
    }

    #[test]
    fn maps_java_concepts() {
        let ast = parse("public class Test {\n  // TODO: fix\n  public static void main(String[] args) {\n    System.out.println(\"hello\");\n  }\n}");
        assert_eq!(ast.kind(), &NodeKind::SourceUnit);
        assert_eq!(ast.find_all(&NodeKind::FunctionDef).len(), 1);
        assert_eq!(ast.find_all(&NodeKind::Comment).len(), 1);
        assert_eq!(ast.find_all(&NodeKind::Call).len(), 1);
    }
}
