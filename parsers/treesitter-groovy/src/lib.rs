//! Inbound adapter: Groovy → neutral AST via tree-sitter.
//! tree-sitter types never escape this crate.

use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile, Span};
use yunq_rules_engine::{AstParser, ParseError};

pub struct GroovyParser;

impl GroovyParser {
    pub fn new() -> Self {
        Self
    }
}

impl Default for GroovyParser {
    fn default() -> Self {
        Self::new()
    }
}

impl AstParser for GroovyParser {
    fn language(&self) -> LanguageIdentifier {
        LanguageIdentifier::groovy()
    }

    fn parse(&self, file: &SourceFile) -> Result<AstNode, ParseError> {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_groovy::LANGUAGE.into())
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
        "program" => NodeKind::SourceUnit,
        "method_declaration" | "constructor_declaration" | "compact_constructor_declaration"
        | "function_definition" | "closure" => NodeKind::FunctionDef,
        "method_invocation" | "object_creation_expression" | "juxt_function_call" => NodeKind::Call,
        "string_literal" => NodeKind::StringLiteral,
        "identifier" => NodeKind::Identifier,
        "local_variable_declaration" | "assignment_expression" => NodeKind::Assignment,
        "field_access" => NodeKind::MemberAccess,
        "line_comment" | "block_comment" => NodeKind::Comment,
        other => NodeKind::Other(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(code: &str) -> AstNode {
        let file = SourceFile::new("Test.groovy", code, LanguageIdentifier::groovy()).unwrap();
        GroovyParser::new().parse(&file).unwrap()
    }

    #[test]
    fn maps_core_concepts() {
        let ast = parse(
            "class Hello {\n  // TODO: refactor\n  def main() {\n    def password = \"hunter2\"\n    println(password)\n  }\n}\n",
        );
        assert_eq!(ast.kind(), &NodeKind::SourceUnit);
        assert_eq!(ast.find_all(&NodeKind::FunctionDef).len(), 1);
        assert_eq!(ast.find_all(&NodeKind::Comment).len(), 1);
        assert!(!ast.find_all(&NodeKind::StringLiteral).is_empty());
    }

    #[test]
    fn println_is_a_call() {
        let ast = parse("def main() { println(\"hi\") }\n");
        let calls = ast.find_all(&NodeKind::Call);
        assert!(calls.iter().any(|c| c.text().starts_with("println")));
    }
}
