//! Inbound adapter: Scala → neutral AST via tree-sitter.
//! tree-sitter types never escape this crate.

use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile, Span};
use yunq_rules_engine::{AstParser, ParseError};

pub struct ScalaParser;

impl ScalaParser {
    pub fn new() -> Self {
        Self
    }
}

impl Default for ScalaParser {
    fn default() -> Self {
        Self::new()
    }
}

impl AstParser for ScalaParser {
    fn language(&self) -> LanguageIdentifier {
        LanguageIdentifier::scala()
    }

    fn parse(&self, file: &SourceFile) -> Result<AstNode, ParseError> {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_scala::LANGUAGE.into())
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
        "compilation_unit" => NodeKind::SourceUnit,
        "function_definition" | "function_declaration" => NodeKind::FunctionDef,
        "call_expression" => NodeKind::Call,
        "string" | "interpolated_string" => NodeKind::StringLiteral,
        "identifier" => NodeKind::Identifier,
        "val_declaration" | "var_declaration" | "val_definition" | "var_definition" => {
            NodeKind::VariableDecl
        }
        "assignment_expression" => NodeKind::Assignment,
        "field_expression" => NodeKind::MemberAccess,
        "comment" | "block_comment" => NodeKind::Comment,
        other => NodeKind::Other(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(code: &str) -> AstNode {
        let file = SourceFile::new("Test.scala", code, LanguageIdentifier::scala()).unwrap();
        ScalaParser::new().parse(&file).unwrap()
    }

    #[test]
    fn maps_core_concepts() {
        let ast = parse(
            "object Hello {\n  // TODO: refactor\n  def main(args: Array[String]) = {\n    val password = \"hunter2\"\n    println(password)\n  }\n}\n",
        );
        assert_eq!(ast.kind(), &NodeKind::SourceUnit);
        assert_eq!(ast.find_all(&NodeKind::FunctionDef).len(), 1);
        assert_eq!(ast.find_all(&NodeKind::Comment).len(), 1);
        assert!(!ast.find_all(&NodeKind::VariableDecl).is_empty());
        assert!(!ast.find_all(&NodeKind::StringLiteral).is_empty());
    }

    #[test]
    fn println_is_a_call() {
        let ast = parse("object Hello {\n  def main() = { println(\"hi\") }\n}\n");
        let calls = ast.find_all(&NodeKind::Call);
        assert!(calls.iter().any(|c| c.text().starts_with("println")));
    }
}
