//! Inbound adapter: HCL/Terraform → neutral AST via tree-sitter.
//! Covers Terraform (and other HCL-based IaC) — resource/module/variable
//! blocks are definition-shaped so they map to `FunctionDef`, function
//! calls (`length(...)`, `join(...)`) map to `Call`, and `key = value`
//! attributes map to `Assignment`.
//! tree-sitter types never escape this crate.

use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile, Span};
use yunq_rules_engine::{AstParser, ParseError};

pub struct HclParser;

impl HclParser {
    pub fn new() -> Self {
        Self
    }
}

impl Default for HclParser {
    fn default() -> Self {
        Self::new()
    }
}

impl AstParser for HclParser {
    fn language(&self) -> LanguageIdentifier {
        LanguageIdentifier::hcl()
    }

    fn parse(&self, file: &SourceFile) -> Result<AstNode, ParseError> {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_hcl::LANGUAGE.into())
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
        "config_file" => NodeKind::SourceUnit,
        "block" => NodeKind::FunctionDef,
        "function_call" => NodeKind::Call,
        "string_lit" | "template_literal" => NodeKind::StringLiteral,
        "identifier" | "variable_expr" => NodeKind::Identifier,
        "attribute" => NodeKind::Assignment,
        "comment" => NodeKind::Comment,
        other => NodeKind::Other(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(code: &str) -> AstNode {
        let file = SourceFile::new("test.tf", code, LanguageIdentifier::hcl()).unwrap();
        HclParser::new().parse(&file).unwrap()
    }

    #[test]
    fn maps_core_concepts() {
        let ast = parse(
            "resource \"aws_instance\" \"foo\" {\n  # TODO: refactor\n  ami = \"abc\"\n  count = length(var.azs)\n}\n",
        );
        assert_eq!(ast.kind(), &NodeKind::SourceUnit);
        assert_eq!(ast.find_all(&NodeKind::FunctionDef).len(), 1);
        assert_eq!(ast.find_all(&NodeKind::Comment).len(), 1);
        assert_eq!(ast.find_all(&NodeKind::Assignment).len(), 2);
        assert!(!ast.find_all(&NodeKind::StringLiteral).is_empty());
    }

    #[test]
    fn length_is_a_call() {
        let ast = parse("resource \"x\" \"y\" {\n  count = length(var.azs)\n}\n");
        let calls = ast.find_all(&NodeKind::Call);
        assert!(calls.iter().any(|c| c.text().starts_with("length")));
    }
}
