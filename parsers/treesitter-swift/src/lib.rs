//! Inbound adapter: Swift → neutral AST via tree-sitter.
//! tree-sitter types never escape this crate.

use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile, Span};
use yunq_rules_engine::{AstParser, ParseError};

pub struct SwiftParser;

impl SwiftParser {
    pub fn new() -> Self {
        Self
    }
}

impl Default for SwiftParser {
    fn default() -> Self {
        Self::new()
    }
}

impl AstParser for SwiftParser {
    fn language(&self) -> LanguageIdentifier {
        LanguageIdentifier::swift()
    }

    fn parse(&self, file: &SourceFile) -> Result<AstNode, ParseError> {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_swift::LANGUAGE.into())
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
        if parser.set_language(&tree_sitter_swift::LANGUAGE.into()).is_err() {
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

const KIND_TABLE: &[(&str, NodeKind)] = &[
    ("source_file", NodeKind::SourceUnit),
    ("function_declaration", NodeKind::FunctionDef),
    ("call_expression", NodeKind::Call),
    ("line_string_literal", NodeKind::StringLiteral),
    ("multi_line_string_literal", NodeKind::StringLiteral),
    ("raw_string_literal", NodeKind::StringLiteral),
    ("simple_identifier", NodeKind::Identifier),
    ("property_declaration", NodeKind::VariableDecl),
    ("assignment", NodeKind::Assignment),
    ("navigation_expression", NodeKind::MemberAccess),
    ("comment", NodeKind::Comment),
    ("multiline_comment", NodeKind::Comment),
];

fn map_kind(kind: &str) -> NodeKind {
    yunq_ast::lookup_kind(KIND_TABLE, kind)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(code: &str) -> AstNode {
        let file = SourceFile::new("test.swift", code, LanguageIdentifier::swift()).unwrap();
        SwiftParser::new().parse(&file).unwrap()
    }

    #[test]
    fn maps_core_concepts() {
        let ast = parse(
            "// TODO: refactor\nfunc greet(name: String) {\n    let password = \"hunter2\"\n    print(\"Hello, \\(name)! \\(password)\")\n}\n",
        );
        assert_eq!(ast.kind(), &NodeKind::SourceUnit);
        assert_eq!(ast.find_all(&NodeKind::FunctionDef).len(), 1);
        assert_eq!(ast.find_all(&NodeKind::Comment).len(), 1);
        assert!(!ast.find_all(&NodeKind::VariableDecl).is_empty());
        assert!(!ast.find_all(&NodeKind::StringLiteral).is_empty());
    }

    #[test]
    fn print_is_a_call() {
        let ast = parse("func f() {\n    print(\"hi\")\n}\n");
        let calls = ast.find_all(&NodeKind::Call);
        assert!(calls.iter().any(|c| c.text().starts_with("print")));
    }
}
