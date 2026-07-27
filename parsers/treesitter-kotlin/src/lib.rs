//! Inbound adapter: Kotlin → neutral AST via tree-sitter.
//! Uses the actively maintained `tree-sitter-kotlin-ng` grammar fork (the
//! plain `tree-sitter-kotlin` crate is stale and ABI-incompatible with the
//! workspace's tree-sitter version).
//! tree-sitter types never escape this crate.

use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile, Span};
use yunq_rules_engine::{AstParser, ParseError};

pub struct KotlinParser;

impl KotlinParser {
    pub fn new() -> Self {
        Self
    }
}

impl Default for KotlinParser {
    fn default() -> Self {
        Self::new()
    }
}

impl AstParser for KotlinParser {
    fn language(&self) -> LanguageIdentifier {
        LanguageIdentifier::kotlin()
    }

    fn parse(&self, file: &SourceFile) -> Result<AstNode, ParseError> {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_kotlin_ng::LANGUAGE.into())
            .map_err(|e| ParseError::Backend(e.to_string()))?;
        let tree = parser
            .parse(file.content(), None)
            .ok_or_else(|| ParseError::Syntax {
                file: file.path().to_string(),
                detail: "tree-sitter produced no tree".to_string(),
            })?;
        Ok(convert(tree.root_node(), &file.content_shared()))
    }

    fn tokenize_for_duplication(&self, file: &SourceFile) -> Vec<(u32, String)> {
        let mut parser = tree_sitter::Parser::new();
        if parser
            .set_language(&tree_sitter_kotlin_ng::LANGUAGE.into())
            .is_err()
        {
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
    let children = node
        .named_children(&mut cursor)
        .map(|c| convert(c, source))
        .collect();
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
    Span::new(
        start.row as u32 + 1,
        start.column as u32 + 1,
        end.row as u32 + 1,
        end.column as u32 + 1,
    )
}

const KIND_TABLE: &[(&str, NodeKind)] = &[
    ("source_file", NodeKind::SourceUnit),
    ("function_declaration", NodeKind::FunctionDef),
    ("anonymous_function", NodeKind::FunctionDef),
    ("call_expression", NodeKind::Call),
    ("string_literal", NodeKind::StringLiteral),
    ("multiline_string_literal", NodeKind::StringLiteral),
    ("identifier", NodeKind::Identifier),
    ("qualified_identifier", NodeKind::Identifier),
    ("property_declaration", NodeKind::VariableDecl),
    ("variable_declaration", NodeKind::VariableDecl),
    ("multi_variable_declaration", NodeKind::VariableDecl),
    ("assignment", NodeKind::Assignment),
    ("navigation_expression", NodeKind::MemberAccess),
    ("line_comment", NodeKind::Comment),
    ("block_comment", NodeKind::Comment),
];

fn map_kind(kind: &str) -> NodeKind {
    yunq_ast::lookup_kind(KIND_TABLE, kind)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(code: &str) -> AstNode {
        let file = SourceFile::new("Test.kt", code, LanguageIdentifier::kotlin()).unwrap();
        KotlinParser::new().parse(&file).unwrap()
    }

    #[test]
    fn maps_core_concepts() {
        let ast = parse(
            "// TODO: refactor\nfun main(args: Array<String>) {\n    val password = \"hunter2\"\n    println(password)\n}\n",
        );
        assert_eq!(ast.kind(), &NodeKind::SourceUnit);
        assert_eq!(ast.find_all(&NodeKind::FunctionDef).len(), 1);
        assert_eq!(ast.find_all(&NodeKind::Comment).len(), 1);
        assert!(!ast.find_all(&NodeKind::VariableDecl).is_empty());
        assert!(!ast.find_all(&NodeKind::StringLiteral).is_empty());
    }

    #[test]
    fn println_is_a_call() {
        let ast = parse("fun main() {\n    println(\"hi\")\n}\n");
        let calls = ast.find_all(&NodeKind::Call);
        assert!(calls.iter().any(|c| c.text().starts_with("println")));
    }
}
