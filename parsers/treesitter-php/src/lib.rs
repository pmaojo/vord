//! Inbound adapter: PHP → neutral AST via tree-sitter.
//! tree-sitter types never escape this crate.

use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile, Span};
use yunq_rules_engine::{AstParser, ParseError};

pub struct PhpParser;

impl PhpParser {
    pub fn new() -> Self {
        Self
    }
}

impl Default for PhpParser {
    fn default() -> Self {
        Self::new()
    }
}

impl AstParser for PhpParser {
    fn language(&self) -> LanguageIdentifier {
        LanguageIdentifier::php()
    }

    fn parse(&self, file: &SourceFile) -> Result<AstNode, ParseError> {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_php::LANGUAGE_PHP.into())
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
            .set_language(&tree_sitter_php::LANGUAGE_PHP.into())
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

fn map_kind(kind: &str) -> NodeKind {
    match kind {
        "program" => NodeKind::SourceUnit,
        "function_definition" | "method_declaration" | "anonymous_function_creation_expression" => {
            NodeKind::FunctionDef
        }
        "function_call_expression" | "member_call_expression" => NodeKind::Call,
        "string" | "encapsed_string" => NodeKind::StringLiteral,
        "name" | "variable_name" => NodeKind::Identifier,
        "expression_statement" | "assignment_expression" => NodeKind::Assignment,
        "member_access_expression" | "nullsafe_member_access_expression" => NodeKind::MemberAccess,
        "comment" => NodeKind::Comment,
        other => NodeKind::Other(yunq_ast::intern(other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(code: &str) -> AstNode {
        let file = SourceFile::new("test.php", code, LanguageIdentifier::php()).unwrap();
        PhpParser::new().parse(&file).unwrap()
    }

    #[test]
    fn maps_php_concepts() {
        let ast = parse("<?php\n// TODO: fix\nfunction run($cmd) {\n    eval($cmd);\n}\n");
        assert_eq!(ast.kind(), &NodeKind::SourceUnit);
        assert_eq!(ast.find_all(&NodeKind::FunctionDef).len(), 1);
        assert_eq!(ast.find_all(&NodeKind::Comment).len(), 1);
        assert_eq!(ast.find_all(&NodeKind::Call).len(), 1);
    }
}
