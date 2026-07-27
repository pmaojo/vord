//! Inbound adapter: Go → neutral AST via tree-sitter.
//! tree-sitter types never escape this crate.

use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile, Span};
use yunq_rules_engine::{AstParser, ParseError};

pub struct GoParser;

impl GoParser {
    pub fn new() -> Self {
        Self
    }
}

impl Default for GoParser {
    fn default() -> Self {
        Self::new()
    }
}

impl AstParser for GoParser {
    fn language(&self) -> LanguageIdentifier {
        LanguageIdentifier::go()
    }

    fn parse(&self, file: &SourceFile) -> Result<AstNode, ParseError> {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_go::LANGUAGE.into())
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
            .set_language(&tree_sitter_go::LANGUAGE.into())
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

// Zero-copy: every produced node slices the shared file buffer.
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
    ("method_declaration", NodeKind::FunctionDef),
    ("func_literal", NodeKind::FunctionDef),
    ("call_expression", NodeKind::Call),
    ("interpreted_string_literal", NodeKind::StringLiteral),
    ("raw_string_literal", NodeKind::StringLiteral),
    ("identifier", NodeKind::Identifier),
    ("field_identifier", NodeKind::Identifier),
    ("package_identifier", NodeKind::Identifier),
    ("short_var_declaration", NodeKind::VariableDecl),
    ("var_spec", NodeKind::VariableDecl),
    ("assignment_statement", NodeKind::Assignment),
    ("selector_expression", NodeKind::MemberAccess),
    ("comment", NodeKind::Comment),
];

fn map_kind(kind: &str) -> NodeKind {
    yunq_ast::lookup_kind(KIND_TABLE, kind)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(code: &str) -> AstNode {
        let file = SourceFile::new("test.go", code, LanguageIdentifier::go()).unwrap();
        GoParser::new().parse(&file).unwrap()
    }

    #[test]
    fn maps_core_concepts() {
        let ast = parse(
            "package main\n// TODO: refactor\nfunc main() {\n    password := \"hunter2\"\n    _ = password\n}\n",
        );
        assert_eq!(ast.kind(), &NodeKind::SourceUnit);
        assert_eq!(ast.find_all(&NodeKind::FunctionDef).len(), 1);
        assert_eq!(ast.find_all(&NodeKind::Comment).len(), 1);
        assert!(!ast.find_all(&NodeKind::VariableDecl).is_empty());
        assert!(!ast.find_all(&NodeKind::StringLiteral).is_empty());
    }

    #[test]
    fn exec_command_is_a_call_with_selector_callee() {
        let ast = parse("package main\nfunc f() { exec.Command(\"ls\").Run() }\n");
        let call = ast
            .find_all(&NodeKind::Call)
            .into_iter()
            .find(|c| c.text().starts_with("exec.Command"))
            .expect("exec.Command call");
        assert_eq!(call.first_child().unwrap().kind(), &NodeKind::MemberAccess);
    }
}
