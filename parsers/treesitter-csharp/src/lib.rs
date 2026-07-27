//! Inbound adapter: C# → neutral AST via tree-sitter.
//! tree-sitter types never escape this crate.

use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile, Span};
use yunq_rules_engine::{AstParser, ParseError};

pub struct CSharpParser;

impl CSharpParser {
    pub fn new() -> Self {
        Self
    }
}

impl Default for CSharpParser {
    fn default() -> Self {
        Self::new()
    }
}

impl AstParser for CSharpParser {
    fn language(&self) -> LanguageIdentifier {
        LanguageIdentifier::csharp()
    }

    fn parse(&self, file: &SourceFile) -> Result<AstNode, ParseError> {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_c_sharp::LANGUAGE.into())
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
            .set_language(&tree_sitter_c_sharp::LANGUAGE.into())
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
    ("compilation_unit", NodeKind::SourceUnit),
    ("method_declaration", NodeKind::FunctionDef),
    ("local_function_statement", NodeKind::FunctionDef),
    ("constructor_declaration", NodeKind::FunctionDef),
    ("destructor_declaration", NodeKind::FunctionDef),
    ("invocation_expression", NodeKind::Call),
    ("string_literal", NodeKind::StringLiteral),
    ("raw_string_literal", NodeKind::StringLiteral),
    ("verbatim_string_literal", NodeKind::StringLiteral),
    ("interpolated_string_expression", NodeKind::StringLiteral),
    ("identifier", NodeKind::Identifier),
    ("variable_declaration", NodeKind::VariableDecl),
    ("local_declaration_statement", NodeKind::VariableDecl),
    ("field_declaration", NodeKind::VariableDecl),
    ("assignment_expression", NodeKind::Assignment),
    ("member_access_expression", NodeKind::MemberAccess),
    ("conditional_access_expression", NodeKind::MemberAccess),
    ("comment", NodeKind::Comment),
];

fn map_kind(kind: &str) -> NodeKind {
    yunq_ast::lookup_kind(KIND_TABLE, kind)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(code: &str) -> AstNode {
        let file = SourceFile::new("Test.cs", code, LanguageIdentifier::csharp()).unwrap();
        CSharpParser::new().parse(&file).unwrap()
    }

    #[test]
    fn maps_core_concepts() {
        let ast = parse(
            "class Foo {\n    // TODO: refactor\n    void Bar() {\n        var password = \"hunter2\";\n        Console.WriteLine(password);\n    }\n}\n",
        );
        assert_eq!(ast.kind(), &NodeKind::SourceUnit);
        assert_eq!(ast.find_all(&NodeKind::FunctionDef).len(), 1);
        assert_eq!(ast.find_all(&NodeKind::Comment).len(), 1);
        assert!(!ast.find_all(&NodeKind::VariableDecl).is_empty());
        assert!(!ast.find_all(&NodeKind::StringLiteral).is_empty());
    }

    #[test]
    fn console_write_line_is_a_call_with_member_access_callee() {
        let ast = parse("class Foo {\n    void Bar() { Console.WriteLine(\"hi\"); }\n}\n");
        let call = ast
            .find_all(&NodeKind::Call)
            .into_iter()
            .find(|c| c.text().starts_with("Console.WriteLine"))
            .expect("Console.WriteLine call");
        assert_eq!(call.first_child().unwrap().kind(), &NodeKind::MemberAccess);
    }
}
