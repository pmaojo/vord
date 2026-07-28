//! Inbound adapter: C# → neutral AST via tree-sitter.
//! tree-sitter types never escape this crate.

use yunq_ast::{LanguageIdentifier, NodeKind};

yunq_treesitter_adapter::declare_parser!(
    CSharpParser,
    LanguageIdentifier::csharp(),
    tree_sitter_c_sharp::LANGUAGE,
    map_kind
);

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
    use yunq_ast::{AstNode, SourceFile};
    use yunq_rules_engine::AstParser;

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
