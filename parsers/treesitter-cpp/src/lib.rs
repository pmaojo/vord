//! Inbound adapter: C++ → neutral AST via tree-sitter.
//! tree-sitter types never escape this crate.

use yunq_ast::{LanguageIdentifier, NodeKind};

yunq_treesitter_adapter::declare_parser!(
    CppParser,
    LanguageIdentifier::cpp(),
    tree_sitter_cpp::LANGUAGE,
    map_kind
);

fn map_kind(kind: &str) -> NodeKind {
    match kind {
        "translation_unit" => NodeKind::SourceUnit,
        "function_definition" | "lambda_expression" => NodeKind::FunctionDef,
        "call_expression" | "new_expression" => NodeKind::Call,
        "string_literal" | "raw_string_literal" => NodeKind::StringLiteral,
        "identifier" | "field_identifier" | "namespace_identifier" => NodeKind::Identifier,
        "declaration" | "assignment_expression" => NodeKind::Assignment,
        "field_expression" | "pointer_expression" | "qualified_identifier" => {
            NodeKind::MemberAccess
        }
        "comment" => NodeKind::Comment,
        other => NodeKind::Other(yunq_ast::intern(other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use yunq_ast::{AstNode, SourceFile};
    use yunq_rules_engine::AstParser;

    fn parse(code: &str) -> AstNode {
        let file = SourceFile::new("test.cpp", code, LanguageIdentifier::cpp()).unwrap();
        CppParser::new().parse(&file).unwrap()
    }

    #[test]
    fn maps_cpp_concepts() {
        let ast = parse(
            "// TODO: modernize\nint main() {\n    std::cout << \"hello\" << std::endl;\n    return 0;\n}",
        );
        assert_eq!(ast.kind(), &NodeKind::SourceUnit);
        assert_eq!(ast.find_all(&NodeKind::FunctionDef).len(), 1);
        assert_eq!(ast.find_all(&NodeKind::Comment).len(), 1);
    }
}
