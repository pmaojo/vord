//! Inbound adapter: C → neutral AST via tree-sitter.
//! tree-sitter types never escape this crate.

use yunq_ast::{LanguageIdentifier, NodeKind};

yunq_treesitter_adapter::declare_parser!(
    CParser,
    LanguageIdentifier::c(),
    tree_sitter_c::LANGUAGE,
    map_kind
);

fn map_kind(kind: &str) -> NodeKind {
    match kind {
        "translation_unit" => NodeKind::SourceUnit,
        "function_definition" => NodeKind::FunctionDef,
        "call_expression" => NodeKind::Call,
        "string_literal" | "system_lib_string" => NodeKind::StringLiteral,
        "identifier" | "field_identifier" => NodeKind::Identifier,
        "declaration" | "assignment_expression" => NodeKind::Assignment,
        "field_expression" | "pointer_expression" => NodeKind::MemberAccess,
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
        let file = SourceFile::new("test.c", code, LanguageIdentifier::c()).unwrap();
        CParser::new().parse(&file).unwrap()
    }

    #[test]
    fn maps_c_concepts() {
        let ast = parse(
            "// TODO: refactor\nint main() {\n    printf(\"hello world\\n\");\n    return 0;\n}",
        );
        assert_eq!(ast.kind(), &NodeKind::SourceUnit);
        assert_eq!(ast.find_all(&NodeKind::FunctionDef).len(), 1);
        assert_eq!(ast.find_all(&NodeKind::Comment).len(), 1);
        assert_eq!(ast.find_all(&NodeKind::Call).len(), 1);
    }
}
