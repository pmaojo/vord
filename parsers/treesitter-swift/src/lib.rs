//! Inbound adapter: Swift → neutral AST via tree-sitter.
//! tree-sitter types never escape this crate.

use vord_ast::{LanguageIdentifier, NodeKind};

vord_treesitter_adapter::declare_parser!(
    SwiftParser,
    LanguageIdentifier::swift(),
    tree_sitter_swift::LANGUAGE,
    map_kind
);

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
    vord_ast::lookup_kind(KIND_TABLE, kind)
}

#[cfg(test)]
mod tests {
    use super::*;
    use vord_ast::{AstNode, SourceFile};
    use vord_rules_engine::AstParser;

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
