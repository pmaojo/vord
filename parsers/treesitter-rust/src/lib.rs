//! Inbound adapter: Rust → neutral AST via tree-sitter.
//! tree-sitter types never escape this crate.

use vord_ast::{LanguageIdentifier, NodeKind};

vord_treesitter_adapter::declare_parser!(
    RustParser,
    LanguageIdentifier::rust(),
    tree_sitter_rust::LANGUAGE,
    map_kind
);

const KIND_TABLE: &[(&str, NodeKind)] = &[
    ("source_file", NodeKind::SourceUnit),
    ("function_item", NodeKind::FunctionDef),
    ("closure_expression", NodeKind::FunctionDef),
    ("call_expression", NodeKind::Call),
    ("macro_invocation", NodeKind::Call),
    ("string_literal", NodeKind::StringLiteral),
    ("raw_string_literal", NodeKind::StringLiteral),
    ("identifier", NodeKind::Identifier),
    ("field_identifier", NodeKind::Identifier),
    ("shorthand_field_identifier", NodeKind::Identifier),
    ("assignment_expression", NodeKind::Assignment),
    ("compound_assignment_expr", NodeKind::Assignment),
    ("let_declaration", NodeKind::VariableDecl),
    ("field_expression", NodeKind::MemberAccess),
    ("line_comment", NodeKind::Comment),
    ("block_comment", NodeKind::Comment),
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
        let file = SourceFile::new("test.rs", code, LanguageIdentifier::rust()).unwrap();
        RustParser::new().parse(&file).unwrap()
    }

    #[test]
    fn maps_core_concepts() {
        let ast = parse(
            "// FIXME: rewrite\nfn main() {\n    let secret = \"hunter2\";\n    let value = std::env::var(\"HOME\").unwrap();\n}\n",
        );
        assert_eq!(ast.kind(), &NodeKind::SourceUnit);
        assert_eq!(ast.find_all(&NodeKind::FunctionDef).len(), 1);
        assert_eq!(ast.find_all(&NodeKind::VariableDecl).len(), 2);
        assert_eq!(ast.find_all(&NodeKind::Comment).len(), 1);
        assert!(!ast.find_all(&NodeKind::StringLiteral).is_empty());
    }

    #[test]
    fn method_call_callee_is_member_access_ending_in_method_name() {
        let ast = parse("fn f() { let x = risky().unwrap(); }\n");
        let unwrap_call = ast
            .find_all(&NodeKind::Call)
            .into_iter()
            .find(|c| c.text().ends_with("unwrap()"))
            .expect("unwrap call present");
        let callee = unwrap_call.first_child().unwrap();
        assert_eq!(callee.kind(), &NodeKind::MemberAccess);
        let last_ident = callee
            .children()
            .iter()
            .rev()
            .find(|c| *c.kind() == NodeKind::Identifier)
            .unwrap();
        assert_eq!(last_ident.text(), "unwrap");
    }
}
