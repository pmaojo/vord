//! Inbound adapter: Go → neutral AST via tree-sitter.
//! tree-sitter types never escape this crate.

use yunq_ast::{LanguageIdentifier, NodeKind};

yunq_treesitter_adapter::declare_parser!(
    GoParser,
    LanguageIdentifier::go(),
    tree_sitter_go::LANGUAGE,
    map_kind
);

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
    use yunq_ast::{AstNode, SourceFile};
    use yunq_rules_engine::AstParser;

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
