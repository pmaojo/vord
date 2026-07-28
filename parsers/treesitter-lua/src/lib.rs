//! Inbound adapter: Lua → neutral AST via tree-sitter.
//! tree-sitter types never escape this crate.

use yunq_ast::{LanguageIdentifier, NodeKind};

yunq_treesitter_adapter::declare_parser!(
    LuaParser,
    LanguageIdentifier::lua(),
    tree_sitter_lua::LANGUAGE,
    map_kind
);

const KIND_TABLE: &[(&str, NodeKind)] = &[
    ("chunk", NodeKind::SourceUnit),
    ("function_declaration", NodeKind::FunctionDef),
    ("function_definition", NodeKind::FunctionDef),
    ("function_call", NodeKind::Call),
    ("string", NodeKind::StringLiteral),
    ("identifier", NodeKind::Identifier),
    ("variable_declaration", NodeKind::VariableDecl),
    ("implicit_variable_declaration", NodeKind::VariableDecl),
    ("assignment_statement", NodeKind::Assignment),
    ("dot_index_expression", NodeKind::MemberAccess),
    ("method_index_expression", NodeKind::MemberAccess),
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
        let file = SourceFile::new("test.lua", code, LanguageIdentifier::lua()).unwrap();
        LuaParser::new().parse(&file).unwrap()
    }

    #[test]
    fn maps_core_concepts() {
        let ast = parse(
            "-- TODO: refactor\nlocal function main()\n  local password = \"hunter2\"\n  print(password)\nend\n",
        );
        assert_eq!(ast.kind(), &NodeKind::SourceUnit);
        assert_eq!(ast.find_all(&NodeKind::FunctionDef).len(), 1);
        assert_eq!(ast.find_all(&NodeKind::Comment).len(), 1);
        assert!(!ast.find_all(&NodeKind::VariableDecl).is_empty());
        assert!(!ast.find_all(&NodeKind::StringLiteral).is_empty());
    }

    #[test]
    fn print_is_a_call() {
        let ast = parse("print(\"hi\")\n");
        let calls = ast.find_all(&NodeKind::Call);
        assert!(calls.iter().any(|c| c.text().starts_with("print")));
    }
}
