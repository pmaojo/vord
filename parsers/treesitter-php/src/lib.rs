//! Inbound adapter: PHP → neutral AST via tree-sitter.
//! tree-sitter types never escape this crate.

use yunq_ast::{LanguageIdentifier, NodeKind};

yunq_treesitter_adapter::declare_parser!(
    PhpParser,
    LanguageIdentifier::php(),
    tree_sitter_php::LANGUAGE_PHP,
    map_kind
);

fn map_kind(kind: &str) -> NodeKind {
    match kind {
        "program" => NodeKind::SourceUnit,
        "function_definition" | "method_declaration" | "anonymous_function_creation_expression" => NodeKind::FunctionDef,
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
    use yunq_ast::{AstNode, SourceFile};
    use yunq_rules_engine::AstParser;

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
