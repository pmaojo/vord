//! Inbound adapter: Kotlin → neutral AST via tree-sitter.
//! Uses the actively maintained `tree-sitter-kotlin-ng` grammar fork (the
//! plain `tree-sitter-kotlin` crate is stale and ABI-incompatible with the
//! workspace's tree-sitter version).
//! tree-sitter types never escape this crate.

use yunq_ast::{LanguageIdentifier, NodeKind};

yunq_treesitter_adapter::declare_parser!(
    KotlinParser,
    LanguageIdentifier::kotlin(),
    tree_sitter_kotlin_ng::LANGUAGE,
    map_kind
);

const KIND_TABLE: &[(&str, NodeKind)] = &[
    ("source_file", NodeKind::SourceUnit),
    ("function_declaration", NodeKind::FunctionDef),
    ("anonymous_function", NodeKind::FunctionDef),
    ("call_expression", NodeKind::Call),
    ("string_literal", NodeKind::StringLiteral),
    ("multiline_string_literal", NodeKind::StringLiteral),
    ("identifier", NodeKind::Identifier),
    ("qualified_identifier", NodeKind::Identifier),
    ("property_declaration", NodeKind::VariableDecl),
    ("variable_declaration", NodeKind::VariableDecl),
    ("multi_variable_declaration", NodeKind::VariableDecl),
    ("assignment", NodeKind::Assignment),
    ("navigation_expression", NodeKind::MemberAccess),
    ("line_comment", NodeKind::Comment),
    ("block_comment", NodeKind::Comment),
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
        let file = SourceFile::new("Test.kt", code, LanguageIdentifier::kotlin()).unwrap();
        KotlinParser::new().parse(&file).unwrap()
    }

    #[test]
    fn maps_core_concepts() {
        let ast = parse(
            "// TODO: refactor\nfun main(args: Array<String>) {\n    val password = \"hunter2\"\n    println(password)\n}\n",
        );
        assert_eq!(ast.kind(), &NodeKind::SourceUnit);
        assert_eq!(ast.find_all(&NodeKind::FunctionDef).len(), 1);
        assert_eq!(ast.find_all(&NodeKind::Comment).len(), 1);
        assert!(!ast.find_all(&NodeKind::VariableDecl).is_empty());
        assert!(!ast.find_all(&NodeKind::StringLiteral).is_empty());
    }

    #[test]
    fn println_is_a_call() {
        let ast = parse("fun main() {\n    println(\"hi\")\n}\n");
        let calls = ast.find_all(&NodeKind::Call);
        assert!(calls.iter().any(|c| c.text().starts_with("println")));
    }
}
