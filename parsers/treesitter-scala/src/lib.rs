//! Inbound adapter: Scala → neutral AST via tree-sitter.
//! tree-sitter types never escape this crate.

use yunq_ast::{LanguageIdentifier, NodeKind};

yunq_treesitter_adapter::declare_parser!(
    ScalaParser,
    LanguageIdentifier::scala(),
    tree_sitter_scala::LANGUAGE,
    map_kind
);

const KIND_TABLE: &[(&str, NodeKind)] = &[
    ("compilation_unit", NodeKind::SourceUnit),
    ("function_definition", NodeKind::FunctionDef),
    ("function_declaration", NodeKind::FunctionDef),
    ("call_expression", NodeKind::Call),
    ("string", NodeKind::StringLiteral),
    ("interpolated_string", NodeKind::StringLiteral),
    ("identifier", NodeKind::Identifier),
    ("val_declaration", NodeKind::VariableDecl),
    ("var_declaration", NodeKind::VariableDecl),
    ("val_definition", NodeKind::VariableDecl),
    ("var_definition", NodeKind::VariableDecl),
    ("assignment_expression", NodeKind::Assignment),
    ("field_expression", NodeKind::MemberAccess),
    ("comment", NodeKind::Comment),
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
        let file = SourceFile::new("Test.scala", code, LanguageIdentifier::scala()).unwrap();
        ScalaParser::new().parse(&file).unwrap()
    }

    #[test]
    fn maps_core_concepts() {
        let ast = parse(
            "object Hello {\n  // TODO: refactor\n  def main(args: Array[String]) = {\n    val password = \"hunter2\"\n    println(password)\n  }\n}\n",
        );
        assert_eq!(ast.kind(), &NodeKind::SourceUnit);
        assert_eq!(ast.find_all(&NodeKind::FunctionDef).len(), 1);
        assert_eq!(ast.find_all(&NodeKind::Comment).len(), 1);
        assert!(!ast.find_all(&NodeKind::VariableDecl).is_empty());
        assert!(!ast.find_all(&NodeKind::StringLiteral).is_empty());
    }

    #[test]
    fn println_is_a_call() {
        let ast = parse("object Hello {\n  def main() = { println(\"hi\") }\n}\n");
        let calls = ast.find_all(&NodeKind::Call);
        assert!(calls.iter().any(|c| c.text().starts_with("println")));
    }
}
