//! Inbound adapter: Groovy → neutral AST via tree-sitter.
//! tree-sitter types never escape this crate.

use yunq_ast::{LanguageIdentifier, NodeKind};

yunq_treesitter_adapter::declare_parser!(
    GroovyParser,
    LanguageIdentifier::groovy(),
    tree_sitter_groovy::LANGUAGE,
    map_kind
);

fn map_kind(kind: &str) -> NodeKind {
    match kind {
        "program" => NodeKind::SourceUnit,
        "method_declaration" | "constructor_declaration" | "compact_constructor_declaration"
        | "function_definition" | "closure" => NodeKind::FunctionDef,
        "method_invocation" | "object_creation_expression" | "juxt_function_call" => NodeKind::Call,
        "string_literal" => NodeKind::StringLiteral,
        "identifier" => NodeKind::Identifier,
        "local_variable_declaration" | "assignment_expression" => NodeKind::Assignment,
        "field_access" => NodeKind::MemberAccess,
        "line_comment" | "block_comment" => NodeKind::Comment,
        other => NodeKind::Other(yunq_ast::intern(other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use yunq_ast::{AstNode, SourceFile};
    use yunq_rules_engine::AstParser;

    fn parse(code: &str) -> AstNode {
        let file = SourceFile::new("Test.groovy", code, LanguageIdentifier::groovy()).unwrap();
        GroovyParser::new().parse(&file).unwrap()
    }

    #[test]
    fn maps_core_concepts() {
        let ast = parse(
            "class Hello {\n  // TODO: refactor\n  def main() {\n    def password = \"hunter2\"\n    println(password)\n  }\n}\n",
        );
        assert_eq!(ast.kind(), &NodeKind::SourceUnit);
        assert_eq!(ast.find_all(&NodeKind::FunctionDef).len(), 1);
        assert_eq!(ast.find_all(&NodeKind::Comment).len(), 1);
        assert!(!ast.find_all(&NodeKind::StringLiteral).is_empty());
    }

    #[test]
    fn println_is_a_call() {
        let ast = parse("def main() { println(\"hi\") }\n");
        let calls = ast.find_all(&NodeKind::Call);
        assert!(calls.iter().any(|c| c.text().starts_with("println")));
    }
}
