//! Inbound adapter: Java → neutral AST via tree-sitter.
//! tree-sitter types never escape this crate.

use vord_ast::{LanguageIdentifier, NodeKind};

vord_treesitter_adapter::declare_parser!(
    JavaParser,
    LanguageIdentifier::java(),
    tree_sitter_java::LANGUAGE,
    map_kind
);

fn map_kind(kind: &str) -> NodeKind {
    match kind {
        "program" | "compilation_unit" => NodeKind::SourceUnit,
        "method_declaration" | "constructor_declaration" => NodeKind::FunctionDef,
        "method_invocation" | "object_creation_expression" => NodeKind::Call,
        "string_literal" => NodeKind::StringLiteral,
        "identifier" => NodeKind::Identifier,
        "local_variable_declaration" | "assignment_expression" => NodeKind::Assignment,
        "field_access" => NodeKind::MemberAccess,
        "line_comment" | "block_comment" => NodeKind::Comment,
        other => NodeKind::Other(vord_ast::intern(other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vord_ast::{AstNode, SourceFile};
    use vord_rules_engine::AstParser;

    fn parse(code: &str) -> AstNode {
        let file = SourceFile::new("Test.java", code, LanguageIdentifier::java()).unwrap();
        JavaParser::new().parse(&file).unwrap()
    }

    #[test]
    fn maps_java_concepts() {
        let ast = parse(
            "public class Test {\n  // TODO: fix\n  public static void main(String[] args) {\n    System.out.println(\"hello\");\n  }\n}",
        );
        assert_eq!(ast.kind(), &NodeKind::SourceUnit);
        assert_eq!(ast.find_all(&NodeKind::FunctionDef).len(), 1);
        assert_eq!(ast.find_all(&NodeKind::Comment).len(), 1);
        assert_eq!(ast.find_all(&NodeKind::Call).len(), 1);
    }
}
