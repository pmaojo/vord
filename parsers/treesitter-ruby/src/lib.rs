//! Inbound adapter: Ruby → neutral AST via tree-sitter.
//! tree-sitter types never escape this crate.

use yunq_ast::{LanguageIdentifier, NodeKind};

yunq_treesitter_adapter::declare_parser!(
    RubyParser,
    LanguageIdentifier::ruby(),
    tree_sitter_ruby::LANGUAGE,
    map_kind
);

fn map_kind(kind: &str) -> NodeKind {
    match kind {
        "program" => NodeKind::SourceUnit,
        "method" | "singleton_method" => NodeKind::FunctionDef,
        "call" => NodeKind::Call,
        "string" | "bare_string" | "chained_string" => NodeKind::StringLiteral,
        "identifier" => NodeKind::Identifier,
        "assignment" | "operator_assignment" => NodeKind::Assignment,
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
        let file = SourceFile::new("test.rb", code, LanguageIdentifier::ruby()).unwrap();
        RubyParser::new().parse(&file).unwrap()
    }

    #[test]
    fn maps_core_concepts() {
        let ast = parse(
            "# TODO: refactor\ndef hello(name)\n  password = \"hunter2\"\n  puts \"Hello, #{name}! #{password}\"\nend\n",
        );
        assert_eq!(ast.kind(), &NodeKind::SourceUnit);
        assert_eq!(ast.find_all(&NodeKind::FunctionDef).len(), 1);
        assert_eq!(ast.find_all(&NodeKind::Comment).len(), 1);
        assert!(!ast.find_all(&NodeKind::Assignment).is_empty());
        assert!(!ast.find_all(&NodeKind::StringLiteral).is_empty());
    }

    #[test]
    fn puts_is_a_call() {
        let ast = parse("def hello\n  puts \"hi\"\nend\n");
        let calls = ast.find_all(&NodeKind::Call);
        assert!(calls.iter().any(|c| c.text().starts_with("puts")));
    }
}
