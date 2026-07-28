//! Inbound adapter: Bash/shell → neutral AST via tree-sitter.
//! tree-sitter types never escape this crate.

use yunq_ast::{LanguageIdentifier, NodeKind};

yunq_treesitter_adapter::declare_parser!(
    BashParser,
    LanguageIdentifier::bash(),
    tree_sitter_bash::LANGUAGE,
    map_kind
);

fn map_kind(kind: &str) -> NodeKind {
    match kind {
        "program" => NodeKind::SourceUnit,
        "function_definition" => NodeKind::FunctionDef,
        "command" => NodeKind::Call,
        "string" | "raw_string" | "ansi_c_string" | "translated_string" => NodeKind::StringLiteral,
        "variable_name" => NodeKind::Identifier,
        "variable_assignment" => NodeKind::Assignment,
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
        let file = SourceFile::new("test.sh", code, LanguageIdentifier::bash()).unwrap();
        BashParser::new().parse(&file).unwrap()
    }

    #[test]
    fn maps_core_concepts() {
        let ast = parse(
            "# TODO: refactor\nfunction greet() {\n  password=\"hunter2\"\n  echo \"hi $password\"\n}\ngreet\n",
        );
        assert_eq!(ast.kind(), &NodeKind::SourceUnit);
        assert_eq!(ast.find_all(&NodeKind::FunctionDef).len(), 1);
        assert_eq!(ast.find_all(&NodeKind::Comment).len(), 1);
        assert!(!ast.find_all(&NodeKind::Assignment).is_empty());
        assert!(!ast.find_all(&NodeKind::StringLiteral).is_empty());
    }

    #[test]
    fn echo_is_a_call() {
        let ast = parse("echo \"hi\"\n");
        let calls = ast.find_all(&NodeKind::Call);
        assert!(calls.iter().any(|c| c.text().starts_with("echo")));
    }
}
