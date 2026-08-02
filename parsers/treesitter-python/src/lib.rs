//! Inbound adapter: Python → neutral AST via tree-sitter.
//! tree-sitter types never escape this crate.

use vord_ast::{LanguageIdentifier, NodeKind};

vord_treesitter_adapter::declare_parser!(
    PythonParser,
    LanguageIdentifier::python(),
    tree_sitter_python::LANGUAGE,
    map_kind
);

fn map_kind(kind: &str) -> NodeKind {
    match kind {
        "module" => NodeKind::SourceUnit,
        "function_definition" | "lambda" => NodeKind::FunctionDef,
        "call" => NodeKind::Call,
        "string" | "concatenated_string" => NodeKind::StringLiteral,
        "identifier" => NodeKind::Identifier,
        // Python has no declarations; assignment is the binding form and
        // upholds the `Assignment` structural contract (target first).
        "assignment" | "augmented_assignment" => NodeKind::Assignment,
        "attribute" | "subscript" => NodeKind::MemberAccess,
        "comment" => NodeKind::Comment,
        other => NodeKind::Other(vord_ast::intern(other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vord_ast::{AstNode, SourceFile};
    use vord_rules_engine::AstParser;

    fn parse(code: &str) -> AstNode {
        let file = SourceFile::new("test.py", code, LanguageIdentifier::python()).unwrap();
        PythonParser::new().parse(&file).unwrap()
    }

    #[test]
    fn maps_core_concepts() {
        let ast = parse("# TODO: cleanup\npassword = \"hunter2\"\ndef run(cmd):\n    eval(cmd)\n");
        assert_eq!(ast.kind(), &NodeKind::SourceUnit);
        assert_eq!(ast.find_all(&NodeKind::FunctionDef).len(), 1);
        assert_eq!(ast.find_all(&NodeKind::Comment).len(), 1);
        assert_eq!(ast.find_all(&NodeKind::Assignment).len(), 1);
        let calls = ast.find_all(&NodeKind::Call);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].first_child().unwrap().text(), "eval");
    }

    #[test]
    fn assignment_contract_holds() {
        let ast = parse("data = sys.argv[1]\n");
        let assignment = ast.find_all(&NodeKind::Assignment)[0];
        let first = assignment.first_child().unwrap();
        assert_eq!(first.kind(), &NodeKind::Identifier);
        assert_eq!(first.text(), "data");
        assert!(assignment.children()[1].subtree_contains_text("sys.argv"));
    }
}
