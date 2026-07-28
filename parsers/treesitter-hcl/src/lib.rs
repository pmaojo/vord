//! Inbound adapter: HCL/Terraform → neutral AST via tree-sitter.
//! Covers Terraform (and other HCL-based IaC) — resource/module/variable
//! blocks are definition-shaped so they map to `FunctionDef`, function
//! calls (`length(...)`, `join(...)`) map to `Call`, and `key = value`
//! attributes map to `Assignment`.
//! tree-sitter types never escape this crate.

use yunq_ast::{LanguageIdentifier, NodeKind};

yunq_treesitter_adapter::declare_parser!(
    HclParser,
    LanguageIdentifier::hcl(),
    tree_sitter_hcl::LANGUAGE,
    map_kind
);

fn map_kind(kind: &str) -> NodeKind {
    match kind {
        "config_file" => NodeKind::SourceUnit,
        "block" => NodeKind::FunctionDef,
        "function_call" => NodeKind::Call,
        "string_lit" | "template_literal" => NodeKind::StringLiteral,
        "identifier" | "variable_expr" => NodeKind::Identifier,
        "attribute" => NodeKind::Assignment,
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
        let file = SourceFile::new("test.tf", code, LanguageIdentifier::hcl()).unwrap();
        HclParser::new().parse(&file).unwrap()
    }

    #[test]
    fn maps_core_concepts() {
        let ast = parse(
            "resource \"aws_instance\" \"foo\" {\n  # TODO: refactor\n  ami = \"abc\"\n  count = length(var.azs)\n}\n",
        );
        assert_eq!(ast.kind(), &NodeKind::SourceUnit);
        assert_eq!(ast.find_all(&NodeKind::FunctionDef).len(), 1);
        assert_eq!(ast.find_all(&NodeKind::Comment).len(), 1);
        assert_eq!(ast.find_all(&NodeKind::Assignment).len(), 2);
        assert!(!ast.find_all(&NodeKind::StringLiteral).is_empty());
    }

    #[test]
    fn length_is_a_call() {
        let ast = parse("resource \"x\" \"y\" {\n  count = length(var.azs)\n}\n");
        let calls = ast.find_all(&NodeKind::Call);
        assert!(calls.iter().any(|c| c.text().starts_with("length")));
    }
}
