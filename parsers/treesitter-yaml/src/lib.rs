//! Inbound adapter: YAML → neutral AST via tree-sitter.
//! Covers plain YAML as well as CloudFormation and Kubernetes manifests,
//! which are just YAML documents with conventional shapes — no separate IaC
//! crate is needed for those. YAML is a pure data format with no
//! function/call concept, so `SourceUnit` plus `StringLiteral`/`Comment` is
//! the appropriate mapping; everything else falls through to `Other`.
//! tree-sitter types never escape this crate.

use vord_ast::{LanguageIdentifier, NodeKind};

vord_treesitter_adapter::declare_parser!(
    YamlParser,
    LanguageIdentifier::yaml(),
    tree_sitter_yaml::LANGUAGE,
    map_kind
);

fn map_kind(kind: &str) -> NodeKind {
    match kind {
        "stream" => NodeKind::SourceUnit,
        "string_scalar" | "double_quote_scalar" | "single_quote_scalar" => NodeKind::StringLiteral,
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
        let file = SourceFile::new("test.yaml", code, LanguageIdentifier::yaml()).unwrap();
        YamlParser::new().parse(&file).unwrap()
    }

    #[test]
    fn maps_core_concepts() {
        let ast = parse("# TODO: refactor\nname: vord\nlist:\n  - a\n  - \"b\"\n");
        assert_eq!(ast.kind(), &NodeKind::SourceUnit);
        assert_eq!(ast.find_all(&NodeKind::Comment).len(), 1);
        assert!(!ast.find_all(&NodeKind::StringLiteral).is_empty());
    }

    #[test]
    fn kubernetes_manifest_shape_parses() {
        let ast = parse(
            "apiVersion: v1\nkind: Pod\nmetadata:\n  name: vord-pod\nspec:\n  containers:\n    - name: app\n      image: \"vord:latest\"\n",
        );
        assert_eq!(ast.kind(), &NodeKind::SourceUnit);
        assert!(!ast.find_all(&NodeKind::StringLiteral).is_empty());
    }
}
