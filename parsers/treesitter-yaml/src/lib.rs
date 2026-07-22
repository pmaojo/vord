//! Inbound adapter: YAML → neutral AST via tree-sitter.
//! Covers plain YAML as well as CloudFormation and Kubernetes manifests,
//! which are just YAML documents with conventional shapes — no separate IaC
//! crate is needed for those. YAML is a pure data format with no
//! function/call concept, so `SourceUnit` plus `StringLiteral`/`Comment` is
//! the appropriate mapping; everything else falls through to `Other`.
//! tree-sitter types never escape this crate.

use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile, Span};
use yunq_rules_engine::{AstParser, ParseError};

pub struct YamlParser;

impl YamlParser {
    pub fn new() -> Self {
        Self
    }
}

impl Default for YamlParser {
    fn default() -> Self {
        Self::new()
    }
}

impl AstParser for YamlParser {
    fn language(&self) -> LanguageIdentifier {
        LanguageIdentifier::yaml()
    }

    fn parse(&self, file: &SourceFile) -> Result<AstNode, ParseError> {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_yaml::LANGUAGE.into())
            .map_err(|e| ParseError::Backend(e.to_string()))?;
        let tree = parser.parse(file.content(), None).ok_or_else(|| ParseError::Syntax {
            file: file.path().to_string(),
            detail: "tree-sitter produced no tree".to_string(),
        })?;
        Ok(convert(tree.root_node(), &file.content_shared()))
    }

    fn tokenize_for_duplication(&self, file: &SourceFile) -> Vec<(u32, String)> {
        let mut parser = tree_sitter::Parser::new();
        if parser.set_language(&tree_sitter_yaml::LANGUAGE.into()).is_err() {
            return yunq_cpd::fallback_tokenize(file);
        }
        let Some(tree) = parser.parse(file.content(), None) else {
            return yunq_cpd::fallback_tokenize(file);
        };
        yunq_treesitter_tokens::statement_lines(&tree, file.content())
    }
}

fn convert(node: tree_sitter::Node<'_>, source: &std::sync::Arc<str>) -> AstNode {
    let mut cursor = node.walk();
    let children = node.named_children(&mut cursor).map(|c| convert(c, source)).collect();
    AstNode::from_source(
        map_kind(node.kind()),
        span_of(node),
        std::sync::Arc::clone(source),
        node.byte_range(),
        children,
    )
}

fn span_of(node: tree_sitter::Node<'_>) -> Span {
    let (start, end) = (node.start_position(), node.end_position());
    Span::new(start.row as u32 + 1, start.column as u32 + 1, end.row as u32 + 1, end.column as u32 + 1)
}

fn map_kind(kind: &str) -> NodeKind {
    match kind {
        "stream" => NodeKind::SourceUnit,
        "string_scalar" | "double_quote_scalar" | "single_quote_scalar" => NodeKind::StringLiteral,
        "comment" => NodeKind::Comment,
        other => NodeKind::Other(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(code: &str) -> AstNode {
        let file = SourceFile::new("test.yaml", code, LanguageIdentifier::yaml()).unwrap();
        YamlParser::new().parse(&file).unwrap()
    }

    #[test]
    fn maps_core_concepts() {
        let ast = parse("# TODO: refactor\nname: yunq\nlist:\n  - a\n  - \"b\"\n");
        assert_eq!(ast.kind(), &NodeKind::SourceUnit);
        assert_eq!(ast.find_all(&NodeKind::Comment).len(), 1);
        assert!(!ast.find_all(&NodeKind::StringLiteral).is_empty());
    }

    #[test]
    fn kubernetes_manifest_shape_parses() {
        let ast = parse(
            "apiVersion: v1\nkind: Pod\nmetadata:\n  name: yunq-pod\nspec:\n  containers:\n    - name: app\n      image: \"yunq:latest\"\n",
        );
        assert_eq!(ast.kind(), &NodeKind::SourceUnit);
        assert!(!ast.find_all(&NodeKind::StringLiteral).is_empty());
    }
}
