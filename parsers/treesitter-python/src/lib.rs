//! Inbound adapter: Python → neutral AST via tree-sitter.
//! tree-sitter types never escape this crate.

use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile, Span};
use yunq_rules_engine::{AstParser, ParseError};

pub struct PythonParser;

impl PythonParser {
    pub fn new() -> Self {
        Self
    }
}

impl Default for PythonParser {
    fn default() -> Self {
        Self::new()
    }
}

impl AstParser for PythonParser {
    fn language(&self) -> LanguageIdentifier {
        LanguageIdentifier::python()
    }

    fn parse(&self, file: &SourceFile) -> Result<AstNode, ParseError> {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_python::LANGUAGE.into())
            .map_err(|e| ParseError::Backend(e.to_string()))?;
        let tree = parser.parse(file.content(), None).ok_or_else(|| ParseError::Syntax {
            file: file.path().to_string(),
            detail: "tree-sitter produced no tree".to_string(),
        })?;
        Ok(convert(tree.root_node(), &file.content_shared()))
    }

    fn tokenize_for_duplication(&self, file: &SourceFile) -> Vec<(u32, String)> {
        let mut parser = tree_sitter::Parser::new();
        if parser.set_language(&tree_sitter_python::LANGUAGE.into()).is_err() {
            return yunq_cpd::fallback_tokenize(file);
        }
        let Some(tree) = parser.parse(file.content(), None) else {
            return yunq_cpd::fallback_tokenize(file);
        };
        yunq_treesitter_tokens::statement_lines(&tree, file.content())
    }
}

// Zero-copy: every produced node slices the shared file buffer.
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
        other => NodeKind::Other(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
