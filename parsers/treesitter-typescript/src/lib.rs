//! Inbound adapter: TypeScript/TSX → neutral AST via tree-sitter.
//! tree-sitter types never escape this crate.

use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile, Span};
use yunq_rules_engine::{AstParser, ParseError};

pub struct TypeScriptParser;

impl TypeScriptParser {
    pub fn new() -> Self {
        Self
    }
}

impl Default for TypeScriptParser {
    fn default() -> Self {
        Self::new()
    }
}

impl AstParser for TypeScriptParser {
    fn language(&self) -> LanguageIdentifier {
        LanguageIdentifier::typescript()
    }

    fn parse(&self, file: &SourceFile) -> Result<AstNode, ParseError> {
        let mut parser = tree_sitter::Parser::new();
        let grammar = if file.path().ends_with(".tsx") {
            tree_sitter_typescript::LANGUAGE_TSX
        } else {
            tree_sitter_typescript::LANGUAGE_TYPESCRIPT
        };
        parser
            .set_language(&grammar.into())
            .map_err(|e| ParseError::Backend(e.to_string()))?;
        let tree = parser.parse(file.content(), None).ok_or_else(|| ParseError::Syntax {
            file: file.path().to_string(),
            detail: "tree-sitter produced no tree".to_string(),
        })?;
        Ok(convert(tree.root_node(), file.content()))
    }
}

fn convert(node: tree_sitter::Node<'_>, source: &str) -> AstNode {
    let mut cursor = node.walk();
    let children = node.named_children(&mut cursor).map(|c| convert(c, source)).collect();
    let text = node.utf8_text(source.as_bytes()).unwrap_or_default().to_string();
    AstNode::new(map_kind(node.kind()), span_of(node), text, children)
}

fn span_of(node: tree_sitter::Node<'_>) -> Span {
    let (start, end) = (node.start_position(), node.end_position());
    Span::new(start.row as u32 + 1, start.column as u32 + 1, end.row as u32 + 1, end.column as u32 + 1)
}

fn map_kind(kind: &str) -> NodeKind {
    match kind {
        "program" => NodeKind::SourceUnit,
        "function_declaration"
        | "function_expression"
        | "arrow_function"
        | "method_definition"
        | "generator_function_declaration" => NodeKind::FunctionDef,
        // `new_expression` maps to Call so `new Function(...)` is visible to
        // security rules; its first named child is the callee, as required.
        "call_expression" | "new_expression" => NodeKind::Call,
        "string" | "template_string" => NodeKind::StringLiteral,
        "identifier"
        | "property_identifier"
        | "shorthand_property_identifier"
        | "shorthand_property_identifier_pattern" => NodeKind::Identifier,
        "assignment_expression" | "augmented_assignment_expression" => NodeKind::Assignment,
        "variable_declarator" => NodeKind::VariableDecl,
        "member_expression" | "subscript_expression" => NodeKind::MemberAccess,
        "comment" => NodeKind::Comment,
        other => NodeKind::Other(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(code: &str) -> AstNode {
        let file = SourceFile::new("test.ts", code, LanguageIdentifier::typescript()).unwrap();
        TypeScriptParser::new().parse(&file).unwrap()
    }

    #[test]
    fn maps_core_concepts() {
        let ast = parse("const secret = \"hunter2\";\nfunction run(x: string) { eval(x); }\n// TODO later\n");
        assert_eq!(ast.kind(), &NodeKind::SourceUnit);
        assert_eq!(ast.find_all(&NodeKind::VariableDecl).len(), 1);
        assert_eq!(ast.find_all(&NodeKind::FunctionDef).len(), 1);
        assert_eq!(ast.find_all(&NodeKind::StringLiteral).len(), 1);
        assert_eq!(ast.find_all(&NodeKind::Comment).len(), 1);
        let calls = ast.find_all(&NodeKind::Call);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].first_child().unwrap().text(), "eval");
    }

    #[test]
    fn variable_decl_contract_holds() {
        let ast = parse("let input = process.argv[2];\n");
        let decl = ast.find_all(&NodeKind::VariableDecl)[0];
        let first = decl.first_child().unwrap();
        assert_eq!(first.kind(), &NodeKind::Identifier);
        assert_eq!(first.text(), "input");
        assert!(decl.children()[1].subtree_contains_text("process.argv"));
    }

    #[test]
    fn spans_are_one_based() {
        let ast = parse("eval(x);\n");
        let call = ast.find_all(&NodeKind::Call)[0];
        assert_eq!(call.span().start_line, 1);
        assert_eq!(call.span().start_col, 1);
    }
}
