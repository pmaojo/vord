//! Inbound adapter: TypeScript/TSX → neutral AST via tree-sitter.
//! tree-sitter types never escape this crate.

use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
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
        yunq_treesitter_adapter::parse_with(&grammar_for(file), file, map_kind)
    }

    fn tokenize_for_duplication(
        &self,
        file: &SourceFile,
        normalization: yunq_cpd::TokenNormalization,
    ) -> Vec<(u32, String)> {
        yunq_treesitter_adapter::tokenize_with(&grammar_for(file), file, normalization)
    }
}

// Zero-copy: every produced node slices the shared file buffer.


const KIND_TABLE: &[(&str, NodeKind)] = &[
    ("program", NodeKind::SourceUnit),
    ("function_declaration", NodeKind::FunctionDef),
    ("function_expression", NodeKind::FunctionDef),
    ("arrow_function", NodeKind::FunctionDef),
    ("method_definition", NodeKind::FunctionDef),
    ("generator_function_declaration", NodeKind::FunctionDef),
    // `new_expression` maps to Call so `new Function(...)` is visible to
    // security rules; its first named child is the callee, as required.
    ("call_expression", NodeKind::Call),
    ("new_expression", NodeKind::Call),
    ("string", NodeKind::StringLiteral),
    ("template_string", NodeKind::StringLiteral),
    ("identifier", NodeKind::Identifier),
    ("property_identifier", NodeKind::Identifier),
    ("shorthand_property_identifier", NodeKind::Identifier),
    ("shorthand_property_identifier_pattern", NodeKind::Identifier),
    ("assignment_expression", NodeKind::Assignment),
    ("augmented_assignment_expression", NodeKind::Assignment),
    ("variable_declarator", NodeKind::VariableDecl),
    ("member_expression", NodeKind::MemberAccess),
    ("subscript_expression", NodeKind::MemberAccess),
    ("comment", NodeKind::Comment),
];

/// `.tsx` is a different grammar, not a dialect — and parsing and
/// duplication tokenizing must agree on which one a file gets.
fn grammar_for(file: &SourceFile) -> tree_sitter::Language {
    if file.path().ends_with(".tsx") {
        tree_sitter_typescript::LANGUAGE_TSX.into()
    } else {
        tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into()
    }
}

fn map_kind(kind: &str) -> NodeKind {
    yunq_ast::lookup_kind(KIND_TABLE, kind)
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
