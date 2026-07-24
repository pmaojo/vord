//! Declared-type extraction: given a variable declaration (`VariableDecl`),
//! a function parameter node, or a class/struct field node, what type (if
//! any) is written on it — across the three grammar shapes the registered
//! parsers actually produce for "a name with a type":
//!
//! - TypeScript: a `type_annotation` wrapper child (`x: Foo` → `Foo`'s node
//!   is `type_annotation`'s own single child).
//! - Rust: a bare typed sibling right after the name, with no wrapper
//!   (`field_declaration`'s `x: i32` is just `[Identifier, primitive_type]`).
//! - Python: a `type` wrapper child (`x: int` inside a `typed_parameter`).
//!
//! Both the Rust and Python shapes are "a second child whose raw grammar
//! kind mentions `type`", so one fallback branch covers both.
//!
//! No inference beyond this: a bare `let x = new Foo()` with no annotation
//! is out of scope here — see [`crate::classes`] for the narrow
//! constructor-call inference OOP-smell rules use instead.

use yunq_ast::{AstNode, NodeKind};

fn is_other(node: &AstNode, kind: &str) -> bool {
    matches!(node.kind(), NodeKind::Other(k) if k.as_ref() == kind)
}

/// The declared type text of a `VariableDecl`, parameter, or field node, if
/// one is written. `None` for an untyped binding (e.g. plain JS `let x = 1`,
/// or a Rust/Python name with no annotation).
pub fn declared_type(node: &AstNode) -> Option<String> {
    if let Some(annotation) = node.children().iter().find(|c| is_other(c, "type_annotation")) {
        return annotation
            .first_child()
            .map(|inner| inner.text().to_string())
            .or_else(|| Some(annotation.text().trim_start_matches(':').trim().to_string()));
    }
    node.children()
        .iter()
        .skip(1)
        .find(|c| matches!(c.kind(), NodeKind::Other(k) if k.as_ref() == "type" || k.as_ref().contains("_type")))
        .map(|type_node| type_node.text().to_string())
}

/// The class/type name a `new Foo(...)`-style constructor call constructs,
/// if `expr` is one. Relies on the same TS/JS convention
/// `rulesets/react::common` and `core/taint` lean on: `new_expression` maps
/// to `NodeKind::Call` with the constructed type as its callee, and its own
/// text still carries the `new` keyword (there is no neutral `IsNew` flag).
pub fn constructor_type(expr: &AstNode) -> Option<String> {
    if *expr.kind() != NodeKind::Call || !expr.text().trim_start().starts_with("new ") {
        return None;
    }
    expr.first_child().filter(|c| *c.kind() == NodeKind::Identifier).map(|c| c.text().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use yunq_ast::{LanguageIdentifier, SourceFile};
    use yunq_rules_engine::AstParser;

    fn parse_ts(code: &str) -> AstNode {
        let file = SourceFile::new("t.ts", code, LanguageIdentifier::typescript()).unwrap();
        yunq_parser_typescript::TypeScriptParser::new().parse(&file).unwrap()
    }

    fn parse_rust(code: &str) -> AstNode {
        let file = SourceFile::new("t.rs", code, LanguageIdentifier::rust()).unwrap();
        yunq_parser_rust::RustParser::new().parse(&file).unwrap()
    }

    fn parse_py(code: &str) -> AstNode {
        let file = SourceFile::new("t.py", code, LanguageIdentifier::python()).unwrap();
        yunq_parser_python::PythonParser::new().parse(&file).unwrap()
    }

    #[test]
    fn ts_variable_decl_and_parameter_types() {
        let ast = parse_ts("let x: Foo = new Foo();\nfunction f(other: Other): void {}\n");
        let decl = ast.find_all(&NodeKind::VariableDecl)[0];
        assert_eq!(declared_type(decl), Some("Foo".to_string()));

        let param = ast
            .descendants()
            .find(|n| matches!(n.kind(), NodeKind::Other(k) if k.as_ref() == "required_parameter"))
            .unwrap();
        assert_eq!(declared_type(param), Some("Other".to_string()));
    }

    #[test]
    fn ts_untyped_decl_has_no_type() {
        let ast = parse_ts("let x = 1;\n");
        let decl = ast.find_all(&NodeKind::VariableDecl)[0];
        assert_eq!(declared_type(decl), None);
    }

    #[test]
    fn ts_new_expression_constructor_type() {
        let ast = parse_ts("let x = new Foo();\n");
        let call = ast.find_all(&NodeKind::Call)[0];
        assert_eq!(constructor_type(call), Some("Foo".to_string()));
    }

    #[test]
    fn plain_call_is_not_a_constructor() {
        let ast = parse_ts("let x = Foo();\n");
        let call = ast.find_all(&NodeKind::Call)[0];
        assert_eq!(constructor_type(call), None);
    }

    #[test]
    fn rust_field_and_parameter_types() {
        let ast = parse_rust("struct S { x: i32 }\nfn f(a: i32) {}\n");
        let field = ast
            .descendants()
            .find(|n| matches!(n.kind(), NodeKind::Other(k) if k.as_ref() == "field_declaration"))
            .unwrap();
        assert_eq!(declared_type(field), Some("i32".to_string()));

        let param = ast
            .descendants()
            .find(|n| matches!(n.kind(), NodeKind::Other(k) if k.as_ref() == "parameter"))
            .unwrap();
        assert_eq!(declared_type(param), Some("i32".to_string()));
    }

    #[test]
    fn python_typed_parameter_type() {
        let ast = parse_py("def f(x: int):\n    pass\n");
        let param = ast
            .descendants()
            .find(|n| matches!(n.kind(), NodeKind::Other(k) if k.as_ref() == "typed_parameter"))
            .unwrap();
        assert_eq!(declared_type(param), Some("int".to_string()));
    }
}
