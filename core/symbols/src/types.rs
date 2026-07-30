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
        .find(|c| matches!(c.kind(), NodeKind::Other(k) if is_type_node(k.as_ref())))
        .map(|type_node| type_node.text().to_string())
}

/// Whether a raw grammar kind names a type expression.
///
/// `_type`-suffixed kinds cover the compound shapes (`primitive_type`,
/// `generic_type`, `reference_type`, `tuple_type`, `unit_type`, …) and `"type"`
/// is Python's wrapper, but Rust writes a *plain* user-defined type as
/// `type_identifier`, whose name matches neither — which is why a field or
/// parameter annotated with a project's own type (`repo: OrderRepository`)
/// used to read as untyped while `repo: i32` resolved fine.
fn is_type_node(kind: &str) -> bool {
    matches!(kind, "type" | "type_identifier" | "scoped_type_identifier") || kind.ends_with("_type")
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

/// Language primitives and near-primitives: types that carry a value, not a
/// collaborator. Covers all three grammars at once because a rule asking "is
/// this parameter a dependency or a datum" asks the same question of
/// `string`, `str` and `String`.
const PRIMITIVE_NAMES: &[&str] = &[
    // TypeScript / JavaScript
    "string", "number", "boolean", "bigint", "symbol", "any", "unknown", "void", "never", "null",
    "undefined", "object", "Object", "Date", "RegExp", "Error",
    // Python
    "int", "float", "complex", "bool", "bytes", "bytearray", "None", "Any", "date", "datetime",
    "Decimal", "UUID", "Path",
    // Rust
    "str", "String", "char", "i8", "i16", "i32", "i64", "i128", "isize", "u8", "u16", "u32", "u64",
    "u128", "usize", "f32", "f64", "bool_", "OsStr", "OsString", "PathBuf",
];

/// Types that are transparent wrappers/containers: what matters is what is
/// *inside* them, so they neither make a type primitive nor make it a
/// collaborator on their own. `Arc<dyn OrderRepository>` is a collaborator
/// because of `OrderRepository`; `Vec<String>` is data because of `String`.
const TRANSPARENT_NAMES: &[&str] = &[
    // Containers
    "Array", "ReadonlyArray", "Map", "Set", "WeakMap", "WeakSet", "Record", "Partial", "Readonly",
    "List", "Sequence", "Iterable", "Iterator", "Tuple", "tuple", "list", "dict", "set",
    "frozenset", "Dict", "Vec", "VecDeque", "HashMap", "BTreeMap", "HashSet", "BTreeSet",
    "IndexMap", "slice",
    // Wrappers / effects
    "Optional", "Option", "Result", "Promise", "Awaitable", "Coroutine", "Future", "Box", "Arc",
    "Rc", "RefCell", "Cell", "Mutex", "RwLock", "Cow", "Union", "Literal", "Annotated", "Final",
    // Rust type-expression keywords the text carries along
    "dyn", "impl", "mut", "static", "const", "where", "Send", "Sync", "Sized", "Self", "self",
    // Conversion bounds: `impl Into<String>` is a string with a convenience
    // bound on it, not a collaborator. Counting the bound as a dependency is
    // how a five-value constructor reads as five injected services.
    "Into", "From", "TryInto", "TryFrom", "AsRef", "AsMut", "Borrow", "BorrowMut", "ToString",
    "ToOwned", "Deref",
];

/// The type names written inside a declared-type text, with the tokens that
/// are never type names dropped: lifetimes (`'a`), single-letter generic
/// parameters (`T`, `S`) and numeric literals in const generics.
fn type_identifiers(declared: &str) -> Vec<&str> {
    let bytes = declared.as_bytes();
    let mut names = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte.is_ascii_alphabetic() || byte == b'_' {
            let start = index;
            while index < bytes.len() && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_') {
                index += 1;
            }
            let lifetime = start > 0 && bytes[start - 1] == b'\'';
            let name = &declared[start..index];
            let generic_param = name.len() == 1 && name.chars().all(|c| c.is_ascii_uppercase());
            if !lifetime && !generic_param {
                names.push(name);
            }
        } else {
            index += 1;
        }
    }
    names
}

/// Whether a declared type is *only* data: every type name it mentions is a
/// primitive or a transparent container of primitives.
///
/// The complement ([`mentions_collaborator`]) is what dependency-injection and
/// primitive-obsession rules actually branch on. A type this can't recognize
/// at all (a project's own `Money`, `OrderRepository`, `UserId`) is treated as
/// *not* primitive, which is the safe direction for both: a domain type is
/// exactly what a value object should be and what an injected dependency is.
pub fn is_primitive_type(declared: &str) -> bool {
    let names = type_identifiers(declared);
    if names.is_empty() {
        return false;
    }
    names
        .iter()
        .all(|name| PRIMITIVE_NAMES.contains(name) || TRANSPARENT_NAMES.contains(name))
}

/// Whether a declared type names at least one type that is neither a
/// primitive nor a transparent container — i.e. a collaborator or a domain
/// concept.
pub fn mentions_collaborator(declared: &str) -> bool {
    !is_primitive_type(declared)
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
    fn primitives_of_all_three_languages_are_data() {
        for primitive in ["string", "number", "boolean", "int", "float", "str", "String", "i32", "f64"] {
            assert!(is_primitive_type(primitive), "{primitive} should read as data");
        }
    }

    #[test]
    fn containers_of_primitives_are_still_data() {
        assert!(is_primitive_type("Vec<String>"));
        assert!(is_primitive_type("Array<string>"));
        assert!(is_primitive_type("Map<string, number>"));
        assert!(is_primitive_type("Optional[int]"));
        assert!(is_primitive_type("HashMap<String, Vec<u8>>"));
    }

    #[test]
    fn a_domain_type_inside_a_wrapper_is_a_collaborator() {
        assert!(mentions_collaborator("Arc<dyn OrderRepository>"));
        assert!(mentions_collaborator("Vec<Order>"));
        assert!(mentions_collaborator("Optional[OrderRepository]"));
        assert!(mentions_collaborator("OrderRepository"));
    }

    #[test]
    fn a_conversion_bound_over_a_primitive_is_still_data() {
        assert!(is_primitive_type("impl Into<String>"));
        assert!(is_primitive_type("AsRef<str>"));
        assert!(mentions_collaborator("impl Into<OrderId>"));
    }

    #[test]
    fn lifetimes_and_generic_parameters_are_not_type_names() {
        assert!(is_primitive_type("&'a str"));
        assert!(is_primitive_type("&mut String"));
        // A bare generic parameter carries no information either way; with no
        // recognizable name at all the type is not claimed to be primitive.
        assert!(!is_primitive_type("T"));
    }

    #[test]
    fn an_empty_or_symbol_only_type_is_not_claimed_to_be_primitive() {
        assert!(!is_primitive_type(""));
        assert!(!is_primitive_type("()"));
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
