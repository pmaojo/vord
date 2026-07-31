//! Class/struct extraction: a same-file (or, via
//! [`ClassRegistry::build_cross_file`], whole-file-set) registry of every
//! class-like type — its superclass name, its declared fields, and its
//! methods (name, parameters with resolved declared types, and a reference
//! to the method's own `FunctionDef` node for body inspection).
//!
//! **One module per language, one table, no language conditionals.** Every
//! grammar's "how do I spell a type" knowledge lives in its own submodule
//! (`typescript`, `python`, `rust`, `go`) and reaches this one only through
//! [`EXTRACTORS`], a table of `(declaration kind, build, attach)` rows. The
//! registry itself never asks what language it is looking at — it walks the
//! table, exactly as `yunq_ast::lookup_kind` walks a kind table instead of
//! matching on grammar names. Adding a language is a new file and a new row;
//! nothing here changes, which is the same Open/Closed property the `Rule`
//! trait gives rulesets.
//!
//! Not a general OOP model: single inheritance only (a class's first listed
//! base — Python's MRO and TS's lack of multiple inheritance both make this
//! the common case), and Rust structs and Go types get `superclass: None`
//! unconditionally because neither language has inheritance. Good enough for
//! the OOP-smell rules this exists to support (god class, feature envy,
//! refused bequest, the SOLID and DDD rulesets) — not a substitute for a
//! real type system.

mod go;
mod python;
mod rust;
mod typescript;

use std::collections::BTreeMap;

use yunq_ast::{AstNode, NodeKind, Span};

use crate::types::declared_type;

fn is_other(node: &AstNode, kind: &str) -> bool {
    matches!(node.kind(), NodeKind::Other(k) if k.as_ref() == kind)
}

/// A named member (field or parameter) with its optional declared type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberInfo {
    pub name: String,
    pub declared_type: Option<String>,
    pub span: Span,
}

/// One method: its parameters (for feature-envy's "does a parameter's type
/// resolve to another known class" query) and a reference to its own
/// `FunctionDef` node (for refused-bequest's "is the override body trivial"
/// and feature-envy's "count member accesses by owning class" checks).
#[derive(Clone, Debug)]
pub struct MethodInfo<'a> {
    pub name: String,
    pub params: Vec<MemberInfo>,
    pub node: &'a AstNode,
    pub span: Span,
    /// For a Rust method declared in an `impl Trait for Type` block, the
    /// trait's simple name; `None` for a method the type declares on its
    /// own terms (an inherent `impl Type` block, or a TypeScript/Python
    /// class body). The distinction matters to any analysis that reads a
    /// method set as evidence of how the author *chose* to shape the type:
    /// a trait method's existence, name and signature are dictated by the
    /// trait, so it says nothing about that type's design.
    pub trait_name: Option<String>,
    /// The name the method's body uses to refer to its own instance, when the
    /// language makes it a declared parameter rather than a keyword: Go's
    /// receiver (`func (o *Order) ...` -> `"o"`). `None` where the language
    /// fixes it (`this`, `self`), which every consumer already handles.
    pub receiver: Option<String>,
}

impl MethodInfo<'_> {
    /// Whether this method satisfies a trait the type implements, rather
    /// than being one the type declares for itself.
    pub fn is_trait_impl(&self) -> bool {
        self.trait_name.is_some()
    }
}

/// One class/struct: its declared fields, its methods, and its superclass
/// name (if any), plus which file it came from (empty string for
/// single-file [`ClassRegistry::build`]).
#[derive(Clone, Debug, Default)]
pub struct ClassInfo<'a> {
    pub name: String,
    pub file: String,
    pub superclass: Option<String>,
    pub fields: Vec<MemberInfo>,
    pub methods: Vec<MethodInfo<'a>>,
    pub span: Option<Span>,
}

impl<'a> ClassInfo<'a> {
    pub fn method(&self, name: &str) -> Option<&MethodInfo<'a>> {
        self.methods.iter().find(|m| m.name == name)
    }

    /// The type's constructor, whatever its language calls one:
    /// `constructor`/`__init__` (TypeScript/Python), `new` (Rust convention),
    /// or Go's `New`/`New<Type>` package function (see
    /// `go_constructor_target`). Kept here rather than duplicated as a name
    /// list in every rule that asks "what does construction require".
    pub fn constructor(&self) -> Option<&MethodInfo<'a>> {
        self.methods
            .iter()
            .find(|m| is_constructor_name(&m.name, &self.name))
    }
}

/// Whether `method` names the constructor of a type called `type_name`.
pub fn is_constructor_name(method: &str, type_name: &str) -> bool {
    if matches!(method, "constructor" | "__init__" | "new") {
        return true;
    }
    method
        .strip_prefix("New")
        .is_some_and(|suffix| suffix.is_empty() || suffix == type_name)
}

/// A registry of every class-like type found across one or more files,
/// keyed by name. First declaration wins on a name collision — the same
/// simplifying convention `core/taint`'s cross-file analysis uses for
/// function names: no scoping, no aliasing, project-wide by name.
#[derive(Debug, Default)]
pub struct ClassRegistry<'a> {
    classes: BTreeMap<String, ClassInfo<'a>>,
}

impl<'a> ClassRegistry<'a> {
    /// Builds a registry from a single file's AST.
    pub fn build(ast: &'a AstNode) -> Self {
        Self::build_cross_file(&[("", ast)])
    }

    /// Builds a registry spanning every file in `files`, matching Rust
    /// `impl` blocks to their struct across file boundaries (a struct and
    /// its trait impls are commonly split across files).
    pub fn build_cross_file(files: &[(&'a str, &'a AstNode)]) -> Self {
        let mut classes: BTreeMap<String, ClassInfo<'a>> = BTreeMap::new();
        for (file, ast) in files {
            for node in ast.descendants() {
                for extractor in EXTRACTORS {
                    if !is_other(node, extractor.declaration_kind) {
                        continue;
                    }
                    if let Some(info) = (extractor.build)(node, file) {
                        classes.entry(info.name.clone()).or_insert(info);
                    }
                }
            }
        }
        for (_, ast) in files {
            for attach in EXTRACTORS.iter().filter_map(|e| e.attach) {
                attach(ast, &mut classes);
            }
        }
        Self { classes }
    }

    pub fn get(&self, name: &str) -> Option<&ClassInfo<'a>> {
        self.classes.get(name)
    }

    pub fn iter(&self) -> impl Iterator<Item = &ClassInfo<'a>> {
        self.classes.values()
    }
}

/// One language's class extraction, as data rather than a branch.
///
/// `build` turns a declaration node of `declaration_kind` into a
/// [`ClassInfo`]; `attach` is the optional second pass for languages that
/// declare a type's methods away from the type itself (Rust `impl` blocks, Go
/// receiver functions), and runs once per file after every declaration in the
/// whole file set is registered.
struct ClassExtractor {
    /// The raw grammar kind a type declaration has in this language.
    declaration_kind: &'static str,
    build: BuildFn,
    attach: Option<AttachFn>,
}

/// Turns one type-declaration node into a [`ClassInfo`].
type BuildFn = for<'a> fn(&'a AstNode, &str) -> Option<ClassInfo<'a>>;

/// Attaches methods declared away from their type (Rust `impl` blocks, Go
/// receiver functions) to types already in the registry.
type AttachFn = for<'a> fn(&'a AstNode, &mut BTreeMap<String, ClassInfo<'a>>);

/// Every language this registry understands. The only place in the crate that
/// enumerates them.
const EXTRACTORS: &[ClassExtractor] = &[
    ClassExtractor {
        declaration_kind: "class_declaration",
        build: typescript::build,
        attach: None,
    },
    ClassExtractor {
        declaration_kind: "class_definition",
        build: python::build,
        attach: None,
    },
    ClassExtractor {
        declaration_kind: "struct_item",
        build: rust::build,
        attach: Some(rust::attach_impls),
    },
    ClassExtractor {
        declaration_kind: "type_spec",
        build: go::build,
        attach: Some(go::attach_methods),
    },
];

/// A type reference's simple name: the identifier text as-is, or a
/// `MemberAccess` chain's last segment (`React.Component` → `Component`).
fn simple_type_name(node: &AstNode) -> String {
    match node.kind() {
        NodeKind::MemberAccess => node
            .children()
            .last()
            .map(simple_type_name)
            .unwrap_or_else(|| node.text().to_string()),
        _ => node.text().to_string(),
    }
}

fn first_identifier(node: &AstNode) -> Option<&AstNode> {
    node.children()
        .iter()
        .find(|c| *c.kind() == NodeKind::Identifier)
}

/// The parameters of any function-like node, whatever its grammar calls the
/// wrapper: TypeScript `formal_parameters`, Python and Rust `parameters`, Go
/// `parameter_list`.
///
/// One implementation for all four, because the differences turned out to be
/// data, not logic: take the *last* wrapper (Go puts the receiver in the first
/// one), map each entry through [`extract_param`], and drop the entries that
/// name the instance rather than a parameter (`self`, `cls`, Rust's
/// `self_parameter`).
pub fn function_params(function: &AstNode) -> Vec<MemberInfo> {
    const WRAPPERS: &[&str] = &["formal_parameters", "parameters", "parameter_list"];
    const INSTANCE_NAMES: &[&str] = &["self", "cls"];
    let Some(wrapper) = function
        .children()
        .iter()
        .rfind(|c| matches!(c.kind(), NodeKind::Other(k) if WRAPPERS.contains(&k.as_ref())))
    else {
        return Vec::new();
    };
    wrapper
        .children()
        .iter()
        .filter(|param| !is_other(param, "self_parameter"))
        .map(extract_param)
        .filter(|param| !INSTANCE_NAMES.contains(&param.name.as_str()))
        .collect()
}

/// A single parameter node → its bound name and declared type, handling
/// both a bare `Identifier` (untyped) and a wrapper node (`required_parameter`
/// /`typed_parameter`/`default_parameter`/`parameter_declaration`/...) whose
/// first `Identifier` child is the bound name. Shared by every language
/// module: the shape is the same everywhere, only the wrapper's name differs.
fn extract_param(node: &AstNode) -> MemberInfo {
    if *node.kind() == NodeKind::Identifier {
        return MemberInfo {
            name: node.text().to_string(),
            declared_type: None,
            span: node.span(),
        };
    }
    let name = first_identifier(node)
        .map(|n| n.text().to_string())
        .unwrap_or_default();
    MemberInfo {
        name,
        declared_type: declared_type(node),
        span: node.span(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use yunq_ast::{LanguageIdentifier, SourceFile};
    use yunq_rules_engine::AstParser;

    fn parse_ts(code: &str) -> AstNode {
        let file = SourceFile::new("t.ts", code, LanguageIdentifier::typescript()).unwrap();
        yunq_parser_typescript::TypeScriptParser::new()
            .parse(&file)
            .unwrap()
    }

    fn parse_rust(code: &str) -> AstNode {
        let file = SourceFile::new("t.rs", code, LanguageIdentifier::rust()).unwrap();
        yunq_parser_rust::RustParser::new().parse(&file).unwrap()
    }

    fn parse_py(code: &str) -> AstNode {
        let file = SourceFile::new("t.py", code, LanguageIdentifier::python()).unwrap();
        yunq_parser_python::PythonParser::new()
            .parse(&file)
            .unwrap()
    }

    #[test]
    fn ts_class_fields_methods_and_superclass() {
        let ast = parse_ts(
            "class Base {}\nclass Foo extends Base {\n  private x: number = 1;\n  method(a: Other): void {\n    this.x = 1;\n  }\n}\n",
        );
        let registry = ClassRegistry::build(&ast);
        let foo = registry.get("Foo").unwrap();
        assert_eq!(foo.superclass.as_deref(), Some("Base"));
        assert_eq!(foo.fields.len(), 1);
        assert_eq!(foo.fields[0].name, "x");
        assert_eq!(foo.fields[0].declared_type.as_deref(), Some("number"));
        assert_eq!(foo.methods.len(), 1);
        assert_eq!(foo.methods[0].name, "method");
        assert_eq!(foo.methods[0].params[0].name, "a");
        assert_eq!(
            foo.methods[0].params[0].declared_type.as_deref(),
            Some("Other")
        );
    }

    #[test]
    fn python_class_inheritance_and_self_attrs() {
        let ast = parse_py(
            "class Base:\n    pass\n\nclass Child(Base):\n    shared = 1\n\n    def __init__(self, x):\n        self.x = x\n        self.y = 0\n\n    def bump(self):\n        self.y += 1\n",
        );
        let registry = ClassRegistry::build(&ast);
        let child = registry.get("Child").unwrap();
        assert_eq!(child.superclass.as_deref(), Some("Base"));
        let field_names: Vec<_> = child.fields.iter().map(|f| f.name.as_str()).collect();
        assert!(field_names.contains(&"shared"));
        assert!(field_names.contains(&"x"));
        assert!(field_names.contains(&"y"));
        assert_eq!(child.methods.len(), 2);
        let init = child.method("__init__").unwrap();
        assert_eq!(init.params.len(), 1);
        assert_eq!(init.params[0].name, "x");
    }

    #[test]
    fn rust_struct_with_impl_and_trait_impl() {
        let ast = parse_rust(
            "struct Foo {\n    x: i32,\n}\n\nimpl Foo {\n    fn bar(&self, a: i32) -> i32 {\n        self.x + a\n    }\n}\n\ntrait Shape {\n    fn area(&self) -> f64;\n}\n\nimpl Shape for Foo {\n    fn area(&self) -> f64 {\n        0.0\n    }\n}\n",
        );
        let registry = ClassRegistry::build(&ast);
        let foo = registry.get("Foo").unwrap();
        assert_eq!(foo.fields.len(), 1);
        assert_eq!(foo.fields[0].name, "x");
        assert_eq!(foo.fields[0].declared_type.as_deref(), Some("i32"));
        assert_eq!(foo.methods.len(), 2);
        assert!(foo.method("bar").is_some());
        assert!(foo.method("area").is_some());
        assert_eq!(foo.method("bar").unwrap().params[0].name, "a");
    }

    #[test]
    fn rust_generic_struct_impl_methods_are_attached() {
        // A generic `impl<S, M> Foo<S, M>` target is a `generic_type` node
        // (`Foo<S, M>`), not a bare `type_identifier` — this used to make
        // `attach_rust_impls` fail to match the target struct at all,
        // silently dropping every method a generic impl block declares.
        let ast = parse_rust(
            "struct Foo<S, M> {\n    a: S,\n    b: M,\n}\n\nimpl<S, M> Foo<S, M>\nwhere\n    S: Clone,\n{\n    fn bar(&self) -> i32 {\n        1\n    }\n}\n",
        );
        let registry = ClassRegistry::build(&ast);
        let foo = registry.get("Foo").unwrap();
        assert_eq!(foo.methods.len(), 1);
        assert!(foo.method("bar").is_some());
    }

    #[test]
    fn rust_trait_impl_for_a_reference_type_attaches_methods() {
        // `impl Trait for &Foo` — the implemented-for type is a
        // `reference_type` wrapping the real target, not a bare
        // `type_identifier`.
        let ast = parse_rust(
            "struct Foo {\n    x: i32,\n}\n\ntrait Show {\n    fn show(&self) -> i32;\n}\n\nimpl Show for &Foo {\n    fn show(&self) -> i32 {\n        self.x\n    }\n}\n",
        );
        let registry = ClassRegistry::build(&ast);
        let foo = registry.get("Foo").unwrap();
        assert_eq!(foo.methods.len(), 1);
        assert!(foo.method("show").is_some());
    }

    #[test]
    fn rust_public_methods_and_user_defined_types_are_recorded() {
        // `pub fn` leads with a `visibility_modifier`, and a plain
        // `type_identifier` is how Rust writes a project's own type: both used
        // to be dropped, hiding every public method and every domain-typed
        // field from the OOP-smell rules.
        let ast = parse_rust(
            "pub struct Dep;\npub struct Service {\n    dep: Dep,\n}\n\nimpl Service {\n    pub fn new(dep: Dep) -> Self {\n        Self { dep }\n    }\n}\n",
        );
        let registry = ClassRegistry::build(&ast);
        let service = registry.get("Service").unwrap();
        assert_eq!(service.fields[0].declared_type.as_deref(), Some("Dep"));
        let constructor = service
            .method("new")
            .expect("pub fn new should be recorded");
        assert_eq!(constructor.params[0].declared_type.as_deref(), Some("Dep"));
    }

    #[test]
    fn typescript_methods_with_modifiers_are_recorded() {
        let ast = parse_ts("class Service {\n  private static run(a: Dep): void {}\n}\n");
        let registry = ClassRegistry::build(&ast);
        assert!(registry.get("Service").unwrap().method("run").is_some());
    }

    #[test]
    fn python_decorated_methods_are_recorded() {
        let ast = parse_py(
            "class Order:\n    @property\n    def total(self):\n        return self._total\n\n    @staticmethod\n    def build():\n        return Order()\n",
        );
        let registry = ClassRegistry::build(&ast);
        let order = registry.get("Order").unwrap();
        assert!(order.method("total").is_some());
        assert!(order.method("build").is_some());
    }

    fn parse_go(code: &str) -> AstNode {
        let file = SourceFile::new("t.go", code, LanguageIdentifier::go()).unwrap();
        yunq_parser_go::GoParser::new().parse(&file).unwrap()
    }

    #[test]
    fn go_struct_fields_methods_receiver_and_constructor() {
        let ast = parse_go(
            "package domain\n\ntype Order struct {\n\tID string\n\tItems []Item\n}\n\nfunc NewOrder(id string) *Order {\n\treturn &Order{ID: id}\n}\n\nfunc (o *Order) Ship(at int64) error {\n\treturn nil\n}\n",
        );
        let registry = ClassRegistry::build(&ast);
        let order = registry.get("Order").unwrap();
        assert_eq!(order.fields.len(), 2);
        assert_eq!(order.fields[0].name, "ID");
        assert_eq!(order.fields[0].declared_type.as_deref(), Some("string"));
        assert_eq!(order.fields[1].declared_type.as_deref(), Some("[]Item"));

        let ship = order.method("Ship").expect("receiver method attached");
        assert_eq!(ship.receiver.as_deref(), Some("o"));
        assert_eq!(
            ship.params.len(),
            1,
            "the receiver is not a parameter: {:?}",
            ship.params
        );
        assert_eq!(ship.params[0].name, "at");
        assert_eq!(ship.params[0].declared_type.as_deref(), Some("int64"));

        let constructor = order
            .method("NewOrder")
            .expect("New<Type> function attached");
        assert!(constructor.receiver.is_none());
        assert_eq!(constructor.params[0].name, "id");
    }

    #[test]
    fn go_interface_methods_are_its_contract() {
        let ast = parse_go(
            "package ports\n\ntype Orders interface {\n\tSave(o *Order) error\n\tFind(id string) (*Order, error)\n}\n",
        );
        let registry = ClassRegistry::build(&ast);
        let orders = registry.get("Orders").unwrap();
        assert_eq!(orders.methods.len(), 2);
        assert!(orders.method("Save").is_some());
        assert!(orders.method("Find").is_some());
    }

    #[test]
    fn a_go_function_that_is_not_a_constructor_attaches_to_nothing() {
        let ast = parse_go(
            "package domain\n\ntype Order struct {\n\tID string\n}\n\nfunc Describe(o *Order) string {\n\treturn o.ID\n}\n",
        );
        let registry = ClassRegistry::build(&ast);
        assert!(registry.get("Order").unwrap().methods.is_empty());
    }

    #[test]
    fn go_methods_attach_across_files_in_the_same_package() {
        let type_file = parse_go("package domain\n\ntype Order struct {\n\tID string\n}\n");
        let method_file =
            parse_go("package domain\n\nfunc (o *Order) Ship() error {\n\treturn nil\n}\n");
        let registry =
            ClassRegistry::build_cross_file(&[("order.go", &type_file), ("ship.go", &method_file)]);
        assert!(registry.get("Order").unwrap().method("Ship").is_some());
    }

    #[test]
    fn cross_file_registry_merges_impls_from_other_files() {
        let struct_file = parse_rust("struct Foo { x: i32 }\n");
        let impl_file =
            parse_rust("impl Foo {\n    fn bar(&self) -> i32 {\n        self.x\n    }\n}\n");
        let registry =
            ClassRegistry::build_cross_file(&[("s.rs", &struct_file), ("i.rs", &impl_file)]);
        let foo = registry.get("Foo").unwrap();
        assert_eq!(foo.methods.len(), 1);
        assert_eq!(foo.methods[0].name, "bar");
    }
}
