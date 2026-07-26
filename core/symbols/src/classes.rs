//! Class/struct extraction: a same-file (or, via
//! [`ClassRegistry::build_cross_file`], whole-file-set) registry of every
//! class-like type — its superclass name, its declared fields, and its
//! methods (name, parameters with resolved declared types, and a reference
//! to the method's own `FunctionDef` node for body inspection) — across the
//! three grammar shapes currently supported: TypeScript `class`, Python
//! `class`, and Rust `struct` + its `impl` block(s).
//!
//! Not a general OOP model: single inheritance only (a class's first listed
//! base, Python's MRO and TS/Rust's lack of multiple inheritance both make
//! this the common case), and Rust structs (which have no inheritance) get
//! `superclass: None` unconditionally. Good enough for the OOP-smell rules
//! this exists to support (god class, feature envy, refused bequest) —
//! not a substitute for a real type system.

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
                if let Some(info) = build_class_info(node, file) {
                    classes.entry(info.name.clone()).or_insert(info);
                }
            }
        }
        for (file, ast) in files {
            attach_rust_impls(ast, file, &mut classes);
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

fn build_class_info<'a>(node: &'a AstNode, file: &str) -> Option<ClassInfo<'a>> {
    match node.kind() {
        NodeKind::Other(k) if k.as_ref() == "class_declaration" => Some(build_ts_class(node, file)),
        NodeKind::Other(k) if k.as_ref() == "class_definition" => Some(build_python_class(node, file)),
        NodeKind::Other(k) if k.as_ref() == "struct_item" => Some(build_rust_struct(node, file)),
        _ => None,
    }
}

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
    node.children().iter().find(|c| *c.kind() == NodeKind::Identifier)
}

// ---- TypeScript ------------------------------------------------------

fn build_ts_class<'a>(node: &'a AstNode, file: &str) -> ClassInfo<'a> {
    let name = node
        .children()
        .iter()
        .find(|c| is_other(c, "type_identifier"))
        .map(|c| c.text().to_string())
        .unwrap_or_default();
    let superclass = node
        .children()
        .iter()
        .find(|c| is_other(c, "class_heritage"))
        .and_then(|heritage| heritage.children().iter().find(|c| is_other(c, "extends_clause")))
        .and_then(|clause| clause.first_child())
        .map(simple_type_name);
    let body = node.children().iter().find(|c| is_other(c, "class_body"));

    let mut fields = Vec::new();
    let mut methods = Vec::new();
    if let Some(body) = body {
        for member in body.children() {
            if *member.kind() == NodeKind::FunctionDef {
                if let Some(name_node) = member.first_child().filter(|n| *n.kind() == NodeKind::Identifier) {
                    methods.push(MethodInfo {
                        name: name_node.text().to_string(),
                        params: ts_params(member),
                        node: member,
                        span: member.span(),
                    });
                }
            } else if matches!(member.kind(), NodeKind::Other(k) if k.as_ref().ends_with("field_definition")) {
                if let Some(name_node) = first_identifier(member) {
                    fields.push(MemberInfo {
                        name: name_node.text().to_string(),
                        declared_type: declared_type(member),
                        span: member.span(),
                    });
                }
            }
        }
    }
    ClassInfo { name, file: file.to_string(), superclass, fields, methods, span: Some(node.span()) }
}

fn ts_params(function: &AstNode) -> Vec<MemberInfo> {
    let Some(wrapper) = function.children().iter().find(|c| is_other(c, "formal_parameters")) else {
        return Vec::new();
    };
    wrapper.children().iter().map(extract_param).collect()
}

/// A single parameter node → its bound name and declared type, handling
/// both a bare `Identifier` (untyped) and a wrapper node (`required_parameter`
/// /`typed_parameter`/`default_parameter`/...) whose first `Identifier`
/// child is the bound name.
fn extract_param(node: &AstNode) -> MemberInfo {
    if *node.kind() == NodeKind::Identifier {
        return MemberInfo { name: node.text().to_string(), declared_type: None, span: node.span() };
    }
    let name = first_identifier(node).map(|n| n.text().to_string()).unwrap_or_default();
    MemberInfo { name, declared_type: declared_type(node), span: node.span() }
}

// ---- Python ------------------------------------------------------------

const SELF_NAMES: &[&str] = &["self", "cls"];

fn build_python_class<'a>(node: &'a AstNode, file: &str) -> ClassInfo<'a> {
    let name = first_identifier(node).map(|n| n.text().to_string()).unwrap_or_default();
    let superclass = node
        .children()
        .iter()
        .find(|c| is_other(c, "argument_list"))
        .and_then(first_identifier)
        .map(|n| n.text().to_string());
    let body = node.children().iter().find(|c| is_other(c, "block"));

    let mut fields = Vec::new();
    let mut methods = Vec::new();
    let mut field_names = std::collections::BTreeSet::new();
    if let Some(body) = body {
        for member in body.children() {
            match member.kind() {
                NodeKind::FunctionDef => {
                    if let Some(name_node) = member.first_child().filter(|n| *n.kind() == NodeKind::Identifier) {
                        methods.push(MethodInfo {
                            name: name_node.text().to_string(),
                            params: python_params(member),
                            node: member,
                            span: member.span(),
                        });
                        collect_self_attrs(member, &mut fields, &mut field_names);
                    }
                }
                _ => {
                    // A class-level `attr = value` is wrapped in an
                    // `expression_statement` (same pattern the "declaration
                    // wrapper" note in `core/rules-engine::structural_metrics`
                    // documents for TS's `lexical_declaration`); unwrap one
                    // level to find the `Assignment`, if any.
                    let assignment = if *member.kind() == NodeKind::Assignment {
                        Some(member)
                    } else {
                        member.first_child().filter(|c| *c.kind() == NodeKind::Assignment)
                    };
                    if let Some(assignment) = assignment {
                        if let Some(target) = assignment.first_child().filter(|n| *n.kind() == NodeKind::Identifier)
                        {
                            if field_names.insert(target.text().to_string()) {
                                fields.push(MemberInfo {
                                    name: target.text().to_string(),
                                    declared_type: None,
                                    span: assignment.span(),
                                });
                            }
                        }
                    }
                }
            }
        }
    }
    ClassInfo { name, file: file.to_string(), superclass, fields, methods, span: Some(node.span()) }
}

fn python_params(function: &AstNode) -> Vec<MemberInfo> {
    let Some(wrapper) = function.children().iter().find(|c| is_other(c, "parameters")) else {
        return Vec::new();
    };
    wrapper
        .children()
        .iter()
        .map(extract_param)
        .filter(|p| !SELF_NAMES.contains(&p.name.as_str()))
        .collect()
}

/// Scans a method body for `self.attr = ...` assignments — Python's
/// idiomatic way of declaring instance fields (usually in `__init__`, but
/// this scans every method since assignment there is equally a declaration).
fn collect_self_attrs(
    method: &AstNode,
    fields: &mut Vec<MemberInfo>,
    seen: &mut std::collections::BTreeSet<String>,
) {
    for assignment in method.descendants().filter(|n| *n.kind() == NodeKind::Assignment) {
        let Some(target) = assignment.first_child() else { continue };
        if *target.kind() != NodeKind::MemberAccess {
            continue;
        }
        let mut parts = target.children().iter();
        let Some(base) = parts.next() else { continue };
        if *base.kind() != NodeKind::Identifier || base.text() != "self" {
            continue;
        }
        let Some(prop) = parts.next() else { continue };
        if *prop.kind() == NodeKind::Identifier && seen.insert(prop.text().to_string()) {
            fields.push(MemberInfo { name: prop.text().to_string(), declared_type: None, span: prop.span() });
        }
    }
}

// ---- Rust ----------------------------------------------------------------

fn build_rust_struct<'a>(node: &'a AstNode, file: &str) -> ClassInfo<'a> {
    let name = node
        .children()
        .iter()
        .find(|c| is_other(c, "type_identifier"))
        .map(|c| c.text().to_string())
        .unwrap_or_default();
    let fields = node
        .children()
        .iter()
        .find(|c| is_other(c, "field_declaration_list"))
        .map(|list| {
            list.children()
                .iter()
                .filter(|f| is_other(f, "field_declaration"))
                .filter_map(|f| {
                    first_identifier(f).map(|n| MemberInfo {
                        name: n.text().to_string(),
                        declared_type: declared_type(f),
                        span: f.span(),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    ClassInfo { name, file: file.to_string(), superclass: None, fields, methods: Vec::new(), span: Some(node.span()) }
}

/// A type expression node's base type name: a bare `type_identifier` as-is,
/// a `generic_type`'s own name with its `<...>` arguments stripped
/// (`AnalyzerService<S, M>` → `AnalyzerService`), or a `reference_type`'s
/// referent recursed into (`&Foo`/`&mut Foo` → `Foo`). `None` for anything
/// else (lifetimes, tuple types, …) — not a type expression at all.
fn impl_type_name(node: &AstNode) -> Option<String> {
    match node.kind() {
        NodeKind::Other(k) if k.as_ref() == "type_identifier" => Some(node.text().to_string()),
        NodeKind::Other(k) if k.as_ref() == "generic_type" => {
            node.children().iter().find(|c| is_other(c, "type_identifier")).map(|c| c.text().to_string())
        }
        NodeKind::Other(k) if k.as_ref() == "reference_type" => node.children().iter().find_map(impl_type_name),
        _ => None,
    }
}

/// Second pass: attaches every `impl Foo { .. }` / `impl Trait for Foo { .. }`
/// block's concrete methods (function items with a body — trait method
/// *signatures* with no default body are skipped, they have nothing to
/// inspect) to the already-registered struct `Foo`.
fn attach_rust_impls<'a>(ast: &'a AstNode, _file: &str, classes: &mut BTreeMap<String, ClassInfo<'a>>) {
    for impl_node in ast.descendants().filter(|n| is_other(n, "impl_item")) {
        // `impl Foo` → [Foo]; `impl Trait for Foo` → [Trait, Foo]; `impl<T>
        // Foo<T>` → [Foo<T>] (a `generic_type`, not a bare `type_identifier`,
        // since it carries type arguments) — either way the implemented-for
        // type is the last type-expression child, in declaration order (the
        // `type_parameters`/`where_clause`/`declaration_list` siblings never
        // match `impl_type_name`, so they don't interfere).
        let type_names: Vec<&AstNode> =
            impl_node.children().iter().filter(|c| impl_type_name(c).is_some()).collect();
        let Some(target_name) = type_names.last().and_then(|n| impl_type_name(n)) else { continue };
        let Some(class) = classes.get_mut(&target_name) else { continue };
        let Some(decls) = impl_node.children().iter().find(|c| is_other(c, "declaration_list")) else { continue };
        for member in decls.children() {
            if *member.kind() != NodeKind::FunctionDef {
                continue;
            }
            let Some(name_node) = member.first_child().filter(|n| *n.kind() == NodeKind::Identifier) else {
                continue;
            };
            if class.methods.iter().any(|m| m.name == name_node.text()) {
                continue; // first impl wins on a duplicate (e.g. same trait re-exported)
            }
            class.methods.push(MethodInfo {
                name: name_node.text().to_string(),
                params: rust_params(member),
                node: member,
                span: member.span(),
            });
        }
    }
}

fn rust_params(function: &AstNode) -> Vec<MemberInfo> {
    let Some(wrapper) = function.children().iter().find(|c| is_other(c, "parameters")) else {
        return Vec::new();
    };
    wrapper
        .children()
        .iter()
        .filter(|p| !is_other(p, "self_parameter"))
        .map(extract_param)
        .collect()
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
        assert_eq!(foo.methods[0].params[0].declared_type.as_deref(), Some("Other"));
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
    fn cross_file_registry_merges_impls_from_other_files() {
        let struct_file = parse_rust("struct Foo { x: i32 }\n");
        let impl_file = parse_rust("impl Foo {\n    fn bar(&self) -> i32 {\n        self.x\n    }\n}\n");
        let registry = ClassRegistry::build_cross_file(&[("s.rs", &struct_file), ("i.rs", &impl_file)]);
        let foo = registry.get("Foo").unwrap();
        assert_eq!(foo.methods.len(), 1);
        assert_eq!(foo.methods[0].name, "bar");
    }
}
