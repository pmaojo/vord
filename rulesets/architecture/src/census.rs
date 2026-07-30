//! Per-component type census: how many types a component declares, and how
//! many of those are abstractions. The input `yunq_import_graph::metrics`
//! needs for Martin's `A` (abstractness) that the import graph cannot
//! provide on its own.
//!
//! "Abstraction" is read the way each language actually spells it: a
//! TypeScript `interface` or `abstract class`, a Rust `trait`, a Python class
//! that subclasses `Protocol`/`ABC` or declares an `@abstractmethod`. Nothing
//! is inferred beyond that — a concrete class with a suggestive name is
//! concrete.

use std::collections::BTreeMap;

use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use yunq_import_graph::{component_of, TypeCensus};

fn is_other(node: &AstNode, kind: &str) -> bool {
    matches!(node.kind(), NodeKind::Other(k) if k.as_ref() == kind)
}

/// One file's type census.
pub fn file_census(file: &SourceFile, ast: &AstNode) -> TypeCensus {
    let language = file.language();
    if *language == LanguageIdentifier::typescript() {
        return ts_census(ast);
    }
    if *language == LanguageIdentifier::python() {
        return python_census(ast);
    }
    if *language == LanguageIdentifier::rust() {
        return rust_census(ast);
    }
    if *language == LanguageIdentifier::go() {
        return go_census(ast);
    }
    TypeCensus::default()
}

/// Go: a `type_spec` is a type; its abstraction is the `interface_type` — which
/// in a Go hexagon is exactly what a port is.
fn go_census(ast: &AstNode) -> TypeCensus {
    let mut census = TypeCensus::default();
    for node in ast.descendants().filter(|n| is_other(n, "type_spec")) {
        census.total += 1;
        if node.children().iter().any(|c| is_other(c, "interface_type")) {
            census.abstractions += 1;
        }
    }
    census
}

fn ts_census(ast: &AstNode) -> TypeCensus {
    let mut census = TypeCensus::default();
    for node in ast.descendants() {
        if is_other(node, "class_declaration") {
            census.total += 1;
        } else if is_other(node, "interface_declaration") || is_other(node, "abstract_class_declaration") {
            census.total += 1;
            census.abstractions += 1;
        }
    }
    census
}

/// Python has no `interface` keyword, so an abstraction is one of the two
/// idioms the standard library sanctions: a `Protocol`/`ABC` base, or an
/// `@abstractmethod` in the body.
fn python_census(ast: &AstNode) -> TypeCensus {
    let mut census = TypeCensus::default();
    for node in ast.descendants().filter(|n| is_other(n, "class_definition")) {
        census.total += 1;
        let abstract_base = node
            .children()
            .iter()
            .find(|c| is_other(c, "argument_list"))
            .is_some_and(|bases| ["Protocol", "ABC", "ABCMeta"].iter().any(|b| bases.text().contains(b)));
        let abstract_method = node
            .descendants()
            .any(|n| is_other(n, "decorator") && n.text().contains("abstractmethod"));
        if abstract_base || abstract_method {
            census.abstractions += 1;
        }
    }
    census
}

fn rust_census(ast: &AstNode) -> TypeCensus {
    let mut census = TypeCensus::default();
    for node in ast.descendants() {
        if is_other(node, "struct_item") || is_other(node, "enum_item") || is_other(node, "union_item") {
            census.total += 1;
        } else if is_other(node, "trait_item") {
            census.total += 1;
            census.abstractions += 1;
        }
    }
    census
}

/// The census of every component in `files`, keyed the way
/// `yunq_import_graph::component_of` keys them — the contract
/// `component_metrics` expects. Test-only paths contribute nothing: a test
/// double is not part of the abstractness of the component it exercises.
pub fn component_census(files: &[(SourceFile, AstNode)]) -> BTreeMap<String, TypeCensus> {
    let mut per_component: BTreeMap<String, TypeCensus> = BTreeMap::new();
    for (file, ast) in files {
        if yunq_rules_engine::is_test_only_path(file.path()) {
            continue;
        }
        per_component.entry(component_of(file.path())).or_default().add(file_census(file, ast));
    }
    per_component
}

#[cfg(test)]
mod tests {
    use super::*;
    use yunq_rules_engine::AstParser;

    fn ts(path: &str, code: &str) -> (SourceFile, AstNode) {
        let file = SourceFile::new(path, code, LanguageIdentifier::typescript()).unwrap();
        let ast = yunq_parser_typescript::TypeScriptParser::new().parse(&file).unwrap();
        (file, ast)
    }

    fn py(path: &str, code: &str) -> (SourceFile, AstNode) {
        let file = SourceFile::new(path, code, LanguageIdentifier::python()).unwrap();
        let ast = yunq_parser_python::PythonParser::new().parse(&file).unwrap();
        (file, ast)
    }

    fn rs(path: &str, code: &str) -> (SourceFile, AstNode) {
        let file = SourceFile::new(path, code, LanguageIdentifier::rust()).unwrap();
        let ast = yunq_parser_rust::RustParser::new().parse(&file).unwrap();
        (file, ast)
    }

    #[test]
    fn typescript_interfaces_and_abstract_classes_are_abstractions() {
        let (file, ast) = ts(
            "src/a.ts",
            "export interface Repo {}\nexport abstract class Base {}\nexport class Impl {}\n",
        );
        assert_eq!(file_census(&file, &ast), TypeCensus::new(3, 2));
    }

    #[test]
    fn python_protocol_and_abstractmethod_are_abstractions() {
        let (file, ast) = py(
            "a.py",
            "from typing import Protocol\n\nclass Repo(Protocol):\n    pass\n\nclass Base:\n    @abstractmethod\n    def do(self):\n        ...\n\nclass Impl:\n    pass\n",
        );
        assert_eq!(file_census(&file, &ast), TypeCensus::new(3, 2));
    }

    #[test]
    fn rust_traits_are_abstractions_and_structs_enums_are_not() {
        let (file, ast) = rs("a.rs", "pub trait Repo {}\npub struct Impl;\npub enum Kind { A }\n");
        assert_eq!(file_census(&file, &ast), TypeCensus::new(3, 1));
    }

    #[test]
    fn go_interfaces_are_abstractions_and_structs_are_not() {
        let file = SourceFile::new(
            "a.go",
            "package p\n\ntype Repo interface {\n\tSave() error\n}\n\ntype Impl struct {\n\tid string\n}\n",
            LanguageIdentifier::go(),
        )
        .unwrap();
        let ast = yunq_parser_go::GoParser::new().parse(&file).unwrap();
        assert_eq!(file_census(&file, &ast), TypeCensus::new(2, 1));
    }

    #[test]
    fn census_is_grouped_by_component_and_skips_test_paths() {
        let files = vec![
            ts("pkg/src/a.ts", "export interface A {}\n"),
            ts("pkg/src/b.ts", "export class B {}\n"),
            ts("tests/c.ts", "export class FakeRepo {}\n"),
        ];
        let census = component_census(&files);
        assert_eq!(census.len(), 1);
        assert_eq!(census["pkg/src"], TypeCensus::new(2, 1));
    }
}
