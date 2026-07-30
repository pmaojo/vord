//! Rust class-like type extraction. One of the four per-language modules
//! `super::EXTRACTORS` dispatches to; nothing outside this file knows how
//! Rust spells a type.

use std::collections::BTreeMap;

use yunq_ast::{AstNode, NodeKind};

use super::{first_identifier, function_params, is_other, ClassInfo, MemberInfo, MethodInfo};
use crate::types::declared_type;

pub(super) fn build<'a>(node: &'a AstNode, file: &str) -> Option<ClassInfo<'a>> {
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
    Some(ClassInfo { name, file: file.to_string(), superclass: None, fields, methods: Vec::new(), span: Some(node.span()) })
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
pub(super) fn attach_impls<'a>(ast: &'a AstNode, classes: &mut BTreeMap<String, ClassInfo<'a>>) {
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
        // Two type expressions means `impl Trait for Foo` — the first is
        // the trait. One means an inherent `impl Foo`, no trait involved.
        let trait_name =
            (type_names.len() >= 2).then(|| impl_type_name(type_names[0])).flatten();
        let Some(class) = classes.get_mut(&target_name) else { continue };
        let Some(decls) = impl_node.children().iter().find(|c| is_other(c, "declaration_list")) else { continue };
        for member in decls.children() {
            if *member.kind() != NodeKind::FunctionDef {
                continue;
            }
            // First `Identifier` child, not first child: `pub fn new(..)` leads
            // with a `visibility_modifier`, and dropping those would hide every
            // public method a Rust type has from every OOP-smell rule.
            let Some(name_node) = first_identifier(member) else {
                continue;
            };
            if class.methods.iter().any(|m| m.name == name_node.text()) {
                continue; // first impl wins on a duplicate (e.g. same trait re-exported)
            }
            class.methods.push(MethodInfo {
                name: name_node.text().to_string(),
                params: function_params(member),
                node: member,
                span: member.span(),
                trait_name: trait_name.clone(),
                receiver: None,
            });
        }
    }
}

