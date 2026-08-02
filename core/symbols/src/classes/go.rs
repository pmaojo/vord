//! Go class-like type extraction. One of the four per-language modules
//! `super::EXTRACTORS` dispatches to; nothing outside this file knows how
//! Go spells a type.

use std::collections::BTreeMap;

use vord_ast::{AstNode, NodeKind};

use super::{ClassInfo, MemberInfo, MethodInfo, first_identifier, function_params, is_other};
use crate::types::declared_type;

/// A Go `type_spec` (`type Order struct { .. }`, `type Repo interface { .. }`).
/// Only struct and interface types become registry entries: a type alias or a
/// defined primitive (`type Cents int64`) has no members for an OOP-smell rule
/// to reason about.
///
/// Interfaces are included deliberately — Go's interfaces are the ports of a Go
/// hexagon, and `smells:fat-interface` has to be able to see one.
pub(super) fn build<'a>(node: &'a AstNode, file: &str) -> Option<ClassInfo<'a>> {
    let name = node
        .children()
        .iter()
        .find(|c| is_other(c, "type_identifier"))?
        .text()
        .to_string();
    let body = node
        .children()
        .iter()
        .find(|c| is_other(c, "struct_type") || is_other(c, "interface_type"))?;
    let fields = body
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
    // An interface's `method_elem` members are its contract; they have no body,
    // so they are recorded for their names and signatures only.
    let methods = body
        .children()
        .iter()
        .filter(|c| is_other(c, "method_elem"))
        .filter_map(|member| {
            let name = first_identifier(member)?.text().to_string();
            Some(MethodInfo {
                name,
                params: function_params(member),
                node: member,
                span: member.span(),
                trait_name: None,
                receiver: None,
            })
        })
        .collect();
    Some(ClassInfo {
        name,
        file: file.to_string(),
        superclass: None,
        fields,
        methods,
        span: Some(node.span()),
    })
}

/// The base type name a Go receiver or return type refers to, unwrapping the
/// pointer and generic layers: `*Order` -> `Order`, `Order[T]` -> `Order`.
fn base_type_name(node: &AstNode) -> Option<String> {
    match node.kind() {
        NodeKind::Other(k) if k.as_ref() == "type_identifier" => Some(node.text().to_string()),
        NodeKind::Other(k) if k.as_ref() == "pointer_type" || k.as_ref() == "generic_type" => {
            node.children().iter().find_map(base_type_name)
        }
        _ => None,
    }
}

/// A Go `FunctionDef`'s receiver, when it has one: `func (o *Order) Ship()` ->
/// `("o", "Order")`.
///
/// The discriminator is structural, because the neutral AST maps Go's
/// `method_declaration` and `function_declaration` onto the same
/// `NodeKind::FunctionDef`: a method leads with the receiver `parameter_list`,
/// a plain function leads with its name.
fn receiver_of(function: &AstNode) -> Option<(String, String)> {
    let first = function.first_child()?;
    if !is_other(first, "parameter_list") {
        return None;
    }
    let declaration = first
        .children()
        .iter()
        .find(|c| is_other(c, "parameter_declaration"))?;
    let type_name = declaration.children().iter().find_map(base_type_name)?;
    let binding = first_identifier(declaration)
        .map(|n| n.text().to_string())
        .unwrap_or_default();
    Some((binding, type_name))
}

/// A Go constructor by convention: `func NewOrder(..) *Order` — a package-level
/// function whose name is `New`/`New<Type>` and which returns that type. Go has
/// no constructors, and this is the convention every codebase uses instead, so
/// the rules that reason about "what does construction require" have to see it.
fn constructor_target(function: &AstNode) -> Option<String> {
    let name = first_identifier(function)?.text();
    let suffix = name.strip_prefix("New")?;
    let returned = function
        .children()
        .iter()
        .skip(1)
        .find_map(base_type_name)?;
    (suffix.is_empty() || suffix == returned).then_some(returned)
}

/// Second pass for Go: attaches every method (`func (o *Order) ..`) and every
/// `New<Type>` constructor function to its already-registered type, across file
/// boundaries — a Go type's methods are routinely spread over several files in
/// the same package.
pub(super) fn attach_methods<'a>(ast: &'a AstNode, classes: &mut BTreeMap<String, ClassInfo<'a>>) {
    for function in ast
        .descendants()
        .filter(|n| *n.kind() == NodeKind::FunctionDef)
    {
        let (receiver, target, name) = match receiver_of(function) {
            Some((binding, target)) => {
                let Some(name) = function.children().iter().find_map(|c| {
                    (*c.kind() == NodeKind::Identifier).then(|| c.text().to_string())
                }) else {
                    continue;
                };
                (Some(binding), target, name)
            }
            None => match constructor_target(function) {
                Some(target) => {
                    let Some(name) = first_identifier(function).map(|n| n.text().to_string())
                    else {
                        continue;
                    };
                    (None, target, name)
                }
                None => continue,
            },
        };
        let Some(class) = classes.get_mut(&target) else {
            continue;
        };
        if class.methods.iter().any(|m| m.name == name) {
            continue;
        }
        class.methods.push(MethodInfo {
            name,
            params: function_params(function),
            node: function,
            span: function.span(),
            trait_name: None,
            receiver,
        });
    }
}
