//! Python class-like type extraction. One of the four per-language modules
//! `super::EXTRACTORS` dispatches to; nothing outside this file knows how
//! Python spells a type.

use vord_ast::{AstNode, NodeKind};

use super::{ClassInfo, MemberInfo, MethodInfo, first_identifier, function_params, is_other};
pub(super) fn build<'a>(node: &'a AstNode, file: &str) -> Option<ClassInfo<'a>> {
    let name = first_identifier(node)
        .map(|n| n.text().to_string())
        .unwrap_or_default();
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
            // `@property`/`@staticmethod`/`@abstractmethod` wrap the `def` in a
            // `decorated_definition`; unwrap it so a decorated method is still
            // a method (a `@property` getter is exactly the kind of member the
            // OOP-smell rules exist to reason about).
            let member = if is_other(member, "decorated_definition") {
                member
                    .children()
                    .iter()
                    .find(|c| *c.kind() == NodeKind::FunctionDef)
                    .unwrap_or(member)
            } else {
                member
            };
            match member.kind() {
                NodeKind::FunctionDef => {
                    if let Some(name_node) = first_identifier(member) {
                        methods.push(MethodInfo {
                            name: name_node.text().to_string(),
                            params: function_params(member),
                            node: member,
                            span: member.span(),
                            trait_name: None,
                            receiver: None,
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
                        member
                            .first_child()
                            .filter(|c| *c.kind() == NodeKind::Assignment)
                    };
                    if let Some(assignment) = assignment {
                        if let Some(target) = assignment
                            .first_child()
                            .filter(|n| *n.kind() == NodeKind::Identifier)
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
    Some(ClassInfo {
        name,
        file: file.to_string(),
        superclass,
        fields,
        methods,
        span: Some(node.span()),
    })
}

/// Scans a method body for `self.attr = ...` assignments — Python's
/// idiomatic way of declaring instance fields (usually in `__init__`, but
/// this scans every method since assignment there is equally a declaration).
fn collect_self_attrs(
    method: &AstNode,
    fields: &mut Vec<MemberInfo>,
    seen: &mut std::collections::BTreeSet<String>,
) {
    for assignment in method
        .descendants()
        .filter(|n| *n.kind() == NodeKind::Assignment)
    {
        let Some(target) = assignment.first_child() else {
            continue;
        };
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
            fields.push(MemberInfo {
                name: prop.text().to_string(),
                declared_type: None,
                span: prop.span(),
            });
        }
    }
}
