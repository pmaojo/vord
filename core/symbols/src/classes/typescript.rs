//! TypeScript class-like type extraction. One of the four per-language modules
//! `super::EXTRACTORS` dispatches to; nothing outside this file knows how
//! TypeScript spells a type.

use vord_ast::{AstNode, NodeKind};

use super::{
    ClassInfo, MemberInfo, MethodInfo, first_identifier, function_params, is_other,
    simple_type_name,
};
use crate::types::declared_type;

pub(super) fn build<'a>(node: &'a AstNode, file: &str) -> Option<ClassInfo<'a>> {
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
        .and_then(|heritage| {
            heritage
                .children()
                .iter()
                .find(|c| is_other(c, "extends_clause"))
        })
        .and_then(|clause| clause.first_child())
        .map(simple_type_name);
    let body = node.children().iter().find(|c| is_other(c, "class_body"));

    let mut fields = Vec::new();
    let mut methods = Vec::new();
    if let Some(body) = body {
        for member in body.children() {
            if *member.kind() == NodeKind::FunctionDef {
                // The name is the first `Identifier` child, not necessarily the
                // first child: `private static foo()` puts an accessibility
                // modifier ahead of it.
                if let Some(name_node) = first_identifier(member) {
                    methods.push(MethodInfo {
                        name: name_node.text().to_string(),
                        params: function_params(member),
                        node: member,
                        span: member.span(),
                        trait_name: None,
                        receiver: None,
                    });
                }
            } else if matches!(member.kind(), NodeKind::Other(k) if k.as_ref().ends_with("field_definition"))
            {
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
    Some(ClassInfo {
        name,
        file: file.to_string(),
        superclass,
        fields,
        methods,
        span: Some(node.span()),
    })
}
