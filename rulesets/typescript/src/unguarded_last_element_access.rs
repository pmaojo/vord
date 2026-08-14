//! Rule: flags `arr[arr.length - N].prop` (or `arr.at(-N).prop`) accessed
//! directly, with no guard for `arr` being empty — indexing past the end
//! (or an empty array's `-1`) yields `undefined`, and the immediate
//! property access then throws `Cannot read properties of undefined`.
//! `useChatScroll`-shaped code (`lastMessage`/`previousMessage` derived
//! from a possibly-empty messages array) is exactly this shape.
//!
//! A guard is recognized in the three places that actually short-circuit
//! the access: an `if (arr.length) { ... }` consequent, the right side of
//! `arr.length > 0 && ...`, and the consequent branch of
//! `arr.length ? ... : ...`. Optional chaining (`?.`) on the access itself
//! also counts as guarded — the whole point of `?.` is exactly this
//! safety. Deliberately narrow: a length check via a different mechanism
//! (an early `return` from a helper, a destructured `.length` bound to its
//! own variable first) is not recognized and stays silent rather than
//! guessing.

use std::collections::BTreeSet;

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

use crate::common::is_other;

fn operator_between<'a>(
    container: &'a AstNode,
    first: &AstNode,
    second: &AstNode,
) -> Option<&'a str> {
    container.text_between(first, second).map(str::trim)
}

/// The array identifier name behind `arr[arr.length - N]`, if `member` is
/// shaped exactly that way: a bracket (computed) member access whose index
/// is `<same-array>.length - <number>`.
fn length_minus_index_array_name(member: &AstNode) -> Option<&str> {
    let [object, index] = member.children() else {
        return None;
    };
    let op = operator_between(member, object, index)?;
    if !op.starts_with('[') {
        return None;
    }
    if *object.kind() != NodeKind::Identifier {
        return None;
    }
    if !is_other(index, "binary_expression") {
        return None;
    }
    let [length_expr, offset] = index.children() else {
        return None;
    };
    if operator_between(index, length_expr, offset)? != "-" {
        return None;
    }
    if *offset.kind() != NodeKind::Other("number".into()) {
        return None;
    }
    if *length_expr.kind() != NodeKind::MemberAccess {
        return None;
    }
    let [arr, prop] = length_expr.children() else {
        return None;
    };
    if operator_between(length_expr, arr, prop)? != "." || prop.text() != "length" {
        return None;
    }
    (*arr.kind() == NodeKind::Identifier && arr.text() == object.text()).then(|| arr.text())
}

/// The array identifier name behind `arr.at(-N)`, if `call` is shaped
/// exactly that way.
fn at_negative_index_array_name(call: &AstNode) -> Option<&str> {
    if *call.kind() != NodeKind::Call {
        return None;
    }
    let callee = call.first_child()?;
    if *callee.kind() != NodeKind::MemberAccess {
        return None;
    }
    let [arr, method] = callee.children() else {
        return None;
    };
    if *arr.kind() != NodeKind::Identifier || method.text() != "at" {
        return None;
    }
    let args = call
        .children()
        .iter()
        .find(|c| is_other(c, "arguments"))
        .map(|a| a.children())
        .unwrap_or(&[]);
    let [arg] = args else {
        return None;
    };
    let is_negative = is_other(arg, "unary_expression") && arg.text().trim_start().starts_with('-');
    is_negative.then(|| arr.text())
}

/// If `node` is a direct, non-optional property/element access on a
/// `arr[arr.length - N]` or `arr.at(-N)` expression, the array's name and
/// the finding span.
fn flagged_access(node: &AstNode) -> Option<(&str, vord_ast::Span)> {
    if *node.kind() != NodeKind::MemberAccess {
        return None;
    }
    let [object, accessed] = node.children() else {
        return None;
    };
    let op = operator_between(node, object, accessed)?;
    if op.starts_with('?') {
        return None; // optional chaining is itself the guard
    }
    let name = match object.kind() {
        NodeKind::MemberAccess => length_minus_index_array_name(object),
        NodeKind::Call => at_negative_index_array_name(object),
        _ => None,
    }?;
    Some((name, node.span()))
}

/// Names of arrays whose `.length` is referenced anywhere in `condition`'s
/// text — the guard-recognition heuristic: textual, not structural, so it
/// tolerates `arr.length > 0`, `arr.length !== 0`, and bare `arr.length`
/// alike.
fn length_guarded_names(condition: &AstNode) -> BTreeSet<String> {
    condition
        .descendants()
        .filter(|n| *n.kind() == NodeKind::MemberAccess)
        .filter_map(|member| {
            let [object, prop] = member.children() else {
                return None;
            };
            (*object.kind() == NodeKind::Identifier && prop.text() == "length")
                .then(|| object.text().to_string())
        })
        .collect()
}

fn walk(node: &AstNode, guarded: &BTreeSet<String>, out: &mut Vec<Finding>) {
    if is_other(node, "if_statement") {
        let condition = node.first_child();
        let consequent = node.children().get(1);
        let alternate = node.children().get(2);
        if let Some(condition) = condition {
            walk(condition, guarded, out);
            let mut inner = guarded.clone();
            inner.extend(length_guarded_names(condition));
            if let Some(consequent) = consequent {
                walk(consequent, &inner, out);
            }
        }
        if let Some(alternate) = alternate {
            walk(alternate, guarded, out);
        }
        return;
    }

    if is_other(node, "binary_expression") {
        if let [left, right] = node.children() {
            if operator_between(node, left, right) == Some("&&") {
                walk(left, guarded, out);
                let mut inner = guarded.clone();
                inner.extend(length_guarded_names(left));
                walk(right, &inner, out);
                return;
            }
        }
    }

    if is_other(node, "ternary_expression") {
        if let [condition, consequent, alternate] = node.children() {
            walk(condition, guarded, out);
            let mut inner = guarded.clone();
            inner.extend(length_guarded_names(condition));
            walk(consequent, &inner, out);
            walk(alternate, guarded, out);
            return;
        }
    }

    if let Some((array_name, span)) = flagged_access(node) {
        if !guarded.contains(array_name) {
            out.push(Finding::new(
                format!(
                    "`{array_name}` may be empty here; guard before reading its last element (`{array_name}[{array_name}.length - 1}}` is `undefined` on an empty array and the property access throws)"
                ),
                span,
            ));
        }
    }

    for child in node.children() {
        walk(child, guarded, out);
    }
}

pub struct UnguardedLastElementAccessRule {
    id: RuleId,
}

impl UnguardedLastElementAccessRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("typescript:unguarded-last-element-access").expect("valid rule id"),
        }
    }
}

impl Default for UnguardedLastElementAccessRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for UnguardedLastElementAccessRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, lang: &LanguageIdentifier) -> bool {
        *lang == LanguageIdentifier::typescript()
    }

    fn default_severity(&self) -> Severity {
        Severity::Major
    }

    fn issue_type(&self) -> IssueType {
        IssueType::Bug
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "A property is read directly off `arr[arr.length - N]` or `arr.at(-N)` with no guard for `arr` being empty; on an empty array this is `undefined`, and the property access throws. Guard with a length check (or use optional chaining) before reading the element.".into(),
            tags: vec!["typescript".into(), "robustness".into(), "null-safety".into()],
            cwe: Some(476),
            produces_hotspots: false,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        if vord_rules_engine::is_test_only_path(file.path()) {
            return Vec::new();
        }
        let mut findings = Vec::new();
        walk(ast, &BTreeSet::new(), &mut findings);
        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vord_rules_engine::AstParser;

    fn check(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.ts", code, LanguageIdentifier::typescript()).unwrap();
        let ast = vord_parser_typescript::TypeScriptParser::new()
            .parse(&file)
            .unwrap();
        UnguardedLastElementAccessRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_unguarded_bracket_access() {
        let findings = check("const last = messages[messages.length - 1].text;\n");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("messages"));
    }

    #[test]
    fn flags_unguarded_at_negative_access() {
        let findings = check("const last = messages.at(-1).text;\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn allows_when_guarded_by_if_length() {
        let findings = check(
            "if (messages.length) {\n  const last = messages[messages.length - 1].text;\n}\n",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn allows_when_guarded_by_logical_and() {
        let findings =
            check("const last = messages.length > 0 && messages[messages.length - 1].text;\n");
        assert!(findings.is_empty());
    }

    #[test]
    fn allows_when_guarded_by_ternary() {
        let findings = check(
            "const last = messages.length ? messages[messages.length - 1].text : undefined;\n",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn allows_optional_chaining_on_the_access_itself() {
        let findings = check("const last = messages.at(-1)?.text;\n");
        assert!(findings.is_empty());
    }

    #[test]
    fn flags_inside_the_else_branch_unguarded() {
        let findings =
            check("if (other) {} else {\n  const last = messages[messages.length - 1].text;\n}\n");
        assert_eq!(findings.len(), 1);
    }
}
