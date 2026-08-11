//! Rule: flags `array[array.length - N]` and suggests the ES2022
//! `array.at(-N)` instead — same value, without repeating the array
//! expression or spelling out the length arithmetic by hand.

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, Rule, RuleId, RuleMetadata, Severity};

use crate::common::is_other;

/// The raw operator token between a binary expression's two operands.
/// tree-sitter's named children drop anonymous tokens (the `-` itself
/// never survives as a child), so it's recovered from the source gap
/// between the operands — same technique `smells:cognitive-complexity`
/// uses to recover `&&`/`||`.
fn binary_operator<'a>(node: &'a AstNode, left: &AstNode, right: &AstNode) -> Option<&'a str> {
    let node_start = node.byte_range().start;
    let gap_start = left.byte_range().end.saturating_sub(node_start);
    let gap_end = right.byte_range().start.saturating_sub(node_start);
    node.text().get(gap_start..gap_end).map(str::trim)
}

fn is_length_access_of(node: &AstNode, base: &str) -> bool {
    if *node.kind() != NodeKind::MemberAccess {
        return false;
    }
    let [object, property] = node.children() else {
        return false;
    };
    *property.kind() == NodeKind::Identifier
        && property.text() == "length"
        && object.text() == base
}

fn flagged_index(el: &AstNode) -> Option<&AstNode> {
    if *el.kind() != NodeKind::MemberAccess {
        return None;
    }
    let [object, index] = el.children() else {
        return None;
    };
    if !is_other(index, "binary_expression") {
        return None;
    }
    let [left, right] = index.children() else {
        return None;
    };
    if binary_operator(index, left, right) != Some("-") {
        return None;
    }
    if !is_length_access_of(left, object.text()) {
        return None;
    }
    is_other(right, "number").then_some(el)
}

pub struct PreferArrayAtRule {
    id: RuleId,
}

impl PreferArrayAtRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("typescript:prefer-array-at").expect("valid rule id"),
        }
    }
}

impl Default for PreferArrayAtRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for PreferArrayAtRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, lang: &LanguageIdentifier) -> bool {
        *lang == LanguageIdentifier::typescript()
    }

    fn default_severity(&self) -> Severity {
        Severity::Minor
    }

    fn remediation_effort_minutes(&self) -> u32 {
        2
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "`array[array.length - N]` repeats the array expression and spells out length arithmetic by hand; `array.at(-N)` (ES2022) expresses the same access directly.".into(),
            tags: vec!["typescript".into(), "clarity".into(), "es2022".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter_map(flagged_index)
            .map(|n| Finding::new("prefer `.at(…)` over `[…length - index]`", n.span()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use vord_ast::SourceFile;
    use vord_rules_engine::AstParser;

    use super::*;

    fn check(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.ts", code, LanguageIdentifier::typescript()).unwrap();
        let ast = vord_parser_typescript::TypeScriptParser::new()
            .parse(&file)
            .unwrap();
        PreferArrayAtRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_last_element_access() {
        assert_eq!(check("const last = items[items.length - 1];\n").len(), 1);
    }

    #[test]
    fn flags_member_expression_base() {
        assert_eq!(
            check("const last = this.items[this.items.length - 2];\n").len(),
            1
        );
    }

    #[test]
    fn allows_plain_index_access() {
        assert!(check("const first = items[0];\n").is_empty());
    }

    #[test]
    fn allows_at_call() {
        assert!(check("const last = items.at(-1);\n").is_empty());
    }

    #[test]
    fn allows_length_check_that_is_not_an_index() {
        assert!(check("const empty = items.length - 1 === 0;\n").is_empty());
    }

    #[test]
    fn allows_mismatched_base_expressions() {
        assert!(check("const x = items[other.length - 1];\n").is_empty());
    }
}
