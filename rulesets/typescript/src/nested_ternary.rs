//! Rule: flags a ternary expression (`a ? b : c`) whose `true` or `false`
//! branch is itself another ternary. Nesting conditional expressions forces
//! a reader to parse a decision tree inline instead of following a flat
//! sequence of statements — extracting the inner ternary into its own
//! statement (an `if`/`else`, or a separate variable) reads far more
//! directly.

use vord_ast::{AstNode, LanguageIdentifier, SourceFile};
use vord_rules_engine::{Finding, Rule, RuleId, RuleMetadata, Severity};

use crate::common::is_other;

/// Follows a chain of `parenthesized_expression` wrappers down to the
/// underlying expression — `a ? (b ? c : d) : e` nests just as much as the
/// unparenthesized form.
fn unwrap_parens(node: &AstNode) -> &AstNode {
    let mut current = node;
    while is_other(current, "parenthesized_expression") {
        match current.children() {
            [inner] => current = inner,
            _ => break,
        }
    }
    current
}

fn nested_ternary(node: &AstNode) -> Option<&AstNode> {
    if !is_other(node, "ternary_expression") {
        return None;
    }
    let [_condition, consequent, alternate] = node.children() else {
        return None;
    };
    for branch in [consequent, alternate] {
        let branch = unwrap_parens(branch);
        if is_other(branch, "ternary_expression") {
            return Some(branch);
        }
    }
    None
}

pub struct NestedTernaryRule {
    id: RuleId,
}

impl NestedTernaryRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("typescript:nested-ternary").expect("valid rule id"),
        }
    }
}

impl Default for NestedTernaryRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for NestedTernaryRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, lang: &LanguageIdentifier) -> bool {
        *lang == LanguageIdentifier::typescript()
    }

    fn default_severity(&self) -> Severity {
        Severity::Major
    }

    fn remediation_effort_minutes(&self) -> u32 {
        10
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "A ternary nested inside another ternary's branch forces a reader to parse a decision tree inline; extract it into an independent statement instead.".into(),
            tags: vec!["typescript".into(), "readability".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter_map(nested_ternary)
            .map(|n| {
                Finding::new(
                    "extract this nested ternary operation into an independent statement",
                    n.span(),
                )
            })
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
        NestedTernaryRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_ternary_nested_in_the_true_branch() {
        assert_eq!(check("const x = a ? (b ? c : d) : e;\n").len(), 1);
    }

    #[test]
    fn flags_ternary_nested_in_the_false_branch() {
        assert_eq!(check("const x = a ? b : c ? d : e;\n").len(), 1);
    }

    #[test]
    fn allows_a_flat_ternary() {
        assert!(check("const x = a ? b : c;\n").is_empty());
    }

    #[test]
    fn allows_a_ternary_in_the_condition_position() {
        // The condition itself isn't a branch outcome, so nesting there
        // isn't the "hidden decision tree" this rule targets.
        assert!(check("const x = (a ? b : c) ? d : e;\n").is_empty());
    }
}
