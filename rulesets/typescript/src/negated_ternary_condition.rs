//! Rule: flags a ternary whose condition is a negation (`!cond ? a : b`).
//! Swapping the branches and dropping the `!` (`cond ? b : a`) reads the
//! same but without asking the reader to hold a negation in mind while
//! matching branches to outcomes.

use vord_ast::{AstNode, LanguageIdentifier, SourceFile};
use vord_rules_engine::{Finding, Rule, RuleId, RuleMetadata, Severity};

use crate::common::is_other;

fn flagged_ternary(node: &AstNode) -> Option<&AstNode> {
    if !is_other(node, "ternary_expression") {
        return None;
    }
    let [condition, _, _] = node.children() else {
        return None;
    };
    if !is_other(condition, "unary_expression") {
        return None;
    }
    condition.text().starts_with('!').then_some(node)
}

pub struct NegatedTernaryConditionRule {
    id: RuleId,
}

impl NegatedTernaryConditionRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("typescript:negated-ternary-condition").expect("valid rule id"),
        }
    }
}

impl Default for NegatedTernaryConditionRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for NegatedTernaryConditionRule {
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
            description: "A ternary with a negated condition (`!cond ? a : b`) reads harder than the equivalent with branches swapped (`cond ? b : a`).".into(),
            tags: vec!["typescript".into(), "clarity".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter_map(flagged_ternary)
            .map(|n| {
                Finding::new(
                    "unexpected negated condition in ternary; swap the branches and drop the `!` instead",
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
        NegatedTernaryConditionRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_negated_condition() {
        assert_eq!(check("const x = !cond ? a : b;\n").len(), 1);
    }

    #[test]
    fn allows_positive_condition() {
        assert!(check("const x = cond ? a : b;\n").is_empty());
    }

    #[test]
    fn allows_negated_operand_not_at_condition() {
        assert!(check("const x = cond ? !a : b;\n").is_empty());
    }
}
