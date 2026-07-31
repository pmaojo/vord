use yunq_ast::{AstNode, LanguageIdentifier, SourceFile};
use yunq_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

use crate::common::is_other;

/// A "variable variable" (`$$name`, or `${$expr}`) computes which variable
/// to read or write from another variable's value at runtime. That makes
/// the set of variables a piece of code can touch impossible to determine
/// by reading it — every reviewer (human or static analyzer) has to
/// reconstruct what `$name` might contain to know what's actually being
/// read or written, which is exactly the same reasoning gap `extract()` on
/// request data exploits. An associative array almost always expresses the
/// same intent directly.
pub struct VariableVariableRule {
    id: RuleId,
}

impl VariableVariableRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("php:variable-variable").expect("valid rule id"),
        }
    }
}

impl Default for VariableVariableRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for VariableVariableRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, language: &LanguageIdentifier) -> bool {
        *language == LanguageIdentifier::php()
    }

    fn default_severity(&self) -> Severity {
        Severity::Major
    }

    fn issue_type(&self) -> IssueType {
        IssueType::CodeSmell
    }

    fn metadata(&self) -> yunq_rules_engine::RuleMetadata {
        yunq_rules_engine::RuleMetadata {
            description: "A variable variable (`$$name`) makes which variable is read or \
                written depend on another variable's runtime value, so the set of variables \
                this line can touch can't be determined by reading it. Use an associative \
                array instead."
                .into(),
            tags: vec!["maintainability".into(), "php".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter(|n| is_other(n.kind(), "dynamic_variable_name"))
            .map(|n| {
                Finding::new(
                    "variable variable — which variable this touches depends on a runtime \
                    value; use an associative array instead"
                        .to_string(),
                    n.span(),
                )
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use yunq_ast::SourceFile;
    use yunq_rules_engine::AstParser;

    use super::*;

    fn check(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.php", code, LanguageIdentifier::php()).unwrap();
        let ast = yunq_parser_php::PhpParser::new().parse(&file).unwrap();
        VariableVariableRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_variable_variable_assignment() {
        assert_eq!(check("<?php\n$$foo = 1;\n").len(), 1);
    }

    #[test]
    fn ignores_ordinary_variables() {
        assert!(check("<?php\n$foo = 1;\n").is_empty());
    }
}
