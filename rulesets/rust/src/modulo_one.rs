use vord_ast::{AstNode, LanguageIdentifier, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

use crate::common::{is_other, operator_between};

/// `x % 1` is always `0` for every integer `x`, regardless of its value or
/// signedness — almost always a leftover from editing a different modulus
/// (`% 10`, `% n`, ...) or a copy-paste mistake, not a real check.
pub struct ModuloOneRule {
    id: RuleId,
}

impl ModuloOneRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("rust:modulo-one").expect("valid rule id"),
        }
    }
}

impl Default for ModuloOneRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for ModuloOneRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, language: &LanguageIdentifier) -> bool {
        *language == LanguageIdentifier::rust()
    }

    fn default_severity(&self) -> Severity {
        Severity::Major
    }

    fn issue_type(&self) -> IssueType {
        IssueType::Bug
    }

    fn remediation_effort_minutes(&self) -> u32 {
        5
    }

    fn metadata(&self) -> vord_rules_engine::RuleMetadata {
        vord_rules_engine::RuleMetadata {
            description: "`x % 1` always evaluates to `0` for any integer `x` — this is almost \
                certainly a typo for a different modulus."
                .into(),
            tags: vec!["bug".into(), "rust".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        let test_ranges = vord_rules_engine::rust_test_module_ranges(file.content());

        ast.descendants()
            .filter(|n| is_other(n.kind(), "binary_expression") && n.children().len() == 2)
            .filter(|n| {
                let right = &n.children()[1];
                is_other(right.kind(), "integer_literal")
                    && right.text() == "1"
                    && operator_between(file.content(), &n.children()[0], right) == "%"
            })
            .filter(|n| !vord_rules_engine::in_ranges(&test_ranges, n.span().start_line))
            .map(|n| {
                Finding::new(
                    "`% 1` always evaluates to 0; this looks like a typo".to_string(),
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
        let file = SourceFile::new("t.rs", code, LanguageIdentifier::rust()).unwrap();
        let ast = vord_parser_rust::RustParser::new().parse(&file).unwrap();
        ModuloOneRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_modulo_one() {
        let findings = check("fn f(x: i32) -> i32 { x % 1 }\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_modulo_one_in_condition() {
        let findings = check("fn f(x: u32) { if x % 1 == 0 { } }\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn ignores_modulo_ten() {
        assert!(check("fn f(x: i32) -> i32 { x % 10 }\n").is_empty());
    }

    #[test]
    fn ignores_modulo_variable() {
        assert!(check("fn f(x: i32, n: i32) -> i32 { x % n }\n").is_empty());
    }

    #[test]
    fn ignores_division_by_one() {
        assert!(check("fn f(x: i32) -> i32 { x / 1 }\n").is_empty());
    }

    #[test]
    fn ignores_modulo_one_inside_a_cfg_test_module() {
        let code = "fn prod() {}\n\n#[cfg(test)]\nmod tests {\n    fn t(x: i32) -> i32 {\n        x % 1\n    }\n}\n";
        assert!(check(code).is_empty());
    }
}
