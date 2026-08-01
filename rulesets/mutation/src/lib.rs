pub mod arithmetic_operator_mutant;
pub mod boolean_inversion_mutant;
pub mod conditional_boundary_mutant;

pub use arithmetic_operator_mutant::ArithmeticOperatorMutantRule;
pub use boolean_inversion_mutant::BooleanInversionMutantRule;
pub use conditional_boundary_mutant::ConditionalBoundaryMutantRule;

use std::sync::Arc;
use yunq_rules_engine::Rule;

/// Returns all instant AST mutation gap analysis rules in this crate as Arcs.
pub fn rules() -> Vec<Arc<dyn Rule>> {
    vec![
        Arc::new(ConditionalBoundaryMutantRule::new()),
        Arc::new(BooleanInversionMutantRule::new()),
        Arc::new(ArithmeticOperatorMutantRule::new()),
    ]
}

/// Returns all instant AST mutation gap analysis rules in this crate as Boxes.
pub fn all_rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(ConditionalBoundaryMutantRule::new()),
        Box::new(BooleanInversionMutantRule::new()),
        Box::new(ArithmeticOperatorMutantRule::new()),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use yunq_ast::{LanguageIdentifier, SourceFile};
    use yunq_parser_typescript::TypeScriptParser;
    use yunq_rules_engine::AstParser;

    #[test]
    fn test_mutation_rules_detect_boundary_gaps() {
        let parser = TypeScriptParser::new();
        let code = r#"
        function checkAge(age: number): boolean {
            if (age >= 18 && age < 65) {
                let total = age + 10;
                return true;
            }
            return false;
        }
        "#;

        let file = SourceFile::new("src/test.ts", code, LanguageIdentifier::typescript()).unwrap();
        let ast = parser.parse(&file).unwrap();
        let rule_list = rules();

        let mut all_findings = Vec::new();
        for r in &rule_list {
            all_findings.extend(r.check(&file, &ast));
        }

        assert!(!all_findings.is_empty(), "Mutation rules should flag boundary, boolean logic, and arithmetic gaps");
    }
}
