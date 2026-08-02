use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, Rule, RuleId, RuleMetadata, Severity};

/// Grammar node kinds (per tree-sitter grammar) that add a decision point.
const BRANCH_KINDS: &[&str] = &[
    "if_statement",
    "if_expression",
    "elif_clause",
    "while_statement",
    "while_expression",
    "for_statement",
    "for_expression",
    "for_in_statement",
    "loop_expression",
    "match_arm",
    "case_clause",
    "switch_case",
    "expression_case",
    "catch_clause",
    "except_clause",
    "conditional_expression",
    "ternary_expression",
    "boolean_operator",
    "enhanced_for_statement", // Groovy/Java-family for-each
    "switch_label", // Groovy's per-case switch marker
    "repeat_statement", // Lua's `repeat ... until`
    "elseif_statement", // Lua's `elseif` (no wrapping `elif_clause` node)
];

/// Flags functions whose cyclomatic complexity exceeds a threshold.
/// Complexity = 1 + decision points in the function body, excluding nested
/// functions (they are measured on their own).
pub struct ComplexityRule {
    id: RuleId,
    max: u32,
}

impl ComplexityRule {
    pub fn new(max: u32) -> Self {
        Self { id: RuleId::new("smells:high-complexity").expect("valid rule id"), max }
    }
}

impl Default for ComplexityRule {
    fn default() -> Self {
        Self::new(10)
    }
}

fn decision_points(node: &AstNode) -> u32 {
    node.children()
        .iter()
        .map(|child| {
            // Nested functions are rated independently.
            if *child.kind() == NodeKind::FunctionDef {
                return 0;
            }
            let own = match child.kind() {
                NodeKind::Other(kind) if BRANCH_KINDS.contains(&kind.as_ref()) => 1,
                _ => 0,
            };
            own + decision_points(child)
        })
        .sum()
}

impl Rule for ComplexityRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, _language: &LanguageIdentifier) -> bool {
        true
    }

    fn default_severity(&self) -> Severity {
        Severity::Major
    }

    fn remediation_effort_minutes(&self) -> u32 {
        30
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "Functions with high cyclomatic complexity are hard to test and maintain; split them into smaller units.".into(),
            tags: vec!["maintainability".into(), "brain-overload".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter(|n| *n.kind() == NodeKind::FunctionDef)
            .filter_map(|function| {
                let complexity = 1 + decision_points(function);
                (complexity > self.max).then(|| {
                    Finding::new(
                        format!(
                            "function has cyclomatic complexity {complexity} (max {})",
                            self.max
                        ),
                        function.span(),
                    )
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use vord_ast::SourceFile;
    use vord_rules_engine::AstParser;

    use super::*;

    fn check_rust(code: &str, max: u32) -> Vec<Finding> {
        let file = SourceFile::new("t.rs", code, LanguageIdentifier::rust()).unwrap();
        let ast = vord_parser_rust::RustParser::new().parse(&file).unwrap();
        ComplexityRule::new(max).check(&file, &ast)
    }

    #[test]
    fn flags_branchy_function_and_spares_simple_one() {
        let code = "fn busy(x: i32) -> i32 {\n\
            if x > 0 { return 1; }\n\
            if x > 1 { return 2; }\n\
            if x > 2 { return 3; }\n\
            for i in 0..x { if i % 2 == 0 { continue; } }\n\
            while x < 100 { break; }\n\
            0\n}\n\nfn calm() -> i32 { 42 }\n";
        let findings = check_rust(code, 4);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("complexity 7"));
        assert!(check_rust(code, 10).is_empty());
    }

    #[test]
    fn nested_functions_do_not_inflate_the_parent() {
        let code = "fn outer() {\n    let inner = |x: i32| { if x > 0 { () } };\n    inner(1);\n}\n";
        // Only the closure (complexity 2) exceeds max 1 — the outer function
        // is not inflated by its nested function's branches.
        let findings = check_rust(code, 1);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("complexity 2"));
        assert!(check_rust(code, 2).is_empty());
    }
}
