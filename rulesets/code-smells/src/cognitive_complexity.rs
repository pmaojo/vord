use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use yunq_rules_engine::{Finding, Rule, RuleId, RuleMetadata, Severity};

/// Structures whose entry adds `1 + current nesting depth` and increases the
/// nesting depth for their own body — the weighting that makes cognitive
/// complexity punish deeply nested code harder than cyclomatic complexity
/// does.
const NESTING_KINDS: &[&str] = &[
    "if_statement",
    "if_expression",
    "while_statement",
    "while_expression",
    "for_statement",
    "for_expression",
    "for_in_statement",
    "loop_expression",
    "catch_clause",
    "except_clause",
    "conditional_expression",
    "ternary_expression",
    "match_arm",
    "case_clause",
    "switch_case",
    "expression_case",
];

/// Structures that add a flat `+1` without increasing nesting depth —
/// `else`/`elif` continue the same branch rather than nesting into it.
const FLAT_KINDS: &[&str] = &["else_clause", "elif_clause"];

/// Cognitive Complexity (SonarSource's metric): unlike cyclomatic
/// complexity, nested control flow costs more than sequential control flow,
/// which tracks how hard a human finds a function to read.
///
/// This implementation covers the structural nesting weighting, the metric's
/// dominant term. It does not yet implement the boolean-operator-sequence
/// increment (each break in a chain of `&&`/`||` also adds 1 in the full
/// SonarSource formula) — grammar-portable detection of that needs operator
/// text inspection per language and is left for a follow-up.
pub struct CognitiveComplexityRule {
    id: RuleId,
    max: u32,
}

impl CognitiveComplexityRule {
    pub fn new(max: u32) -> Self {
        Self { id: RuleId::new("smells:cognitive-complexity").expect("valid rule id"), max }
    }
}

impl Default for CognitiveComplexityRule {
    fn default() -> Self {
        Self::new(15)
    }
}

const BOOLEAN_OPS: &[&str] = &[
    "binary_expression",
    "boolean_operator",
    "logical_expression",
];

fn score(node: &AstNode, nesting: u32) -> u32 {
    node.children()
        .iter()
        .map(|child| {
            // Nested functions/closures are rated independently.
            if *child.kind() == NodeKind::FunctionDef {
                return 0;
            }
            let is_bool_op = match child.kind() {
                NodeKind::Other(kind) if BOOLEAN_OPS.contains(&kind.as_str()) => {
                    let text = child.text();
                    text.contains("&&") || text.contains("||") || text.contains(" and ") || text.contains(" or ")
                }
                _ => false,
            };
            let bool_cost = if is_bool_op { 1 } else { 0 };

            match child.kind() {
                NodeKind::Other(kind) if FLAT_KINDS.contains(&kind.as_str()) => {
                    1 + bool_cost + score(child, nesting)
                }
                NodeKind::Other(kind) if NESTING_KINDS.contains(&kind.as_str()) => {
                    (1 + nesting) + bool_cost + score(child, nesting + 1)
                }
                _ => bool_cost + score(child, nesting),
            }
        })
        .sum()
}

impl Rule for CognitiveComplexityRule {
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
            description: "Cognitive complexity weights nested control flow more heavily than sequential control flow, tracking how hard a function is for a human to follow.".into(),
            tags: vec!["maintainability".into(), "cognitive-load".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter(|n| *n.kind() == NodeKind::FunctionDef)
            .filter_map(|function| {
                let complexity = score(function, 0);
                (complexity > self.max).then(|| {
                    Finding::new(
                        format!(
                            "function has cognitive complexity {complexity} (max {})",
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
    use yunq_ast::SourceFile;
    use yunq_rules_engine::AstParser;

    use super::*;

    fn check_rust(code: &str, max: u32) -> Vec<Finding> {
        let file = SourceFile::new("t.rs", code, LanguageIdentifier::rust()).unwrap();
        let ast = yunq_parser_rust::RustParser::new().parse(&file).unwrap();
        CognitiveComplexityRule::new(max).check(&file, &ast)
    }

    fn check_python(code: &str, max: u32) -> Vec<Finding> {
        let file = SourceFile::new("t.py", code, LanguageIdentifier::python()).unwrap();
        let ast = yunq_parser_python::PythonParser::new().parse(&file).unwrap();
        CognitiveComplexityRule::new(max).check(&file, &ast)
    }

    #[test]
    fn nesting_costs_more_than_sequential_branches() {
        // Three sequential (non-nested) ifs: 1+1+1 = 3.
        let sequential = "fn seq(x: i32) -> i32 {\n\
            if x > 0 { return 1; }\n\
            if x > 1 { return 2; }\n\
            if x > 2 { return 3; }\n\
            0\n}\n";
        // Three nested ifs: (1+0) + (1+1) + (1+2) = 6.
        let nested = "fn nested(x: i32) -> i32 {\n\
            if x > 0 {\n\
                if x > 1 {\n\
                    if x > 2 {\n\
                        return 3;\n\
                    }\n\
                }\n\
            }\n\
            0\n}\n";

        assert!(check_rust(sequential, 5).is_empty());
        let findings = check_rust(nested, 5);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("complexity 6"));

        // Same number of `if`s, but nesting makes the difference visible.
        assert!(check_rust(sequential, 2).len() == 1); // 3 > 2
        assert!(check_rust(nested, 2).len() == 1); // 6 > 2, but for a different reason
    }

    #[test]
    fn elif_and_else_add_flat_cost_without_extra_nesting() {
        // Written on one line (no backslash line-continuation): Python needs
        // real indentation in the string content, which continuation strips.
        let code = "def branch(x):\n    if x > 0:\n        return 1\n    elif x > 1:\n        return 2\n    else:\n        return 3\n";
        // if (1+0) + elif (flat +1) + else (flat +1) = 3.
        let findings = check_python(code, 2);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("complexity 3"));
        assert!(check_python(code, 3).is_empty());
    }

    #[test]
    fn nested_functions_are_scored_independently() {
        let code = "fn outer() {\n    let inner = |x: i32| { if x > 0 { if x > 1 { () } } };\n    inner(1);\n}\n";
        // outer: 0 (its only structure is the nested closure, skipped).
        // inner: (1+0) + (1+1) = 3.
        assert!(check_rust(code, 3).is_empty());
        let findings = check_rust(code, 2);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("complexity 3"));
    }
}
