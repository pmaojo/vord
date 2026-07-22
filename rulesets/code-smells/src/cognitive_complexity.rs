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
/// Covers both dominant terms of the SonarSource formula: structural nesting
/// weighting, and the boolean-operator-sequence increment (a chain of
/// binary logical operators costs +1 per contiguous run of the same
/// operator, plus +1 each time the operator changes — `a && b && c` costs 1,
/// `a && b || c` costs 2).
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

/// Node kinds across the wired tree-sitter grammars that represent a
/// two-operand binary expression. Most of these fire far more often for
/// arithmetic/comparison operators than for `&&`/`||` — [`logical_op`]
/// filters those out by inspecting the actual operator token, so listing
/// the kind here is just "candidate", not "confirmed logical".
const BOOLEAN_OPS: &[&str] = &[
    "binary_expression",
    "boolean_operator",
    "logical_expression",
];

#[derive(Clone, Copy, PartialEq, Eq)]
enum LogicalOp {
    And,
    Or,
}

/// tree-sitter's `named_children` (used by every parser adapter) drops
/// anonymous tokens, so the `&&`/`||`/`and`/`or` keyword never survives as a
/// child node — only the two operands do. Recover it from the raw source
/// gap between them instead. Returns `None` for non-logical binary
/// expressions (`+`, `==`, ...) and anything that isn't a plain two-operand
/// node.
fn logical_op(node: &AstNode) -> Option<LogicalOp> {
    match node.kind() {
        NodeKind::Other(kind) if BOOLEAN_OPS.contains(&kind.as_str()) => {}
        _ => return None,
    }
    let [left, right] = node.children() else { return None };
    let node_start = node.byte_range().start;
    let gap_start = left.byte_range().end.saturating_sub(node_start);
    let gap_end = right.byte_range().start.saturating_sub(node_start);
    let text = node.text();
    let between = text.get(gap_start..gap_end)?.trim();
    match between {
        "&&" | "and" => Some(LogicalOp::And),
        "||" | "or" => Some(LogicalOp::Or),
        _ => None,
    }
}

/// Flattens a chain of same-family logical nodes (`a && b && c` nests as
/// `(a && b) && c`) into the ordered sequence of operators a reader would
/// scan left to right, so a homogeneous run can be told apart from a break.
fn logical_sequence(node: &AstNode) -> Vec<LogicalOp> {
    let Some(op) = logical_op(node) else { return Vec::new() };
    let [left, right] = node.children() else { return Vec::new() };
    let mut sequence = logical_sequence(left);
    sequence.push(op);
    sequence.extend(logical_sequence(right));
    sequence
}

/// SonarSource's boolean-sequence rule: +1 for the first operator, +1 again
/// each time it changes — repeats of the same operator in a row are free.
fn logical_chain_cost(sequence: &[LogicalOp]) -> u32 {
    let mut cost = 0;
    let mut previous = None;
    for &op in sequence {
        if previous != Some(op) {
            cost += 1;
        }
        previous = Some(op);
    }
    cost
}

/// The non-logical operands at the fringes of a logical chain — each may
/// itself hide independent structure (a nested `if`, another unrelated
/// boolean chain inside a call argument, ...) that still needs scoring.
fn logical_leaves<'a>(node: &'a AstNode, out: &mut Vec<&'a AstNode>) {
    match node.children() {
        [left, right] if logical_op(node).is_some() => {
            logical_leaves(left, out);
            logical_leaves(right, out);
        }
        _ => out.push(node),
    }
}

fn score(node: &AstNode, nesting: u32) -> u32 {
    node.children()
        .iter()
        .map(|child| {
            // Nested functions/closures are rated independently.
            if *child.kind() == NodeKind::FunctionDef {
                return 0;
            }
            if logical_op(child).is_some() {
                let sequence = logical_sequence(child);
                let bool_cost = logical_chain_cost(&sequence);
                let mut leaves = Vec::new();
                logical_leaves(child, &mut leaves);
                return bool_cost + leaves.iter().map(|leaf| score(leaf, nesting)).sum::<u32>();
            }

            match child.kind() {
                NodeKind::Other(kind) if FLAT_KINDS.contains(&kind.as_str()) => 1 + score(child, nesting),
                NodeKind::Other(kind) if NESTING_KINDS.contains(&kind.as_str()) => {
                    (1 + nesting) + score(child, nesting + 1)
                }
                _ => score(child, nesting),
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
    fn homogeneous_boolean_chain_costs_once() {
        // `a && b && c` is one contiguous run of the same operator: +1 total,
        // not +1 per `&&` (SonarSource doesn't penalize repeating the same
        // logical operator in a row).
        let code = "fn f(a: bool, b: bool, c: bool) -> bool {\n    a && b && c\n}\n";
        let findings = check_rust(code, 0);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("complexity 1"), "{}", findings[0].message);
        assert!(check_rust(code, 1).is_empty());
    }

    #[test]
    fn boolean_operator_switch_costs_again() {
        // `a && b || c`: +1 for the first operator, +1 more for the switch
        // to `||` — two breaks in the sequence, two increments.
        let code = "fn f(a: bool, b: bool, c: bool) -> bool {\n    a && b || c\n}\n";
        let findings = check_rust(code, 1);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("complexity 2"), "{}", findings[0].message);
        assert!(check_rust(code, 2).is_empty());
    }

    #[test]
    fn boolean_chain_with_two_switches() {
        // `a || b || c && d` parses as `(a || b) || (c && d)`: sequence
        // [||, ||, &&] — first `||` costs 1, the repeat costs 0, the switch
        // to `&&` costs 1 again. Total 2, matching the single-switch case
        // above despite having one more operator.
        let code = "fn f(a: bool, b: bool, c: bool, d: bool) -> bool {\n    a || b || c && d\n}\n";
        let findings = check_rust(code, 1);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("complexity 2"), "{}", findings[0].message);
    }

    #[test]
    fn boolean_operand_nesting_is_still_scored_but_not_inflated_by_the_operator() {
        // The `&&` itself doesn't add nesting depth for its operands — an
        // `if` sitting inside one operand is scored at the *outer* nesting
        // level, not one level deeper because it's behind a `&&`.
        let code = "fn f(a: bool, b: i32) -> bool {\n    a && (if b > 0 { true } else { false })\n}\n";
        // bool chain (1) + nested if at nesting 0 (1+0) + its else (flat +1) = 3.
        let findings = check_rust(code, 2);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("complexity 3"), "{}", findings[0].message);
    }

    #[test]
    fn python_boolean_operator_uses_and_or_keywords() {
        // Python's `and`/`or` are the same construct as `&&`/`||` elsewhere;
        // the operator recovery must handle keyword operators, not just
        // symbolic ones.
        let code = "def f(a, b, c):\n    return a and b or c\n";
        let findings = check_python(code, 1);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("complexity 2"), "{}", findings[0].message);
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
