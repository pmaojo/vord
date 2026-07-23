use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use yunq_rules_engine::{Finding, Rule, RuleId, RuleMetadata, Severity};

/// `if`/`else if` chain roots. Handled separately from [`NESTING_KINDS`]
/// (via [`score_if_chain`]) because SonarSource charges every link after
/// the first a flat `+1` instead of the nesting-weighted cost an ordinary
/// nested structure pays — see [`chained_if`].
const IF_KINDS: &[&str] = &["if_statement", "if_expression"];

/// Structures whose entry adds `1 + current nesting depth` and increases the
/// nesting depth for their own body — the weighting that makes cognitive
/// complexity punish deeply nested code harder than cyclomatic complexity
/// does. The switch/match statement itself is the sole cost source here;
/// its cases/arms are plain pass-through wrappers around already-nested
/// content, matching SonarSource (a 20-case switch costs the same as a
/// 2-case one).
const NESTING_KINDS: &[&str] = &[
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
    "switch_statement",
    "expression_switch_statement",
    "type_switch_statement",
    "match_expression",
    "match_statement",
    "enhanced_for_statement", // Groovy/Java-family for-each
    "switch_expression", // Groovy's unified switch statement/expression form
    "repeat_statement", // Lua's `repeat ... until`
];

/// Structures that add a flat `+1` without increasing nesting depth —
/// `else`/`elif` continue the same branch rather than nesting into it.
const FLAT_KINDS: &[&str] = &[
    "else_clause",
    "elif_clause",
    "elseif_statement", // Lua
    "else_statement", // Lua (no wrapping `else_clause` node)
];

/// `break`/`continue` node kinds across the wired grammars. A plain
/// `break`/`continue` is free (it doesn't add a new way to misread the
/// function); only a jump to an explicit label costs — see
/// [`is_labeled_jump`].
const JUMP_KINDS: &[&str] = &["break_expression", "continue_expression", "break_statement", "continue_statement"];

/// Node kinds a labeled `break`/`continue` uses for the label/lifetime
/// child: Rust wraps it in a `label` node, C-like grammars (JS/TS/Java/Go)
/// expose it directly as a `statement_identifier`.
const LABEL_KINDS: &[&str] = &["label", "statement_identifier"];

/// True when `node` is a `break`/`continue` that names an explicit label —
/// SonarSource charges this a flat +1 (no nesting weighting: jumping to an
/// enclosing label doesn't itself nest anything new).
fn is_labeled_jump(node: &AstNode) -> bool {
    matches!(node.kind(), NodeKind::Other(kind) if JUMP_KINDS.contains(&kind.as_str()))
        && node
            .children()
            .iter()
            .any(|c| matches!(c.kind(), NodeKind::Other(kind) if LABEL_KINDS.contains(&kind.as_str())))
}

/// Cognitive Complexity (SonarSource's metric): unlike cyclomatic
/// complexity, nested control flow costs more than sequential control flow,
/// which tracks how hard a human finds a function to read.
///
/// Covers both dominant terms of the SonarSource formula — structural
/// nesting weighting, and the boolean-operator-sequence increment (a chain
/// of binary logical operators costs +1 per contiguous run of the same
/// operator, plus +1 each time the operator changes — `a && b && c` costs 1,
/// `a && b || c` costs 2) — plus the flat +1 for direct self-recursion
/// (indirect/mutual recursion across functions is out of scope: it needs a
/// whole-file call graph this rule doesn't build).
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
    "binary_operator", // Elixir: every binary op (`&&`/`||`/`and`/`or`/+/==/...) shares this one kind
];

#[derive(Clone, Copy, PartialEq, Eq)]
enum LogicalOp {
    And,
    Or,
}

/// Follows a chain of `parenthesized_expression` wrappers down to the
/// underlying expression. SonarSource's boolean-sequence rule treats
/// parentheses as fully transparent — `a && (b || c)` is one continuous
/// sequence, not a nested chain with its own separate +1 — so anything
/// inspecting an operand's shape needs to see through them first.
fn unwrap_parens(node: &AstNode) -> &AstNode {
    let mut current = node;
    while matches!(current.kind(), NodeKind::Other(kind) if kind == "parenthesized_expression") {
        match current.children() {
            [inner] => current = inner,
            _ => break,
        }
    }
    current
}

/// tree-sitter's `named_children` (used by every parser adapter) drops
/// anonymous tokens, so the `&&`/`||`/`and`/`or` keyword never survives as a
/// child node — only the two operands do. Recover it from the raw source
/// gap between them instead. Returns `None` for non-logical binary
/// expressions (`+`, `==`, ...) and anything that isn't a plain two-operand
/// node.
fn logical_op(node: &AstNode) -> Option<LogicalOp> {
    let node = unwrap_parens(node);
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
    let [left, right] = unwrap_parens(node).children() else { return Vec::new() };
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
    match unwrap_parens(node).children() {
        [left, right] if logical_op(node).is_some() => {
            logical_leaves(left, out);
            logical_leaves(right, out);
        }
        _ => out.push(node),
    }
}

/// The declared name of a `FunctionDef`, if it has one — the first
/// `Identifier` among its direct children (parser adapters place a
/// function's own name there; parameters/generics/body are never bare
/// `Identifier` nodes at that level). Closures/lambdas have no such child,
/// so they're never treated as recursive by name — correct, since an
/// anonymous function can't call itself by its own name.
fn function_name(function: &AstNode) -> Option<&str> {
    function
        .children()
        .iter()
        .find(|c| *c.kind() == NodeKind::Identifier)
        .map(|c| c.text())
}

/// Whether `call`'s callee refers to `fn_name` — a plain `foo()` call, or a
/// method-style `self.foo()`/`this.foo()` call ending in that name. This is
/// a same-file, name-based heuristic (matching [`crate::cognitive_complexity`]'s
/// only source of a call graph): it can't tell a genuine recursive call from
/// an unrelated function that happens to share a name, which is why it's
/// scoped to *direct* recursion only — no cross-function call graph, no
/// indirect/mutual recursion.
fn is_recursive_call(call: &AstNode, fn_name: &str) -> bool {
    let Some(callee) = call.first_child() else { return false };
    match callee.kind() {
        NodeKind::Identifier => callee.text() == fn_name,
        NodeKind::MemberAccess => callee
            .children()
            .iter()
            .rev()
            .find(|c| *c.kind() == NodeKind::Identifier)
            .is_some_and(|c| c.text() == fn_name),
        _ => false,
    }
}

/// Shared prefix for every dispatcher below: nested function defs are rated
/// independently (contribute 0 here), labeled `break`/`continue` are a flat
/// +1, boolean-operator chains follow their own flat, non-nesting-weighted
/// rule, and a direct self-recursive call is a flat +1 (recursion is a
/// "meta-loop" in SonarSource's model, so it's charged like a jump, not
/// nesting-weighted like a real loop). Returns `None` for anything else, so
/// the caller applies its own nesting-aware fallback.
fn score_common(child: &AstNode, nesting: u32, fn_name: Option<&str>) -> Option<u32> {
    if *child.kind() == NodeKind::FunctionDef {
        return Some(0);
    }
    if is_labeled_jump(child) {
        return Some(1 + score(child, nesting, fn_name));
    }
    if *child.kind() == NodeKind::Call && fn_name.is_some_and(|name| is_recursive_call(child, name)) {
        return Some(1 + score(child, nesting, fn_name));
    }
    if logical_op(child).is_some() {
        let sequence = logical_sequence(child);
        let bool_cost = logical_chain_cost(&sequence);
        let mut leaves = Vec::new();
        logical_leaves(child, &mut leaves);
        return Some(bool_cost + leaves.iter().map(|leaf| score(leaf, nesting, fn_name)).sum::<u32>());
    }
    None
}

fn score(node: &AstNode, nesting: u32, fn_name: Option<&str>) -> u32 {
    node.children().iter().map(|child| score_child(child, nesting, fn_name)).sum()
}

fn score_child(child: &AstNode, nesting: u32, fn_name: Option<&str>) -> u32 {
    if let Some(cost) = score_common(child, nesting, fn_name) {
        return cost;
    }
    match child.kind() {
        NodeKind::Other(kind) if FLAT_KINDS.contains(&kind.as_str()) => 1 + score_branch_body(child, nesting, fn_name),
        NodeKind::Other(kind) if IF_KINDS.contains(&kind.as_str()) => score_if_chain(child, nesting, false, fn_name),
        NodeKind::Other(kind) if NESTING_KINDS.contains(&kind.as_str()) => {
            (1 + nesting) + score(child, nesting + 1, fn_name)
        }
        _ => score(child, nesting, fn_name),
    }
}

/// Scores an `else`/`elif` clause's contents. If the clause wraps nothing
/// but a nested `if` (`else if ...`, [`chained_if`]), that's a chain
/// continuation, not fresh nesting: delegate to [`score_if_chain`] with
/// `is_link: true` so it's charged the flat +1 already added by the
/// caller instead of paying `1 + nesting` again.
fn score_branch_body(clause: &AstNode, nesting: u32, fn_name: Option<&str>) -> u32 {
    match chained_if(clause) {
        Some(inner_if) => score_if_chain(inner_if, nesting, true, fn_name),
        None => score(clause, nesting + 1, fn_name),
    }
}

/// Scores one `if`/`else if`/`else` chain rooted at `if_node`, anchored at
/// nesting level `nesting`. SonarSource charges only the first link
/// `1 + nesting`; every later link in the same chain (`is_link: true`) is a
/// flat +1 with no extra nesting, and the chain's own nesting level does not
/// compound per link — only the *body* of each link (its `then` branch, or
/// a terminal plain `else` block) sits one level deeper, at `nesting + 1`.
fn score_if_chain(if_node: &AstNode, nesting: u32, is_link: bool, fn_name: Option<&str>) -> u32 {
    let header = if is_link { 0 } else { 1 + nesting };
    header + if_node.children().iter().map(|child| score_if_member(child, nesting, fn_name)).sum::<u32>()
}

/// Scores one direct child of an `if`/`else if` node (its condition or
/// `then` branch) at `nesting + 1`, except a further `else`/`elif` clause,
/// which [`score_branch_body`] anchors back at `nesting` to keep the chain
/// from compounding.
fn score_if_member(child: &AstNode, nesting: u32, fn_name: Option<&str>) -> u32 {
    if let Some(cost) = score_common(child, nesting, fn_name) {
        return cost;
    }
    match child.kind() {
        NodeKind::Other(kind) if FLAT_KINDS.contains(&kind.as_str()) => 1 + score_branch_body(child, nesting, fn_name),
        _ => score(child, nesting + 1, fn_name),
    }
}

/// If `clause` wraps nothing but a nested `if` (`else if ...`), returns
/// that inner if-node — the shape most curly-brace grammars (Rust, C-like,
/// JS/TS) use to represent an else-if chain link, as opposed to a terminal
/// `else { ... }` block. Languages with a native flat elif node (Python's
/// `elif_clause`) never match here, since their elif's children are its own
/// condition/body, not a nested if-kind node — which is correct, since
/// those chain links are already flat siblings of the outer `if`, not
/// nested one inside another.
fn chained_if(clause: &AstNode) -> Option<&AstNode> {
    match clause.children() {
        [only] if is_if_kind(only.kind()) => Some(only),
        _ => None,
    }
}

fn is_if_kind(kind: &NodeKind) -> bool {
    matches!(kind, NodeKind::Other(k) if IF_KINDS.contains(&k.as_str()))
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
                let complexity = score(function, 0, function_name(function));
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
    fn direct_recursion_is_a_flat_increment_not_nesting_weighted() {
        // SonarSource's own whitepaper worked example (`Sum`): the `if`
        // costs `1+0`, and the recursive call costs a flat `+1` — recursion
        // is charged like a jump, not weighted by how deep the call site
        // sits.
        let code = "fn sum(n: i32) -> i32 {\n    if n <= 1 {\n        return n;\n    }\n    n + sum(n - 1)\n}\n";
        let findings = check_rust(code, 1);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("complexity 2"), "{}", findings[0].message);
        assert!(check_rust(code, 2).is_empty());
    }

    #[test]
    fn recursion_via_self_method_call_is_detected() {
        // Method-style recursion (`self.fact(...)`) is still a direct
        // self-call — the callee is a `MemberAccess` ending in the
        // function's own name, not a bare `Identifier`.
        let code = "impl S {\n    fn fact(&self, n: i32) -> i32 {\n        if n <= 1 {\n            1\n        } else {\n            n * self.fact(n - 1)\n        }\n    }\n}\n";
        // if (1+0) + else (flat +1) + recursive call (flat +1) = 3.
        let findings = check_rust(code, 2);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("complexity 3"), "{}", findings[0].message);
        assert!(check_rust(code, 3).is_empty());
    }

    #[test]
    fn calling_a_different_function_by_name_is_not_recursion() {
        let code = "fn f(n: i32) -> i32 {\n    g(n)\n}\n";
        assert!(check_rust(code, 0).is_empty());
    }

    #[test]
    fn python_direct_recursion_is_a_flat_increment() {
        let code = "def fact(n):\n    if n <= 1:\n        return 1\n    return n * fact(n - 1)\n";
        let findings = check_python(code, 1);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("complexity 2"), "{}", findings[0].message);
        assert!(check_python(code, 2).is_empty());
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

    #[test]
    fn else_if_chain_is_flat_and_does_not_compound_nesting() {
        // Direct translation of SonarSource's own test fixture
        // (sonar-java's CognitiveComplexityMethodCheckMax0.java,
        // `noNestingForIfElseIf`), which documents an expected total of 21:
        // the `else if`/`else` links in the chain cost flat +1 each and
        // don't get progressively deeper just for being further down the
        // chain — only the terminal `else`'s nested `if` sits one level
        // deeper than the chain itself.
        let code = "fn f(cond: bool) {\n    loop {\n        if cond {\n            loop {\n                if cond {\n                } else if cond {\n                } else {\n                    if cond {\n                    }\n                }\n                if cond {}\n            }\n        }\n    }\n}\n";
        let findings = check_rust(code, 20);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("complexity 21"), "{}", findings[0].message);
    }

    #[test]
    fn switch_arms_share_the_switch_statements_single_cost() {
        // SonarSource costs a switch/match statement `1 + nesting` once,
        // regardless of how many cases/arms it has (sonar-java's own
        // `toProtocolType` fixture: a 4-branch switch costs exactly 1).
        let code = "fn f(x: i32) -> i32 {\n    match x {\n        0 => 1,\n        1 => 2,\n        2 => 3,\n        _ => 4,\n    }\n}\n";
        assert!(check_rust(code, 1).is_empty());
        let findings = check_rust(code, 0);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("complexity 1"), "{}", findings[0].message);
    }

    /// Regression suite ported from SonarSource's own sonar-java test
    /// fixtures (`CognitiveComplexity.java`,
    /// `CognitiveComplexityMethodCheckMax0.java`), rewritten in Rust/Python
    /// and pinned to the exact complexity values those fixtures document.
    /// Kept as one table (rather than one `#[test]` per case) so a fixture
    /// name shows up directly in the failure message.
    #[test]
    fn matches_sonarqube_reference_fixtures() {
        let rust_cases: &[(&str, &str, u32)] = &[
            ("extra_conditions", "fn f(a: bool, b: bool, c: bool) -> bool {\n    a && b || foo(b && c)\n}\n", 3),
            ("extra_conditions2", "fn f(a: bool, b: bool, c: bool, d: bool) -> bool {\n    a && (b || c) || d\n}\n", 2),
            ("extra_conditions3", "fn f(a: bool, b: bool, c: bool, d: bool) {\n    if a && b || c || d {}\n}\n", 3),
            ("extra_conditions4", "fn f(a: bool, b: bool, c: bool, d: bool, e: bool) {\n    if a && b || c && d || e {}\n}\n", 5),
            ("extra_conditions5", "fn f(a: bool, b: bool, c: bool, d: bool, e: bool) {\n    if a || b && c || d && e {}\n}\n", 5),
            ("extra_conditions6", "fn f(a: bool, b: bool, c: bool, d: bool, e: bool) {\n    if a && b && c || d || e {}\n}\n", 3),
            ("extra_conditions7", "fn f(a: bool) {\n    if a {}\n}\n", 1),
            ("extra_conditions8", "fn f(a: bool, b: bool, c: bool, d: bool, e: bool) {\n    if a && b && c && d && e {}\n}\n", 2),
            ("extra_conditions9", "fn f(a: bool, b: bool, c: bool, d: bool, e: bool) {\n    if a || b || c || d || e {}\n}\n", 2),
            ("extra_condition10", "fn f(a: bool, b: bool, c: bool, d: bool, e: bool, f: bool) {\n    if a && b && c || d || e && f {}\n}\n", 4),
            ("extra_condition11", "fn f(a: bool, b: bool, c: bool) {\n    if a || (b || c) {}\n}\n", 2),
            ("extra_conditions12", "fn f(a: bool, b: bool, c: bool, d: bool, e: bool, f: bool, g: bool, h: bool, i: bool, j: bool, k: bool, l: bool, m: bool) {\n    if a && b && c || d || e && f && g || (h || (i && j || k)) || l || m {}\n}\n", 7),
            ("switch2", "fn f(foo: i32, lhs_is_identifier: bool, a: bool, b: bool, c: bool, d: bool, element_is_assignment: bool) {\n    match foo {\n        1 => {}\n        2 => {\n            if lhs_is_identifier {\n                if a && b && c || d {}\n                if element_is_assignment {\n                } else {\n                }\n            }\n        }\n        _ => {}\n    }\n}\n", 12),
            ("break_with_label", "fn f(objects: &[bool]) {\n    'outer: for o in objects {\n        break 'outer;\n    }\n}\n", 2),
            ("to_method", "fn f(args: &[String], chain: &[i32], foo: bool) {\n    for ctr in 0..args.len() {\n        if args[ctr] == \"-debug\" {\n        }\n    }\n    for i in (0..chain.len()).rev() {\n    }\n    if foo {\n        for i in 0..10 {\n        }\n    }\n}\n", 7),
            ("get_value_to_eval", "fn f(alert_level: i32, foo: i32) -> i32 {\n    if alert_level == 1 && foo == 2 {\n        1\n    } else if alert_level == 3 {\n        2\n    } else {\n        while true {\n        }\n        3\n    }\n}\n", 6),
            ("get_weight", "fn f(i: i32) -> i32 {\n    if i <= 0 {\n        return 1;\n    }\n    if i < 10 {\n        return 2;\n    }\n    if i < 20 {\n        return 3;\n    }\n    if i < 30 {\n        return 4;\n    }\n    5\n}\n", 4),
            ("sum_of_non_primes", "fn f(limit: i32) -> i32 {\n    let mut sum = 0;\n    'outer: for i in 0..limit {\n        if i <= 2 {\n            continue;\n        }\n        for j in 2..1 {\n            if i % j == 0 {\n                continue 'outer;\n            }\n        }\n        sum += i;\n    }\n    sum\n}\n", 9),
        ];
        let python_cases: &[(&str, &str, u32)] = &[
            ("do_filter", "def f(consumed, redirected, not_set, has_other, is_wrapper, external, is_set, chain):\n    if consumed:\n        return\n    try:\n        pass\n    except HaltException:\n        pass\n    except Exception:\n        pass\n    if not_set and redirected:\n        pass\n    if not_set and has_other:\n        if is_wrapper:\n            pass\n    if not_set and not external:\n        pass\n    if is_set:\n        pass\n    elif chain is not None:\n        pass\n", 13),
            ("bulk_activate", "def f(rules, changes, condition):\n    try:\n        while rules.has_next():\n            try:\n                if not changes.is_empty():\n                    pass\n            except BadRequestException:\n                pass\n    finally:\n        if condition:\n            pass\n    return 0\n", 6),
        ];

        let mut mismatches = Vec::new();
        for (name, code, expected) in rust_cases {
            let actual = complexity_rust(code);
            if actual != *expected {
                mismatches.push(format!("{name}: got {actual}, expected {expected}"));
            }
        }
        for (name, code, expected) in python_cases {
            let actual = complexity_python(code);
            if actual != *expected {
                mismatches.push(format!("{name}: got {actual}, expected {expected}"));
            }
        }
        assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
    }

    fn complexity_rust(code: &str) -> u32 {
        let file = SourceFile::new("t.rs", code, LanguageIdentifier::rust()).unwrap();
        let ast = yunq_parser_rust::RustParser::new().parse(&file).unwrap();
        let function = ast.descendants().find(|n| *n.kind() == NodeKind::FunctionDef).unwrap();
        score(function, 0, function_name(function))
    }

    fn complexity_python(code: &str) -> u32 {
        let file = SourceFile::new("t.py", code, LanguageIdentifier::python()).unwrap();
        let ast = yunq_parser_python::PythonParser::new().parse(&file).unwrap();
        let function = ast.descendants().find(|n| *n.kind() == NodeKind::FunctionDef).unwrap();
        score(function, 0, function_name(function))
    }
}
