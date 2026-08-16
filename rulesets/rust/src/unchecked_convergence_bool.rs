use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

const LOOP_KINDS: &[&str] = &[
    "while_statement",
    "while_expression",
    "for_statement",
    "for_expression",
    "for_in_statement",
    "loop_expression",
];

/// Field/variable names that read as "did this bounded computation actually
/// finish" — a Newton-Raphson fit, a fixed-point iteration, a retry loop.
/// Case-insensitive exact match, not a substring test, so a field like
/// `is_oklahoma` doesn't trip the `ok` entry.
const CONVERGENCE_NAMES: &[&str] = &[
    "converged",
    "is_converged",
    "success",
    "succeeded",
    "is_success",
    "ok",
    "is_valid",
];

const ASSERT_MACRO_NAMES: &[&str] = &[
    "assert",
    "assert_eq",
    "assert_ne",
    "debug_assert",
    "debug_assert_eq",
    "debug_assert_ne",
];

fn other_kind_name(node: &AstNode) -> Option<&str> {
    match node.kind() {
        NodeKind::Other(name) => Some(name.as_ref()),
        _ => None,
    }
}

fn is_convergence_name(name: &str) -> bool {
    CONVERGENCE_NAMES
        .iter()
        .any(|candidate| candidate.eq_ignore_ascii_case(name))
}

/// True when `node`'s own subtree (not descending into a nested function,
/// which is judged independently) contains a `for`/`while`/`loop` header —
/// the "bounded iteration" half of the heuristic. Doesn't distinguish an
/// actually-bounded loop from an infinite one; that's a runtime property no
/// syntactic check can see, so this only narrows to "a function shaped like
/// an iterative algorithm".
fn contains_loop(node: &AstNode) -> bool {
    node.children().iter().any(|child| {
        if *child.kind() == NodeKind::FunctionDef {
            return false;
        }
        other_kind_name(child).is_some_and(|kind| LOOP_KINDS.contains(&kind))
            || contains_loop(child)
    })
}

/// Field names written by a `Type { name: expr, .. }` or shorthand
/// `Type { name, .. }` struct literal anywhere in `node`'s own subtree
/// (not descending into a nested function). This is the shape a Rust
/// "algorithm result" type almost always takes — `FitResult { converged,
/// iterations, params }` — and it's precise enough that a bare local
/// variable named `converged` used only as scratch state, never returned,
/// doesn't trip it.
fn struct_field_names<'a>(node: &'a AstNode, out: &mut Vec<&'a str>) {
    for child in node.children() {
        if *child.kind() == NodeKind::FunctionDef {
            continue;
        }
        if other_kind_name(child) == Some("field_initializer_list") {
            for field in child.children() {
                match field.kind() {
                    NodeKind::Identifier => out.push(field.text()),
                    _ if matches!(
                        other_kind_name(field),
                        Some("field_initializer") | Some("shorthand_field_initializer")
                    ) =>
                    {
                        if let Some(name) = field.children().first()
                            && *name.kind() == NodeKind::Identifier
                        {
                            out.push(name.text());
                        }
                    }
                    _ => {}
                }
            }
        }
        struct_field_names(child, out);
    }
}

/// Every identifier text appearing inside an `assert!`/`assert_eq!`/
/// `assert_ne!` (or `debug_assert*`) call whose own line falls in
/// `test_ranges` (see `rust_test_module_ranges`) — production code
/// elsewhere in the file that happens to call `assert!` doesn't count.
/// Macro arguments parse as a flat, unstructured `token_tree` rather than
/// real expressions, so `assert!(result.converged)` and
/// `assert!(converged)` both just surface `converged` as one of the
/// identifiers in the tree — exactly the granularity this check needs (it
/// only asks "is this field named anywhere in an assertion", not what
/// shape the assertion takes).
fn identifiers_in_assertions<'a>(
    node: &'a AstNode,
    test_ranges: &[vord_rules_engine::LineRange],
    out: &mut Vec<&'a str>,
) {
    if *node.kind() == NodeKind::Call
        && vord_rules_engine::in_ranges(test_ranges, node.span().start_line)
        && let Some(callee) = node.children().first()
        && *callee.kind() == NodeKind::Identifier
        && ASSERT_MACRO_NAMES.contains(&callee.text())
    {
        for arg in node.children().iter().skip(1) {
            collect_identifiers(arg, out);
        }
    }
    for child in node.children() {
        identifiers_in_assertions(child, test_ranges, out);
    }
}

fn collect_identifiers<'a>(node: &'a AstNode, out: &mut Vec<&'a str>) {
    if *node.kind() == NodeKind::Identifier {
        out.push(node.text());
    }
    for child in node.children() {
        collect_identifiers(child, out);
    }
}

/// Flags a function that builds a convergence/success-shaped bool
/// (`converged`, `success`, `ok`, ...) inside a bounded loop, when no test
/// in the same file ever names that field in an assertion — the exact gap
/// a synthetic, perfectly-separable test fixture can hide: the loop always
/// "succeeds" in the test data, so nothing ever exercises the caller
/// actually checking the flag. Purely syntactic (a name list plus an
/// assert-argument scan, no type or control-flow analysis), so it can't
/// tell a checked-but-differently-named field from a genuinely unchecked
/// one — a heuristic pointer at the function, not a proof of the bug.
pub struct UncheckedConvergenceBoolRule {
    id: RuleId,
}

impl UncheckedConvergenceBoolRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("rust:unchecked-convergence-bool").expect("valid rule id"),
        }
    }
}

impl Default for UncheckedConvergenceBoolRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for UncheckedConvergenceBoolRule {
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
        15
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "A function builds a converged/success/ok-shaped bool inside a bounded \
                loop, but no test in the file asserts on that field — a synthetic, always-easy \
                test fixture can pass while a caller silently ignores a real convergence failure."
                .into(),
            tags: vec!["rust".into(), "test-coverage".into(), "numeric".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        if vord_rules_engine::is_test_only_path(file.path()) {
            return Vec::new();
        }
        let test_ranges = vord_rules_engine::rust_test_module_ranges(file.content());
        if test_ranges.is_empty() {
            // No test code in this file at all: nothing to compare against,
            // and flagging every convergence-shaped function in a project
            // whose tests simply live elsewhere would be mostly noise.
            return Vec::new();
        }

        let mut asserted_names: Vec<&str> = Vec::new();
        identifiers_in_assertions(ast, &test_ranges, &mut asserted_names);

        ast.descendants()
            .filter(|f| *f.kind() == NodeKind::FunctionDef)
            .filter(|f| !vord_rules_engine::in_ranges(&test_ranges, f.span().start_line))
            .filter_map(|function| {
                if !contains_loop(function) {
                    return None;
                }
                let mut fields = Vec::new();
                struct_field_names(function, &mut fields);
                let unchecked: Vec<&str> = fields
                    .into_iter()
                    .filter(|name| is_convergence_name(name))
                    .filter(|name| !asserted_names.contains(name))
                    .collect();
                let field = unchecked.first()?;
                Some(Finding::new(
                    format!(
                        "function builds `{field}` inside a loop, but no test in this file asserts on `{field}`"
                    ),
                    function.span(),
                ))
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
        UncheckedConvergenceBoolRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_a_convergence_bool_built_in_a_loop_and_never_asserted() {
        let code = "\
fn fit(data: &[f64]) -> FitResult {
    let mut converged = false;
    let mut x = 0.0;
    while x < 10.0 {
        x += 1.0;
        converged = true;
    }
    FitResult { converged, x }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_runs() {
        let r = fit(&[1.0, 2.0]);
        assert_eq!(r.x, 10.0);
    }
}
";
        let findings = check(code);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("converged"));
    }

    #[test]
    fn silent_when_a_test_in_the_file_asserts_the_field() {
        let code = "\
fn fit(data: &[f64]) -> FitResult {
    let mut converged = false;
    let mut x = 0.0;
    while x < 10.0 {
        x += 1.0;
        converged = true;
    }
    FitResult { converged, x }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_converges() {
        let r = fit(&[1.0, 2.0]);
        assert!(r.converged);
    }
}
";
        assert!(check(code).is_empty());
    }

    #[test]
    fn silent_when_the_function_has_no_loop() {
        let code = "\
fn build() -> FitResult {
    FitResult { converged: true, x: 1.0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_builds() {
        let r = build();
        assert_eq!(r.x, 1.0);
    }
}
";
        assert!(check(code).is_empty());
    }

    #[test]
    fn silent_when_the_field_name_does_not_look_like_convergence() {
        let code = "\
fn fit(data: &[f64]) -> FitResult {
    let mut x = 0.0;
    while x < 10.0 {
        x += 1.0;
    }
    FitResult { total: x }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_runs() {
        let r = fit(&[1.0]);
        assert_eq!(r.total, 10.0);
    }
}
";
        assert!(check(code).is_empty());
    }

    #[test]
    fn silent_with_no_test_code_in_the_file_at_all() {
        let code = "\
fn fit(data: &[f64]) -> FitResult {
    let mut converged = false;
    let mut x = 0.0;
    while x < 10.0 {
        x += 1.0;
        converged = true;
    }
    FitResult { converged, x }
}
";
        assert!(check(code).is_empty());
    }

    #[test]
    fn silent_in_a_test_only_file() {
        let file = SourceFile::new(
            "tests/fit_test.rs",
            "\
fn fit(data: &[f64]) -> FitResult {
    let mut converged = false;
    while converged == false {
        converged = true;
    }
    FitResult { converged }
}
",
            LanguageIdentifier::rust(),
        )
        .unwrap();
        let ast = vord_parser_rust::RustParser::new().parse(&file).unwrap();
        assert!(
            UncheckedConvergenceBoolRule::new()
                .check(&file, &ast)
                .is_empty()
        );
    }
}
