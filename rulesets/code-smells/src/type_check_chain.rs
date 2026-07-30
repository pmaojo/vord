//! Rule: a chain of type tests on the same `if`/`elif`/`else if` ladder —
//! `instanceof`, `typeof x ===`, `isinstance(...)`, `downcast_ref::<T>()`.
//! The Open/Closed smell in its most literal form: every new subtype means
//! editing this ladder, so the code is open for *modification* instead of
//! extension. The fix is the one refactoring catalogs have named for decades
//! — replace conditional with polymorphism (or, where the operation genuinely
//! belongs outside the types, a visitor).
//!
//! Complements `smells:open-closed-violation`, which catches the *other* half
//! of the same problem from the type side (a base class naming its own
//! subclasses); this one catches it from the control-flow side, in code that
//! may not be a base class at all.
//!
//! The counting algorithm is CodeQL's `java/chained-type-tests`
//! (`ChainedInstanceof.ql`): walk the `else` chain from its head, count how
//! many links test a type, report the head once with the total. CodeQL fires
//! above five `instanceof` tests in Java, where the pattern is often
//! unavoidable boilerplate; three is the bar here because the languages this
//! applies to all have first-class alternatives (TS discriminated unions and
//! method dispatch, Python duck typing and `functools.singledispatch`, Rust
//! enums and trait objects), so a three-link ladder is already a design
//! choice rather than a language limitation.

use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use yunq_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

fn is_other(node: &AstNode, kind: &str) -> bool {
    matches!(node.kind(), NodeKind::Other(k) if k.as_ref() == kind)
}

/// The `if` node shapes across the three grammars: TS/Python
/// `if_statement`, Rust `if_expression`.
fn is_if(node: &AstNode) -> bool {
    is_other(node, "if_statement") || is_other(node, "if_expression")
}

/// Whether a condition's text performs a runtime type test.
///
/// Text-level matching, deliberately: the three grammars spell the same
/// question six different ways (`x instanceof T`, `typeof x === 'string'`,
/// `x.constructor.name`, `isinstance(x, T)`, `type(x) is T`,
/// `x.downcast_ref::<T>()`), and every one of them is a distinct node shape.
/// Matching the written form keeps one table where a structural walk would
/// need six, and the tokens are specific enough that a false positive needs
/// the words to appear in a condition without meaning what they say.
fn is_type_test(condition: &str) -> bool {
    let has_comparison = condition.contains("===") || condition.contains("==") || condition.contains("!=");
    if condition.contains("instanceof") {
        return true;
    }
    if condition.contains("typeof ") && has_comparison {
        return true;
    }
    if condition.contains(".constructor.name") && has_comparison {
        return true;
    }
    if condition.contains("isinstance(") || condition.contains("issubclass(") {
        return true;
    }
    if condition.contains("type(") && (condition.contains(" is ") || has_comparison) {
        return true;
    }
    condition.contains("downcast_ref::<")
        || condition.contains("downcast_mut::<")
        || condition.contains(".is::<")
}

/// Every condition on one `if` ladder: the head's own, each Python
/// `elif_clause`'s, and each `else { if ... }` link's, recursively.
fn chain_conditions<'a>(head: &'a AstNode, conditions: &mut Vec<&'a AstNode>) {
    if let Some(condition) = head.first_child() {
        conditions.push(condition);
    }
    for child in head.children() {
        if is_other(child, "elif_clause") {
            if let Some(condition) = child.first_child() {
                conditions.push(condition);
            }
        } else if is_other(child, "else_clause") {
            for nested in child.children() {
                if is_if(nested) {
                    chain_conditions(nested, conditions);
                }
            }
        }
    }
}

/// Spans of `if` nodes that are themselves the `else` branch of another `if`
/// — i.e. not chain heads. Span identity is enough to recognize a node again:
/// two distinct nodes cannot start and end at the same source position.
fn nested_else_if_spans(ast: &AstNode) -> Vec<(u32, u32, u32, u32)> {
    let mut spans = Vec::new();
    for node in ast.descendants().filter(|n| is_if(n)) {
        for clause in node.children().iter().filter(|c| is_other(c, "else_clause")) {
            for nested in clause.children().iter().filter(|c| is_if(c)) {
                let span = nested.span();
                spans.push((span.start_line, span.start_col, span.end_line, span.end_col));
            }
        }
    }
    spans
}

pub struct TypeCheckChainRule {
    id: RuleId,
    max_type_tests: usize,
}

impl TypeCheckChainRule {
    pub fn new(max_type_tests: usize) -> Self {
        Self { id: RuleId::new("smells:type-check-chain").expect("valid rule id"), max_type_tests }
    }
}

impl Default for TypeCheckChainRule {
    /// Two type tests is a binary distinction; three is a ladder that will
    /// keep growing.
    fn default() -> Self {
        Self::new(2)
    }
}

impl Rule for TypeCheckChainRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, language: &LanguageIdentifier) -> bool {
        *language == LanguageIdentifier::typescript()
            || *language == LanguageIdentifier::python()
            || *language == LanguageIdentifier::rust()
    }

    fn default_severity(&self) -> Severity {
        Severity::Major
    }

    fn remediation_effort_minutes(&self) -> u32 {
        45
    }

    fn issue_type(&self) -> IssueType {
        IssueType::CodeSmell
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "An if/elif ladder branches on the runtime type of a value, so every new subtype requires editing this function instead of adding a type — replace the conditional with polymorphism.".into(),
            tags: vec!["design".into(), "open-closed".into(), "polymorphism".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        if yunq_rules_engine::is_test_only_path(file.path()) {
            return Vec::new();
        }
        let nested = nested_else_if_spans(ast);
        let is_head = |node: &AstNode| {
            let span = node.span();
            !nested.contains(&(span.start_line, span.start_col, span.end_line, span.end_col))
        };
        ast.descendants()
            .filter(|n| is_if(n) && is_head(n))
            .filter_map(|head| {
                let mut conditions = Vec::new();
                chain_conditions(head, &mut conditions);
                let tests = conditions.iter().filter(|c| is_type_test(c.text())).count();
                (tests > self.max_type_tests).then(|| {
                    Finding::new(
                        format!(
                            "this if/else chain performs {tests} runtime type tests — every new subtype means editing it again; replace the conditional with polymorphism (Open/Closed Principle)"
                        ),
                        head.span(),
                    )
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use yunq_rules_engine::AstParser;

    fn ts(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.ts", code, LanguageIdentifier::typescript()).unwrap();
        let ast = yunq_parser_typescript::TypeScriptParser::new().parse(&file).unwrap();
        TypeCheckChainRule::default().check(&file, &ast)
    }

    fn py(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.py", code, LanguageIdentifier::python()).unwrap();
        let ast = yunq_parser_python::PythonParser::new().parse(&file).unwrap();
        TypeCheckChainRule::default().check(&file, &ast)
    }

    fn rs(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.rs", code, LanguageIdentifier::rust()).unwrap();
        let ast = yunq_parser_rust::RustParser::new().parse(&file).unwrap();
        TypeCheckChainRule::default().check(&file, &ast)
    }

    #[test]
    fn flags_a_three_link_instanceof_ladder() {
        let findings = ts(
            "function area(s: Shape): number {\n  if (s instanceof Circle) {\n    return 1;\n  } else if (s instanceof Square) {\n    return 2;\n  } else if (s instanceof Triangle) {\n    return 3;\n  }\n  return 0;\n}\n",
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("3 runtime type tests"), "{}", findings[0].message);
        assert_eq!(findings[0].span.start_line, 2);
    }

    #[test]
    fn allows_a_two_way_type_distinction() {
        let findings = ts(
            "function area(s: Shape): number {\n  if (s instanceof Circle) {\n    return 1;\n  } else if (s instanceof Square) {\n    return 2;\n  }\n  return 0;\n}\n",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn reports_the_chain_head_once_not_every_link() {
        let findings = ts(
            "function f(x: unknown): number {\n  if (typeof x === 'string') {\n    return 1;\n  } else if (typeof x === 'number') {\n    return 2;\n  } else if (typeof x === 'boolean') {\n    return 3;\n  } else if (typeof x === 'bigint') {\n    return 4;\n  }\n  return 0;\n}\n",
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("4 runtime type tests"));
    }

    #[test]
    fn ignores_a_chain_of_ordinary_value_conditions() {
        let findings = ts(
            "function f(n: number): number {\n  if (n === 1) {\n    return 1;\n  } else if (n === 2) {\n    return 2;\n  } else if (n === 3) {\n    return 3;\n  }\n  return 0;\n}\n",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn flags_a_python_isinstance_ladder() {
        let findings = py(
            "def area(s):\n    if isinstance(s, Circle):\n        return 1\n    elif isinstance(s, Square):\n        return 2\n    elif isinstance(s, Triangle):\n        return 3\n    return 0\n",
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("3 runtime type tests"));
    }

    #[test]
    fn flags_a_python_type_identity_ladder() {
        let findings = py(
            "def kind(s):\n    if type(s) is Circle:\n        return 1\n    elif type(s) is Square:\n        return 2\n    elif type(s) is Triangle:\n        return 3\n    return 0\n",
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_a_rust_downcast_ladder() {
        let findings = rs(
            "fn area(s: &dyn Any) -> i32 {\n    if s.downcast_ref::<Circle>().is_some() {\n        1\n    } else if s.downcast_ref::<Square>().is_some() {\n        2\n    } else if s.downcast_ref::<Triangle>().is_some() {\n        3\n    } else {\n        0\n    }\n}\n",
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("3 runtime type tests"));
    }

    #[test]
    fn ignores_an_idiomatic_rust_match_on_an_enum() {
        // Matching an enum's variants is exhaustive and compiler-checked —
        // the opposite of the fragile ladder this rule targets.
        let findings = rs(
            "fn area(s: Shape) -> i32 {\n    match s {\n        Shape::Circle => 1,\n        Shape::Square => 2,\n        Shape::Triangle => 3,\n    }\n}\n",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn silent_in_test_only_paths() {
        let file = SourceFile::new(
            "tests/shapes.ts",
            "if (s instanceof A) {\n} else if (s instanceof B) {\n} else if (s instanceof C) {\n}\n",
            LanguageIdentifier::typescript(),
        )
        .unwrap();
        let ast = yunq_parser_typescript::TypeScriptParser::new().parse(&file).unwrap();
        assert!(TypeCheckChainRule::default().check(&file, &ast).is_empty());
    }

    #[test]
    fn applies_only_to_typescript_python_and_rust() {
        let rule = TypeCheckChainRule::default();
        assert!(rule.applies_to(&LanguageIdentifier::typescript()));
        assert!(rule.applies_to(&LanguageIdentifier::python()));
        assert!(rule.applies_to(&LanguageIdentifier::rust()));
        assert!(!rule.applies_to(&LanguageIdentifier::go()));
    }
}
