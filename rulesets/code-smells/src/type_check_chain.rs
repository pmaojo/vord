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

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

fn is_other(node: &AstNode, kind: &str) -> bool {
    matches!(node.kind(), NodeKind::Other(k) if k.as_ref() == kind)
}

/// The `if` node shapes across the four grammars: TS/Python/Go
/// `if_statement`, Rust `if_expression`.
fn is_if(node: &AstNode) -> bool {
    is_other(node, "if_statement") || is_other(node, "if_expression")
}

/// The nodes making up one `if` link's *header*: everything before its body.
///
/// Structural, and the same shape in all four grammars: TypeScript's
/// parenthesized condition, Python's and Rust's bare condition, and Go's
/// optional init statement plus condition (`if v, ok := x.(*T); ok`) all sit
/// ahead of the `block`/`statement_block` the link executes.
fn header_nodes(link: &AstNode) -> Vec<&AstNode> {
    link.children()
        .iter()
        .take_while(|child| !is_other(child, "block") && !is_other(child, "statement_block"))
        .collect()
}

/// The operator token between two of a node's children — the one every grammar
/// models anonymously, so it is never an `AstNode` of its own.
fn operator_between<'a>(parent: &'a AstNode, first: &AstNode, second: &AstNode) -> Option<&'a str> {
    parent.text_between(first, second).map(str::trim)
}

/// The prefix operator ahead of a unary expression's operand (`typeof x`).
fn prefix_operator(unary: &AstNode) -> Option<&str> {
    let operand = unary.first_child()?;
    let end = operand
        .byte_range()
        .start
        .saturating_sub(unary.byte_range().start);
    unary.text().get(..end).map(str::trim)
}

/// The name a callee refers to: a bare `Identifier`, or the property of a
/// `MemberAccess` (`x.downcast_ref` -> `downcast_ref`).
fn callee_name(callee: &AstNode) -> Option<&str> {
    match callee.kind() {
        NodeKind::Identifier => Some(callee.text()),
        NodeKind::MemberAccess => callee.children().get(1).map(|property| property.text()),
        NodeKind::Other(_) => callee.first_child().and_then(callee_name),
        _ => None,
    }
}

/// Whether one node *is* a runtime type test.
///
/// Every arm is a node check, not a text match: a `Call` to `isinstance`, a
/// `binary_expression` whose operator reads `instanceof`, a `unary_expression`
/// whose operator reads `typeof`, a `comparison_operator` over `type(..)`, Rust's
/// `downcast_ref`/`is` turbofish call, Go's `type_assertion_expression`. A
/// comment, a string literal, or an identifier that merely *contains* one of
/// those words cannot match — which is exactly what a substring search over the
/// condition's source text could not promise.
fn is_type_test(node: &AstNode) -> bool {
    // Go: `x.(*Circle)` has a node kind all to itself.
    if is_other(node, "type_assertion_expression") {
        return true;
    }
    if *node.kind() == NodeKind::Call {
        let Some(callee) = node.first_child() else {
            return false;
        };
        return matches!(
            callee_name(callee),
            Some("isinstance" | "issubclass" | "downcast_ref" | "downcast_mut" | "is")
        );
    }
    if is_other(node, "binary_expression") {
        let (Some(left), Some(right)) = (node.first_child(), node.children().get(1)) else {
            return false;
        };
        return operator_between(node, left, right) == Some("instanceof");
    }
    if is_other(node, "unary_expression") {
        return prefix_operator(node) == Some("typeof");
    }
    // Python `type(x) is Circle`: an identity comparison over a `type(..)` call.
    if is_other(node, "comparison_operator") {
        let (Some(left), Some(right)) = (node.first_child(), node.children().get(1)) else {
            return false;
        };
        let compares_identity =
            matches!(operator_between(node, left, right), Some("is" | "is not"));
        let over_a_type_call = [left, right].iter().any(|operand| {
            *operand.kind() == NodeKind::Call
                && operand.first_child().and_then(callee_name) == Some("type")
        });
        return compares_identity && over_a_type_call;
    }
    false
}

/// Whether an `if` link's header performs a type test anywhere inside it.
fn header_tests_a_type(link: &AstNode) -> bool {
    header_nodes(link)
        .iter()
        .any(|header| header.descendants().any(is_type_test))
}

/// The `if` nodes that continue `node`'s ladder as its else-branch.
///
/// Two shapes, because the grammars disagree about whether `else` gets a node:
/// TypeScript, Python and Rust wrap it in an `else_clause`, while Go makes the
/// next `if` a direct child (its `else` is an anonymous token). A nested `if`
/// inside the *body* is a child of the `block`, never of the `if` itself, so a
/// direct `if` child is unambiguously the else-branch.
fn else_branch_ifs(node: &AstNode) -> Vec<&AstNode> {
    node.children()
        .iter()
        .flat_map(|child| {
            if is_if(child) {
                vec![child]
            } else if is_other(child, "else_clause") {
                child.children().iter().filter(|c| is_if(c)).collect()
            } else {
                Vec::new()
            }
        })
        .collect()
}

/// Every link of one `if` ladder: the head, each Python `elif_clause`, and each
/// else-branch `if`, recursively.
fn chain_links<'a>(head: &'a AstNode, links: &mut Vec<&'a AstNode>) {
    links.push(head);
    for child in head
        .children()
        .iter()
        .filter(|c| is_other(c, "elif_clause"))
    {
        links.push(child);
    }
    for nested in else_branch_ifs(head) {
        chain_links(nested, links);
    }
}

/// Spans of `if` nodes that are themselves the `else` branch of another `if`
/// — i.e. not chain heads. Span identity is enough to recognize a node again:
/// two distinct nodes cannot start and end at the same source position.
fn nested_else_if_spans(ast: &AstNode) -> Vec<(u32, u32, u32, u32)> {
    let mut spans = Vec::new();
    for node in ast.descendants().filter(|n| is_if(n)) {
        for nested in else_branch_ifs(node) {
            let span = nested.span();
            spans.push((span.start_line, span.start_col, span.end_line, span.end_col));
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
        Self {
            id: RuleId::new("smells:type-check-chain").expect("valid rule id"),
            max_type_tests,
        }
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
        [
            LanguageIdentifier::typescript(),
            LanguageIdentifier::python(),
            LanguageIdentifier::rust(),
            LanguageIdentifier::go(),
        ]
        .contains(language)
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
        if vord_rules_engine::is_test_only_path(file.path()) {
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
                let mut links = Vec::new();
                chain_links(head, &mut links);
                let tests = links.iter().filter(|link| header_tests_a_type(link)).count();
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
    use vord_rules_engine::AstParser;

    fn ts(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.ts", code, LanguageIdentifier::typescript()).unwrap();
        let ast = vord_parser_typescript::TypeScriptParser::new()
            .parse(&file)
            .unwrap();
        TypeCheckChainRule::default().check(&file, &ast)
    }

    fn py(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.py", code, LanguageIdentifier::python()).unwrap();
        let ast = vord_parser_python::PythonParser::new()
            .parse(&file)
            .unwrap();
        TypeCheckChainRule::default().check(&file, &ast)
    }

    fn rs(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.rs", code, LanguageIdentifier::rust()).unwrap();
        let ast = vord_parser_rust::RustParser::new().parse(&file).unwrap();
        TypeCheckChainRule::default().check(&file, &ast)
    }

    #[test]
    fn flags_a_three_link_instanceof_ladder() {
        let findings = ts(
            "function area(s: Shape): number {\n  if (s instanceof Circle) {\n    return 1;\n  } else if (s instanceof Square) {\n    return 2;\n  } else if (s instanceof Triangle) {\n    return 3;\n  }\n  return 0;\n}\n",
        );
        assert_eq!(findings.len(), 1);
        assert!(
            findings[0].message.contains("3 runtime type tests"),
            "{}",
            findings[0].message
        );
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
    fn flags_a_go_type_assertion_ladder() {
        let file = SourceFile::new(
            "t.go",
            "package domain

func describe(s interface{}) string {
	if _, ok := s.(*Circle); ok {
		return \"circle\"
	} else if _, ok := s.(*Square); ok {
		return \"square\"
	} else if _, ok := s.(*Triangle); ok {
		return \"triangle\"
	}
	return \"unknown\"
}
",
            LanguageIdentifier::go(),
        )
        .unwrap();
        let ast = vord_parser_go::GoParser::new().parse(&file).unwrap();
        let findings = TypeCheckChainRule::default().check(&file, &ast);
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert!(findings[0].message.contains("3 runtime type tests"));
    }

    #[test]
    fn the_words_alone_are_not_a_type_test() {
        // Structural detection means a string literal or an identifier that
        // merely reads like a type test cannot be counted as one.
        let findings = ts("function label(kind: string): string {
  if (kind === 'instanceof') {
    return 'a';
  } else if (kind === 'isinstance(') {
    return 'b';
  } else if (kind === 'typeof x ===') {
    return 'c';
  }
  return 'd';
}
");
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn silent_in_test_only_paths() {
        let file = SourceFile::new(
            "tests/shapes.ts",
            "if (s instanceof A) {\n} else if (s instanceof B) {\n} else if (s instanceof C) {\n}\n",
            LanguageIdentifier::typescript(),
        )
        .unwrap();
        let ast = vord_parser_typescript::TypeScriptParser::new()
            .parse(&file)
            .unwrap();
        assert!(TypeCheckChainRule::default().check(&file, &ast).is_empty());
    }

    #[test]
    fn applies_to_every_language_with_a_type_test_to_find() {
        let rule = TypeCheckChainRule::default();
        for language in [
            LanguageIdentifier::typescript(),
            LanguageIdentifier::python(),
            LanguageIdentifier::rust(),
            LanguageIdentifier::go(),
        ] {
            assert!(rule.applies_to(&language), "{language:?}");
        }
        assert!(!rule.applies_to(&LanguageIdentifier::php()));
    }
}
