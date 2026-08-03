use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

use crate::common::{impl_trait_is, is_other, operator_between};

/// `(trait name, method name, expected operator)` for every `std::ops`
/// binary-arithmetic trait whose semantics an operator symbol can capture.
const ARITHMETIC_TRAITS: &[(&str, &str, &str)] = &[
    ("Add", "add", "+"),
    ("Sub", "sub", "-"),
    ("Mul", "mul", "*"),
    ("Div", "div", "/"),
    ("Rem", "rem", "%"),
    ("BitAnd", "bitand", "&"),
    ("BitOr", "bitor", "|"),
    ("BitXor", "bitxor", "^"),
    ("Shl", "shl", "<<"),
    ("Shr", "shr", ">>"),
];

const ARITHMETIC_OPS: &[&str] = &["+", "-", "*", "/", "%", "&", "|", "^", "<<", ">>"];

fn method_named<'a>(impl_item: &'a AstNode, name: &str) -> Option<&'a AstNode> {
    let body = impl_item
        .children()
        .iter()
        .find(|c| is_other(c.kind(), "declaration_list"))?;
    body.children().iter().find(|c| {
        *c.kind() == NodeKind::FunctionDef
            && c.first_child()
                .is_some_and(|n| *n.kind() == NodeKind::Identifier && n.text() == name)
    })
}

/// Every arithmetic operator used directly in `func`'s body, without
/// crossing into a nested function or closure.
fn operators_used<'a>(func: &'a AstNode, source: &'a str, out: &mut Vec<&'a str>) {
    for child in func.children() {
        if *child.kind() == NodeKind::FunctionDef {
            continue;
        }
        if is_other(child.kind(), "binary_expression") && child.children().len() == 2 {
            let op = operator_between(source, &child.children()[0], &child.children()[1]);
            if ARITHMETIC_OPS.contains(&op) {
                out.push(op);
            }
        }
        operators_used(child, source, out);
    }
}

/// An `impl Add for T` whose `add` body never uses `+` but does use a
/// *different* arithmetic operator (`-`, `*`, ...) almost certainly has the
/// wrong operator — a stray edit that turned an addition into a
/// subtraction, or a copy-pasted `Sub` impl whose method name wasn't
/// updated. Same idea for `Sub`/`Mul`/`Div`/`Rem`/the bitwise ops.
pub struct SuspiciousArithmeticImplRule {
    id: RuleId,
}

impl SuspiciousArithmeticImplRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("rust:suspicious-arithmetic-impl").expect("valid rule id"),
        }
    }
}

impl Default for SuspiciousArithmeticImplRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for SuspiciousArithmeticImplRule {
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
        10
    }

    fn metadata(&self) -> vord_rules_engine::RuleMetadata {
        vord_rules_engine::RuleMetadata {
            description: "An arithmetic trait impl (`Add`, `Sub`, `Mul`, ...) whose method body \
                never uses the operator the trait promises, but does use a different one, is \
                almost certainly a bug — the caller's `a + b` will silently run whatever \
                operation the body actually performs."
                .into(),
            tags: vec!["bug".into(), "rust".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        let test_ranges = vord_rules_engine::rust_test_module_ranges(file.content());

        ast.descendants()
            .filter(|n| is_other(n.kind(), "impl_item"))
            .filter(|n| !vord_rules_engine::in_ranges(&test_ranges, n.span().start_line))
            .flat_map(|impl_item| {
                ARITHMETIC_TRAITS
                    .iter()
                    .filter_map(move |(trait_name, method, expected_op)| {
                        if !impl_trait_is(impl_item, trait_name) {
                            return None;
                        }
                        let func = method_named(impl_item, method)?;
                        let mut ops = Vec::new();
                        operators_used(func, file.content(), &mut ops);
                        if ops.contains(expected_op) || ops.is_empty() {
                            return None;
                        }
                        Some(Finding::new(
                            format!(
                                "`impl {trait_name} for _` uses `{}` but never `{expected_op}` — \
                            check this is really the intended operation",
                                ops[0]
                            ),
                            func.span(),
                        ))
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

    fn check(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.rs", code, LanguageIdentifier::rust()).unwrap();
        let ast = vord_parser_rust::RustParser::new().parse(&file).unwrap();
        SuspiciousArithmeticImplRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_add_impl_using_subtraction() {
        let findings = check(
            "impl std::ops::Add for P { type Output = P; fn add(self, o: P) -> P { P { x: self.x - o.x } } }\n",
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_sub_impl_using_addition() {
        let findings = check(
            "impl Sub for P { type Output = P; fn sub(self, o: P) -> P { P { x: self.x + o.x } } }\n",
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn ignores_correct_add_impl() {
        assert!(check(
            "impl Add for P { type Output = P; fn add(self, o: P) -> P { P { x: self.x + o.x } } }\n"
        )
        .is_empty());
    }

    #[test]
    fn ignores_add_impl_mixing_expected_and_other_ops() {
        assert!(check(
            "impl Add for P { type Output = P; fn add(self, o: P) -> P { P { x: self.x + o.x, y: self.y * 2 } } }\n"
        )
        .is_empty());
    }

    #[test]
    fn ignores_non_arithmetic_trait() {
        assert!(
            check("impl Clone for P { fn clone(&self) -> P { P { x: self.x - 1 } } }\n").is_empty()
        );
    }

    #[test]
    fn ignores_add_impl_with_no_arithmetic() {
        assert!(
            check(
                "impl Add for P { type Output = P; fn add(self, o: P) -> P { self.combine(o) } }\n"
            )
            .is_empty()
        );
    }

    #[test]
    fn ignores_suspicious_arithmetic_impl_inside_a_cfg_test_module() {
        let code = "fn prod() {}\n\n#[cfg(test)]\nmod tests {\n    impl std::ops::Add for P {\n        type Output = P;\n        fn add(self, o: P) -> P { P { x: self.x - o.x } }\n    }\n}\n";
        assert!(check(code).is_empty());
    }
}
