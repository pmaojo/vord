use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use yunq_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

use crate::common::{impl_trait_is, is_other};

const PANIC_MACROS: &[&str] = &[
    "panic",
    "todo",
    "unimplemented",
    "unreachable",
    "assert",
    "assert_eq",
    "assert_ne",
    "debug_assert",
    "debug_assert_eq",
    "debug_assert_ne",
];

fn drop_method(impl_item: &AstNode) -> Option<&AstNode> {
    let body = impl_item.children().iter().find(|c| is_other(c.kind(), "declaration_list"))?;
    body.children().iter().find(|c| {
        *c.kind() == NodeKind::FunctionDef
            && c.first_child().is_some_and(|n| *n.kind() == NodeKind::Identifier && n.text() == "drop")
    })
}

/// Whether `call` risks panicking: a `panic!`-family macro, or `.unwrap()`/
/// `.expect(..)` on a `Result`/`Option`.
fn panic_risk(call: &AstNode) -> bool {
    let Some(callee) = call.first_child() else { return false };
    match callee.kind() {
        NodeKind::Identifier => PANIC_MACROS.contains(&callee.text()),
        NodeKind::MemberAccess => {
            let method = callee.text().rsplit('.').next().unwrap_or(callee.text());
            method == "unwrap" || method == "expect"
        }
        _ => false,
    }
}

/// A panic unwinding out of `Drop::drop` while another panic is already
/// unwinding through the same value (e.g. a panicking constructor whose
/// partially-built value gets dropped, or dropping inside a panicking
/// function) makes Rust abort the whole process immediately — no
/// `catch_unwind`, no cleanup, no unwind at all. `Drop::drop` is exactly the
/// one place a panic is not safe to assume is recoverable.
pub struct PanicInDropRule {
    id: RuleId,
}

impl PanicInDropRule {
    pub fn new() -> Self {
        Self { id: RuleId::new("rust:panic-in-drop").expect("valid rule id") }
    }
}

impl Default for PanicInDropRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for PanicInDropRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, language: &LanguageIdentifier) -> bool {
        *language == LanguageIdentifier::rust()
    }

    fn default_severity(&self) -> Severity {
        Severity::Critical
    }

    fn issue_type(&self) -> IssueType {
        IssueType::Bug
    }

    fn remediation_effort_minutes(&self) -> u32 {
        15
    }

    fn metadata(&self) -> yunq_rules_engine::RuleMetadata {
        yunq_rules_engine::RuleMetadata {
            description: "A panic inside `Drop::drop` that unwinds while another panic is \
                already unwinding through the same value aborts the process immediately, \
                skipping all remaining cleanup. Handle the error instead of \
                panicking/unwrapping/asserting inside `drop`."
                .into(),
            tags: vec!["reliability".into(), "rust".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter(|n| is_other(n.kind(), "impl_item"))
            .filter(|n| impl_trait_is(n, "Drop"))
            .filter_map(drop_method)
            .flat_map(|drop_fn| {
                drop_fn
                    .descendants()
                    .filter(|n| *n.kind() == NodeKind::Call)
                    .filter(|call| panic_risk(call))
                    .map(|call| {
                        Finding::new(
                            "this can panic inside `Drop::drop`; a panic unwinding during \
                            another unwind aborts the process instead of cleaning up"
                                .to_string(),
                            call.span(),
                        )
                    })
                    .collect::<Vec<_>>()
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use yunq_ast::SourceFile;
    use yunq_rules_engine::AstParser;

    use super::*;

    fn check(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.rs", code, LanguageIdentifier::rust()).unwrap();
        let ast = yunq_parser_rust::RustParser::new().parse(&file).unwrap();
        PanicInDropRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_unwrap_in_drop() {
        let findings =
            check("impl Drop for Foo {\n    fn drop(&mut self) {\n        self.close().unwrap();\n    }\n}\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_panic_macro_in_drop() {
        let findings =
            check("impl Drop for Foo {\n    fn drop(&mut self) {\n        panic!(\"bad\");\n    }\n}\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_expect_in_drop() {
        let findings = check(
            "impl Drop for Foo {\n    fn drop(&mut self) {\n        self.flush().expect(\"flush\");\n    }\n}\n",
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn ignores_unwrap_outside_drop() {
        assert!(check("impl Foo {\n    fn close(&self) {\n        self.inner().unwrap();\n    }\n}\n").is_empty());
    }

    #[test]
    fn ignores_safe_drop_body() {
        assert!(check(
            "impl Drop for Foo {\n    fn drop(&mut self) {\n        let _ = self.close();\n    }\n}\n"
        )
        .is_empty());
    }

    #[test]
    fn ignores_other_trait_impls() {
        assert!(check("impl Clone for Foo {\n    fn clone(&self) -> Self {\n        self.x.unwrap();\n        Self\n    }\n}\n").is_empty());
    }
}
