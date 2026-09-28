use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

use crate::common::{impl_trait_is, is_other};

fn drop_method(impl_item: &AstNode) -> Option<&AstNode> {
    let body = impl_item
        .children()
        .iter()
        .find(|c| is_other(c.kind(), "declaration_list"))?;
    body.children().iter().find(|c| {
        *c.kind() == NodeKind::FunctionDef
            && c.first_child()
                .is_some_and(|n| *n.kind() == NodeKind::Identifier && n.text() == "drop")
    })
}

/// Whether `call`'s callee is a `Mutex`/`RwLock`-shaped `.lock()`,
/// `.write()`, or `.read()` method call.
fn is_lock_call(call: &AstNode) -> bool {
    let Some(callee) = call.first_child() else {
        return false;
    };
    if *callee.kind() != NodeKind::MemberAccess {
        return false;
    }
    let method = callee.text().rsplit('.').next().unwrap_or(callee.text());
    method == "lock" || method == "write" || method == "read"
}

/// Acquiring a `Mutex`/`RwLock` guard inside `Drop::drop` is risky: if the
/// same lock is already held elsewhere in the unwind path (e.g. the type
/// being dropped while a guard on the same mutex is still in scope higher
/// up the stack, or the lock is poisoned by a panicking thread), the lock
/// call deadlocks or panics during cleanup — exactly the place a program
/// most needs `drop` to run to completion. Prefer taking any lock the
/// destructor needs *before* entering `drop`, or restructure so cleanup
/// doesn't require synchronization.
pub struct MutexLockedInDropRule {
    id: RuleId,
}

impl MutexLockedInDropRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("rust:mutex-locked-in-drop").expect("valid rule id"),
        }
    }
}

impl Default for MutexLockedInDropRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for MutexLockedInDropRule {
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

    fn metadata(&self) -> vord_rules_engine::RuleMetadata {
        vord_rules_engine::RuleMetadata {
            description: "Locking a `Mutex`/`RwLock` inside `Drop::drop` can deadlock (if the \
                same lock is already held higher up the unwind path) or panic on a poisoned \
                lock, right when the program most needs cleanup to complete. Acquire the lock \
                before entering `drop`, or avoid synchronization in the destructor."
                .into(),
            tags: vec!["reliability".into(), "concurrency".into(), "rust".into()],
            cwe: Some(833),
            produces_hotspots: false,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        let test_ranges = vord_rules_engine::rust_test_module_ranges(file.content());

        ast.descendants()
            .filter(|n| is_other(n.kind(), "impl_item"))
            .filter(|n| impl_trait_is(n, "Drop"))
            .filter(|n| !vord_rules_engine::in_ranges(&test_ranges, n.span().start_line))
            .filter_map(drop_method)
            .flat_map(|drop_fn| {
                drop_fn
                    .descendants()
                    .filter(|n| *n.kind() == NodeKind::Call)
                    .filter(|call| is_lock_call(call))
                    .map(|call| {
                        Finding::new(
                            "this locks a `Mutex`/`RwLock` inside `Drop::drop`, which can \
                            deadlock or panic on a poisoned lock right when cleanup needs to \
                            run"
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
    use vord_ast::SourceFile;
    use vord_rules_engine::AstParser;

    use super::*;

    fn check(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.rs", code, LanguageIdentifier::rust()).unwrap();
        let ast = vord_parser_rust::RustParser::new().parse(&file).unwrap();
        MutexLockedInDropRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_mutex_lock_in_drop() {
        let findings = check(
            "impl Drop for Foo {\n    fn drop(&mut self) {\n        let _g = self.m.lock().unwrap();\n    }\n}\n",
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_rwlock_write_in_drop() {
        let findings = check(
            "impl Drop for Foo {\n    fn drop(&mut self) {\n        let _g = self.m.write().unwrap();\n    }\n}\n",
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_rwlock_read_in_drop() {
        let findings = check(
            "impl Drop for Foo {\n    fn drop(&mut self) {\n        let _g = self.m.read().unwrap();\n    }\n}\n",
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn ignores_lock_outside_drop() {
        assert!(
            check("impl Foo {\n    fn close(&self) {\n        let _g = self.m.lock().unwrap();\n    }\n}\n")
                .is_empty()
        );
    }

    #[test]
    fn ignores_other_trait_impls() {
        assert!(check(
            "impl Clone for Foo {\n    fn clone(&self) -> Self {\n        let _g = self.m.lock().unwrap();\n        Self\n    }\n}\n"
        )
        .is_empty());
    }

    #[test]
    fn ignores_unrelated_methods_in_drop() {
        assert!(check(
            "impl Drop for Foo {\n    fn drop(&mut self) {\n        self.file.flush().ok();\n    }\n}\n"
        )
        .is_empty());
    }

    #[test]
    fn ignores_mutex_lock_in_drop_inside_a_cfg_test_module() {
        let code = "fn prod() {}\n\n#[cfg(test)]\nmod tests {\n    impl Drop for Foo {\n        fn drop(&mut self) {\n            let _g = self.m.lock().unwrap();\n        }\n    }\n}\n";
        assert!(check(code).is_empty());
    }
}
