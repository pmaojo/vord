use vord_ast::{AstNode, LanguageIdentifier, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

use crate::common::{has_safety_comment_directly_above, impl_trait_is, is_other};

fn is_unsafe_impl(node: &AstNode) -> bool {
    node.text()
        .trim_start()
        .strip_prefix("unsafe")
        .is_some_and(|rest| rest.starts_with(|c: char| c.is_whitespace()))
}

/// Security hotspot: manually implementing `Send`/`Sync` opts a type out of
/// the compiler's automatic thread-safety analysis and asserts, by hand,
/// that it's actually safe to move (`Send`) or share by reference (`Sync`)
/// across threads. A wrong assertion is a data race — undefined behavior,
/// not a panic — and the compiler cannot catch the mistake because that's
/// exactly what the `unsafe impl` told it to stop checking. Requires a
/// `SAFETY` comment justifying the invariant, same convention as
/// `rust:unsafe-undocumented`.
pub struct UnsafeSendSyncImplRule {
    id: RuleId,
}

impl UnsafeSendSyncImplRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("rust:unsafe-send-sync-impl").expect("valid rule id"),
        }
    }
}

impl Default for UnsafeSendSyncImplRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for UnsafeSendSyncImplRule {
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
        20
    }

    fn metadata(&self) -> vord_rules_engine::RuleMetadata {
        vord_rules_engine::RuleMetadata {
            description: "A manual `unsafe impl Send`/`Sync` asserts thread-safety the compiler \
                can no longer verify; a `SAFETY` comment must justify why the type actually \
                tolerates being moved or shared across threads."
                .into(),
            tags: vec![
                "security".into(),
                "unsafe".into(),
                "concurrency".into(),
                "rust".into(),
            ],
            cwe: Some(362),
            produces_hotspots: true,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        let lines: Vec<&str> = file.content().lines().collect();
        let test_ranges = vord_rules_engine::rust_test_module_ranges(file.content());

        ast.descendants()
            .filter(|n| is_other(n.kind(), "impl_item"))
            .filter(|n| is_unsafe_impl(n))
            .filter(|n| impl_trait_is(n, "Send") || impl_trait_is(n, "Sync"))
            .filter(|n| !has_safety_comment_directly_above(&lines, n.span().start_line))
            .filter(|n| !vord_rules_engine::in_ranges(&test_ranges, n.span().start_line))
            .map(|n| {
                Finding::hotspot(
                    "`unsafe impl Send`/`Sync` has no `SAFETY` comment justifying the \
                    thread-safety invariant it asserts",
                    n.span(),
                )
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
        UnsafeSendSyncImplRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_undocumented_unsafe_send() {
        let findings = check("unsafe impl Send for Wrapper {}\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_undocumented_unsafe_sync_with_generics() {
        let findings = check("unsafe impl<T> Sync for Wrapper<T> {}\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_scoped_trait_path() {
        let findings = check("unsafe impl std::marker::Send for Wrapper {}\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn accepts_documented_unsafe_send() {
        let findings = check(
            "// SAFETY: Wrapper only ever holds a Box<u8>, which is Send.\nunsafe impl Send for Wrapper {}\n",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn ignores_safe_trait_impls() {
        assert!(check("impl Clone for Foo { fn clone(&self) -> Self { Self } }\n").is_empty());
    }

    #[test]
    fn ignores_inherent_impls() {
        assert!(check("impl Foo { fn new() -> Self { Self } }\n").is_empty());
    }

    #[test]
    fn ignores_other_unsafe_trait_impls() {
        assert!(check("unsafe impl Allocator for Foo {}\n").is_empty());
    }

    #[test]
    fn ignores_unsafe_send_sync_impl_inside_a_cfg_test_module() {
        let code =
            "fn prod() {}\n\n#[cfg(test)]\nmod tests {\n    unsafe impl Send for Wrapper {}\n}\n";
        assert!(check(code).is_empty());
    }
}
