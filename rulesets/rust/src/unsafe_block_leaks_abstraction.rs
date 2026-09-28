use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

use crate::common::is_other;

/// Whether `node`'s text starts with a bare `pub` visibility (not
/// `pub(crate)`/`pub(super)`/...): the next character after the `pub`
/// keyword is whitespace, not `(`. Mirrors
/// `unsafe_send_sync_impl::is_unsafe_impl`'s prefix check.
fn is_plain_pub(node: &AstNode) -> bool {
    node.text()
        .trim_start()
        .strip_prefix("pub")
        .is_some_and(|rest| rest.starts_with(|c: char| c.is_whitespace()))
}

fn is_unsafe_fn(node: &AstNode) -> bool {
    node.children().iter().any(|c| {
        is_other(c.kind(), "function_modifiers")
            && c.text().split_whitespace().any(|w| w == "unsafe")
    })
}

/// The function's declared signature — everything up to (not including) the
/// opening `{` of its body. Raw pointer syntax (`*mut T` / `*const T`)
/// appearing here is part of the public contract; the same syntax appearing
/// only in the body is an internal implementation detail this rule doesn't
/// care about.
fn signature_text(node: &AstNode) -> &str {
    let text = node.text();
    text.find('{').map(|i| &text[..i]).unwrap_or(text)
}

fn signature_has_raw_pointer(node: &AstNode) -> bool {
    let sig = signature_text(node);
    sig.contains("*mut ") || sig.contains("*const ")
}

/// A `pub fn` that is not itself `unsafe` but takes or returns a raw
/// pointer lets `unsafe`-shaped concerns leak across the safe/unsafe
/// boundary: callers can hold, pass around, and dereference the pointer
/// (in their own `unsafe` block) without the compiler ever making them
/// justify the pointer's validity at the point it was handed out. Either
/// mark the function `unsafe fn` so the safety contract is explicit, or
/// return a safe abstraction (`&T`, `Box<T>`, a wrapper type) instead of
/// the raw pointer.
pub struct UnsafeBlockLeaksAbstractionRule {
    id: RuleId,
}

impl UnsafeBlockLeaksAbstractionRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("rust:unsafe-block-leaks-abstraction").expect("valid rule id"),
        }
    }
}

impl Default for UnsafeBlockLeaksAbstractionRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for UnsafeBlockLeaksAbstractionRule {
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
        20
    }

    fn metadata(&self) -> vord_rules_engine::RuleMetadata {
        vord_rules_engine::RuleMetadata {
            description: "A safe `pub fn` that takes or returns a raw pointer lets unsafety \
                leak across the safe/unsafe boundary without the compiler forcing callers to \
                justify the pointer's validity. Mark the function `unsafe fn`, or return a \
                safe abstraction instead of the raw pointer."
                .into(),
            tags: vec!["security".into(), "unsafe".into(), "rust".into()],
            cwe: None,
            produces_hotspots: true,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        let test_ranges = vord_rules_engine::rust_test_module_ranges(file.content());

        ast.descendants()
            .filter(|n| *n.kind() == NodeKind::FunctionDef)
            .filter(|n| is_plain_pub(n))
            .filter(|n| !is_unsafe_fn(n))
            .filter(|n| signature_has_raw_pointer(n))
            .filter(|n| !vord_rules_engine::in_ranges(&test_ranges, n.span().start_line))
            .map(|n| {
                Finding::hotspot(
                    "this safe `pub fn` takes or returns a raw pointer, leaking an unsafe \
                    concern into a safe API; mark it `unsafe fn` or return a safe abstraction",
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
        UnsafeBlockLeaksAbstractionRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_safe_pub_fn_returning_raw_pointer() {
        let findings = check("pub fn get_ptr(v: &mut Vec<u8>) -> *mut u8 { v.as_mut_ptr() }\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_safe_pub_fn_taking_raw_pointer_param() {
        let findings = check("pub fn set(p: *const u8) { }\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn ignores_unsafe_pub_fn_with_raw_pointer() {
        assert!(check("pub unsafe fn get_ptr() -> *mut u8 { std::ptr::null_mut() }\n").is_empty());
    }

    #[test]
    fn ignores_pub_crate_fn_with_raw_pointer() {
        assert!(check("pub(crate) fn get_ptr() -> *mut u8 { std::ptr::null_mut() }\n").is_empty());
    }

    #[test]
    fn ignores_private_fn_with_raw_pointer() {
        assert!(check("fn get_ptr() -> *mut u8 { std::ptr::null_mut() }\n").is_empty());
    }

    #[test]
    fn ignores_safe_pub_fn_without_raw_pointer() {
        assert!(check("pub fn get(&self) -> u32 { self.0 }\n").is_empty());
    }

    #[test]
    fn ignores_raw_pointer_used_only_in_body() {
        assert!(check(
            "pub fn len(v: &Vec<u8>) -> usize {\n    let _p: *const u8 = v.as_ptr();\n    v.len()\n}\n"
        )
        .is_empty());
    }

    #[test]
    fn ignores_unsafe_block_leaks_abstraction_inside_a_cfg_test_module() {
        let code = "fn prod() {}\n\n#[cfg(test)]\nmod tests {\n    pub fn get_ptr() -> *mut u8 {\n        std::ptr::null_mut()\n    }\n}\n";
        assert!(check(code).is_empty());
    }
}
