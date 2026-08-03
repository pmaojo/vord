use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile, Span};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

use crate::common::is_other;

fn is_async_fn(node: &AstNode) -> bool {
    node.children().iter().any(|c| {
        is_other(c.kind(), "function_modifiers")
            && c.text().split_whitespace().any(|w| w == "async")
    })
}

fn is_thread_sleep_call(callee_text: &str) -> bool {
    callee_text.ends_with("thread::sleep")
}

/// Collects blocking `thread::sleep` calls reachable from `node` without
/// crossing into a nested function or closure: a closure handed to
/// `spawn_blocking`/`std::thread::spawn`/a sync callback runs in its own
/// execution context (on whatever thread actually calls it), so a blocking
/// call inside one doesn't stall the enclosing `async fn`'s task the way a
/// direct call in its own body does.
fn collect_blocking_sleeps<'a>(node: &'a AstNode, out: &mut Vec<&'a AstNode>) {
    for child in node.children() {
        if *child.kind() == NodeKind::FunctionDef {
            continue;
        }
        if *child.kind() == NodeKind::Call
            && child
                .first_child()
                .is_some_and(|c| is_thread_sleep_call(c.text()))
        {
            out.push(child);
        }
        collect_blocking_sleeps(child, out);
    }
}

/// `std::thread::sleep` blocks the current OS thread. Async runtimes
/// (Tokio, async-std, ...) multiplex many tasks onto a small pool of OS
/// threads, so a blocking sleep inside an `async fn`'s own body doesn't
/// just delay that one task — it stalls every other task the runtime had
/// scheduled onto that thread until the sleep ends. `tokio::time::sleep(..)
/// .await` (or the runtime's equivalent) yields the thread back to the
/// scheduler instead; a genuinely-synchronous sleep belongs on a dedicated
/// blocking thread (e.g. `spawn_blocking`), not inline in async code.
pub struct BlockingSleepInAsyncRule {
    id: RuleId,
}

impl BlockingSleepInAsyncRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("rust:blocking-sleep-in-async").expect("valid rule id"),
        }
    }
}

impl Default for BlockingSleepInAsyncRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for BlockingSleepInAsyncRule {
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
            description: "`std::thread::sleep` inside an `async fn` blocks the OS thread the \
                async runtime is multiplexing tasks onto, stalling every other task scheduled \
                on it. Use the runtime's async sleep (e.g. `tokio::time::sleep(..).await`) \
                instead."
                .into(),
            tags: vec!["performance".into(), "async".into(), "rust".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        let test_ranges = vord_rules_engine::rust_test_module_ranges(file.content());
        let mut spans: Vec<Span> = Vec::new();
        for async_fn in ast
            .descendants()
            .filter(|n| *n.kind() == NodeKind::FunctionDef && is_async_fn(n))
        {
            let mut sleeps = Vec::new();
            collect_blocking_sleeps(async_fn, &mut sleeps);
            spans.extend(sleeps.into_iter().map(AstNode::span));
        }
        spans
            .into_iter()
            .filter(|span| !vord_rules_engine::in_ranges(&test_ranges, span.start_line))
            .map(|span| {
                Finding::new(
                    "`std::thread::sleep` blocks the OS thread inside an `async fn`, stalling \
                    every other task the runtime scheduled onto it; use an async sleep instead"
                        .to_string(),
                    span,
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
        BlockingSleepInAsyncRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_direct_blocking_sleep_in_async_fn() {
        let findings =
            check("async fn f() { std::thread::sleep(std::time::Duration::from_secs(1)); }\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_qualified_thread_sleep_inside_if() {
        let findings = check(
            "async fn f(x: bool) { if x { thread::sleep(std::time::Duration::from_millis(1)); } }\n",
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn ignores_sleep_inside_nested_closure() {
        assert!(check(
            "async fn f() { spawn_blocking(|| { std::thread::sleep(std::time::Duration::from_secs(1)); }); }\n"
        )
        .is_empty());
    }

    #[test]
    fn ignores_sleep_in_non_async_fn() {
        assert!(
            check("fn f() { std::thread::sleep(std::time::Duration::from_secs(1)); }\n").is_empty()
        );
    }

    #[test]
    fn ignores_awaited_async_sleep() {
        assert!(
            check(
                "async fn f() { tokio::time::sleep(std::time::Duration::from_secs(1)).await; }\n"
            )
            .is_empty()
        );
    }

    #[test]
    fn ignores_blocking_sleep_inside_a_cfg_test_module() {
        let code = "fn prod() {}\n\n#[cfg(test)]\nmod tests {\n    #[test]\n    async fn t() {\n        std::thread::sleep(std::time::Duration::from_secs(1));\n    }\n}\n";
        assert!(check(code).is_empty());
    }
}
