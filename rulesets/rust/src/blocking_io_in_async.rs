use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile, Span};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

use crate::common::is_other;

fn is_async_fn(node: &AstNode) -> bool {
    node.children().iter().any(|c| {
        is_other(c.kind(), "function_modifiers")
            && c.text().split_whitespace().any(|w| w == "async")
    })
}

const BLOCKING_FS_FNS: &[&str] = &[
    "fs::read",
    "fs::read_to_string",
    "fs::read_dir",
    "fs::read_link",
    "fs::write",
    "fs::remove_file",
    "fs::remove_dir",
    "fs::remove_dir_all",
    "fs::create_dir",
    "fs::create_dir_all",
    "fs::rename",
    "fs::copy",
    "fs::metadata",
    "fs::canonicalize",
    "fs::hard_link",
    "fs::set_permissions",
    "fs::File::open",
    "fs::File::create",
];

/// Whether `callee_text` is a *direct* call to a synchronous,
/// thread-blocking I/O operation. Matched by suffix (like
/// `blocking_sleep_in_async::is_thread_sleep_call`) rather than substring,
/// so a later call chained onto the result (`fs::write(..).unwrap()`)
/// isn't counted a second time under its own, unrelated callee text.
/// Restricted to `std::fs` (there is no async `std::fs`, so any call
/// through it blocks the calling OS thread regardless of context, unlike
/// `tokio::fs`/`async_std::fs`, explicitly excluded below) plus blocking
/// stdin/stdout access — a narrow, high-precision net that avoids guessing
/// about arbitrary `read`/`write` method names, which collide with the
/// async equivalents on `AsyncRead`/`AsyncWrite`.
fn is_blocking_io_call(callee_text: &str) -> bool {
    if BLOCKING_FS_FNS.iter().any(|f| callee_text.ends_with(f)) {
        return !callee_text.contains("tokio::fs")
            && !callee_text.contains("async_std::fs")
            && !callee_text.contains("smol::fs");
    }
    (callee_text.ends_with("io::stdin") || callee_text.ends_with("io::stdout"))
        // `tokio::io::stdin`/`tokio::io::stdout` (and the `async_std`/`smol`
        // equivalents) are async-safe wrappers over the same file
        // descriptor, not the blocking `std::io` handles — the whole point
        // of reaching for them in async code. Only the bare `std`/unqualified
        // form (whose blocking nature is why this rule exists) counts.
        && !callee_text.contains("tokio::io")
        && !callee_text.contains("async_std::io")
        && !callee_text.contains("smol::io")
}

/// Collects blocking I/O calls reachable from `node` without crossing into a
/// nested function or closure, mirroring
/// [`crate::blocking_sleep_in_async`]'s traversal: a closure handed to
/// `spawn_blocking` or a sync callback executes in its own context, so a
/// blocking call inside one doesn't stall the enclosing `async fn`'s task
/// the way a direct call in its own body does.
fn collect_blocking_io<'a>(node: &'a AstNode, out: &mut Vec<&'a AstNode>) {
    for child in node.children() {
        if *child.kind() == NodeKind::FunctionDef {
            continue;
        }
        if *child.kind() == NodeKind::Call
            && child
                .first_child()
                .is_some_and(|c| is_blocking_io_call(c.text()))
        {
            out.push(child);
        }
        collect_blocking_io(child, out);
    }
}

/// `std::fs` and blocking stdin/stdout have no async variant: every call
/// blocks the current OS thread until the operation completes. Async
/// runtimes multiplex many tasks onto a small pool of OS threads, so a
/// blocking filesystem or console call inside an `async fn`'s own body
/// stalls every other task the runtime scheduled onto that thread, not just
/// the current one. Use the runtime's async filesystem API (e.g.
/// `tokio::fs::read`) or move the blocking call into
/// `spawn_blocking`/`block_in_place`.
pub struct BlockingIoInAsyncRule {
    id: RuleId,
}

impl BlockingIoInAsyncRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("rust:blocking-io-in-async").expect("valid rule id"),
        }
    }
}

impl Default for BlockingIoInAsyncRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for BlockingIoInAsyncRule {
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
            description: "Synchronous filesystem or stdin/stdout calls inside an `async fn` \
                block the OS thread the async runtime is multiplexing tasks onto, stalling \
                every other task scheduled on it. Use the runtime's async filesystem API or \
                `spawn_blocking` instead."
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
            let mut calls = Vec::new();
            collect_blocking_io(async_fn, &mut calls);
            spans.extend(calls.into_iter().map(AstNode::span));
        }
        spans
            .into_iter()
            .filter(|span| !vord_rules_engine::in_ranges(&test_ranges, span.start_line))
            .map(|span| {
                Finding::new(
                    "this blocking filesystem/console call inside an `async fn` stalls the OS \
                    thread and every other task the runtime scheduled onto it; use an async \
                    equivalent or `spawn_blocking`"
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
        BlockingIoInAsyncRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_std_fs_read_in_async_fn() {
        let findings = check("async fn f() { let _ = std::fs::read(\"x\"); }\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_fs_write_inside_if() {
        let findings =
            check("async fn f(x: bool) { if x { fs::write(\"a\", \"b\").unwrap(); } }\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_blocking_stdin_read() {
        let findings = check(
            "async fn f() { let mut s = String::new(); std::io::stdin().read_line(&mut s).unwrap(); }\n",
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn ignores_blocking_io_inside_nested_closure() {
        assert!(
            check("async fn f() { spawn_blocking(|| { std::fs::read(\"x\").unwrap() }); }\n")
                .is_empty()
        );
    }

    #[test]
    fn ignores_blocking_io_in_non_async_fn() {
        assert!(check("fn f() { let _ = std::fs::read(\"x\"); }\n").is_empty());
    }

    #[test]
    fn ignores_async_fs_call() {
        assert!(check("async fn f() { let _ = tokio::fs::read(\"x\").await; }\n").is_empty());
    }

    #[test]
    fn ignores_tokio_async_stdin_and_stdout() {
        // `tokio::io::stdin`/`tokio::io::stdout` are async-safe wrappers
        // (the whole reason to reach for them in async code), unlike the
        // blocking `std::io::stdin`/`std::io::stdout` this rule targets.
        let findings = check(
            "async fn f() { let stdin = tokio::io::stdin(); let stdout = tokio::io::stdout(); let _ = (stdin, stdout); }\n",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn ignores_unrelated_calls_named_read() {
        assert!(check("async fn f(r: &mut Buf) { r.read(&mut []).await.unwrap(); }\n").is_empty());
    }

    #[test]
    fn ignores_blocking_io_inside_a_cfg_test_module() {
        let code = "fn prod() {}\n\n#[cfg(test)]\nmod tests {\n    #[test]\n    async fn t() {\n        std::fs::read(\"x\").unwrap();\n    }\n}\n";
        assert!(check(code).is_empty());
    }
}
