//! Rule: flags `threading.Thread`/`threading.Lock`/`threading.Event`
//! construction inside an `async def` function body. Mixing OS threads
//! into asyncio code is occasionally the right call (CPU-bound work,
//! blocking third-party APIs), but doing it ad hoc inside a coroutine
//! usually means a synchronization primitive that doesn't cooperate with
//! the event loop (a `threading.Lock` blocks the whole loop while held,
//! where `asyncio.Lock` would yield); reach for `asyncio.to_thread`/
//! `run_in_executor` or the `asyncio` equivalent primitive instead.

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, Rule, RuleId, Severity};

fn is_async_function(node: &AstNode) -> bool {
    *node.kind() == NodeKind::FunctionDef && node.text().trim_start().starts_with("async")
}

fn is_threading_construct(call: &AstNode) -> bool {
    call.first_child()
        .is_some_and(|callee| callee.text().starts_with("threading."))
}

fn walk(node: &AstNode, in_async: bool, out: &mut Vec<Finding>) {
    if in_async && *node.kind() == NodeKind::Call && is_threading_construct(node) {
        out.push(Finding::new(
            "threading primitive constructed directly inside an async function; a plain threading.Lock/Thread doesn't cooperate with the event loop. Use asyncio.to_thread/run_in_executor, or the asyncio equivalent primitive",
            node.span(),
        ));
    }

    let child_in_async = if is_async_function(node) {
        true
    } else if *node.kind() == NodeKind::FunctionDef {
        false
    } else {
        in_async
    };

    for child in node.children() {
        walk(child, child_in_async, out);
    }
}

pub struct ThreadingMixedWithAsyncioRule {
    id: RuleId,
}

impl ThreadingMixedWithAsyncioRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("python:threading-mixed-with-asyncio").expect("valid rule id"),
        }
    }
}

impl Default for ThreadingMixedWithAsyncioRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for ThreadingMixedWithAsyncioRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, lang: &LanguageIdentifier) -> bool {
        *lang == LanguageIdentifier::python()
    }

    fn default_severity(&self) -> Severity {
        Severity::Major
    }

    fn remediation_effort_minutes(&self) -> u32 {
        20
    }

    fn metadata(&self) -> vord_rules_engine::RuleMetadata {
        vord_rules_engine::RuleMetadata {
            description: "A threading primitive constructed directly inside an async function doesn't cooperate with the event loop (e.g. a held threading.Lock blocks the whole loop); use asyncio.to_thread/run_in_executor or the asyncio equivalent primitive instead.".into(),
            tags: vec!["concurrency".into(), "bug".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        let mut out = Vec::new();
        walk(ast, false, &mut out);
        out
    }
}

#[cfg(test)]
mod tests {
    use vord_rules_engine::AstParser;

    use super::*;

    fn findings(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.py", code, LanguageIdentifier::python()).unwrap();
        let ast = vord_parser_python::PythonParser::new()
            .parse(&file)
            .unwrap();
        ThreadingMixedWithAsyncioRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_thread_construction_in_async_function() {
        assert_eq!(
            findings("async def f():\n    t = threading.Thread(target=g)\n    t.start()\n").len(),
            1
        );
    }

    #[test]
    fn flags_threading_lock_in_async_function() {
        assert_eq!(findings("async def f():\n    lock = threading.Lock()\n").len(), 1);
    }

    #[test]
    fn allows_threading_in_sync_function() {
        assert!(findings("def f():\n    t = threading.Thread(target=g)\n    t.start()\n").is_empty());
    }

    #[test]
    fn allows_asyncio_lock_in_async_function() {
        assert!(findings("async def f():\n    lock = asyncio.Lock()\n").is_empty());
    }
}
