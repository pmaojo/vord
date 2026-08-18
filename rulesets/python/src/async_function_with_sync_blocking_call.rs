//! Rule: flags a synchronous, blocking call made directly inside an
//! `async def` function — `time.sleep(...)`, a `requests` call, or
//! `subprocess.run`/`call`/`check_call`/`check_output`. None of these
//! yield control back to the event loop; one of them inside a coroutine
//! blocks the entire loop (every other task on it) for as long as the
//! call takes, instead of the intended `asyncio.sleep`/async HTTP client.

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

use crate::common::other_kind_name;

const BLOCKING_CALLEES: &[&str] = &[
    "time.sleep",
    "requests.get",
    "requests.post",
    "requests.put",
    "requests.delete",
    "requests.patch",
    "requests.head",
    "requests.request",
    "subprocess.run",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
];

fn is_async_function(node: &AstNode) -> bool {
    *node.kind() == NodeKind::FunctionDef && node.text().trim_start().starts_with("async")
}

fn is_blocking_call(call: &AstNode) -> bool {
    call.first_child()
        .is_some_and(|callee| BLOCKING_CALLEES.contains(&callee.text()))
}

/// Walks the tree tracking whether we're inside an `async def` body and
/// whether the current node sits under an `await` expression (blocking
/// calls under `await` are someone else's problem — `await` only applies
/// to awaitables, so a plain blocking call there is already broken code,
/// not this smell). Descent stops re-arming `in_async` at a *nested*
/// `def`/`lambda` boundary, since a blocking call inside a nested
/// synchronous helper doesn't block the coroutine directly at that call
/// site.
fn walk(node: &AstNode, in_async: bool, out: &mut Vec<Finding>) {
    if in_async && *node.kind() == NodeKind::Call && is_blocking_call(node) {
        out.push(Finding::new(
            "blocking call inside an async function; it stalls the entire event loop for as long as it runs instead of yielding to other tasks. Use the async equivalent (asyncio.sleep, an async HTTP client, asyncio.create_subprocess_exec) instead",
            node.span(),
        ));
    }

    if other_kind_name(node) == Some("await") {
        // Whatever is awaited is not blocking the loop by definition.
        return;
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

pub struct AsyncFunctionWithSyncBlockingCallRule {
    id: RuleId,
}

impl AsyncFunctionWithSyncBlockingCallRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("python:async-function-with-sync-blocking-call").expect("valid rule id"),
        }
    }
}

impl Default for AsyncFunctionWithSyncBlockingCallRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for AsyncFunctionWithSyncBlockingCallRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, lang: &LanguageIdentifier) -> bool {
        *lang == LanguageIdentifier::python()
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
            description: "A synchronous, blocking call inside an async function stalls the entire event loop for as long as it runs, freezing every other task on it; use the async equivalent instead.".into(),
            tags: vec!["bug".into(), "concurrency".into(), "performance".into()],
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
        AsyncFunctionWithSyncBlockingCallRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_time_sleep_in_async_function() {
        assert_eq!(findings("async def f():\n    time.sleep(1)\n").len(), 1);
    }

    #[test]
    fn flags_requests_get_in_async_function() {
        assert_eq!(findings("async def f():\n    requests.get(url)\n").len(), 1);
    }

    #[test]
    fn allows_asyncio_sleep() {
        assert!(findings("async def f():\n    await asyncio.sleep(1)\n").is_empty());
    }

    #[test]
    fn allows_blocking_call_in_sync_function() {
        assert!(findings("def f():\n    time.sleep(1)\n").is_empty());
    }

    #[test]
    fn allows_blocking_call_in_nested_sync_helper() {
        let code = "async def f():\n    def helper():\n        time.sleep(1)\n    helper()\n";
        assert!(findings(code).is_empty());
    }
}
