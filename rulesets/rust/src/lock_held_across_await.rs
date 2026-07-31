use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile, Span};
use yunq_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

use crate::common::is_other;

/// Whether `decl`'s initializer chain calls `.lock(` anywhere (`m.lock()`,
/// `m.lock().unwrap()`, ...) — the identifying shape of taking a
/// `Mutex`/`RwLock` guard.
fn locks_a_mutex(decl: &AstNode) -> bool {
    decl.descendants()
        .any(|n| *n.kind() == NodeKind::MemberAccess && n.text().rsplit('.').next() == Some("lock"))
}

/// Whether the guard is taken from an *async* lock — `m.lock().await`
/// rather than `m.lock()`/`m.lock().unwrap()`.
///
/// `tokio::sync::Mutex`/`RwLock` exist precisely so a guard *can* be held
/// across an `.await`: their `lock()` is itself a future, and the tokio
/// docs direct you to them for exactly the case where the lock must
/// survive an await point. Holding one across `.await` is the intended
/// design, not the defect this rule looks for — the defect is a
/// *blocking* `std::sync`/`parking_lot` guard, which parks the OS thread
/// and can deadlock the executor. Awaiting the acquisition is what tells
/// the two apart.
fn awaits_the_lock(decl: &AstNode) -> bool {
    decl.descendants().any(|node| {
        is_other(node.kind(), "await_expression")
            && node.descendants().any(|inner| {
                *inner.kind() == NodeKind::MemberAccess
                    && inner.text().rsplit('.').next() == Some("lock")
            })
    })
}

fn declared_identifier(decl: &AstNode) -> Option<&str> {
    decl.children()
        .iter()
        .find(|c| *c.kind() == NodeKind::Identifier)
        .map(AstNode::text)
}

/// The name `drop(..)` releases, if `stmt` is (or wraps) exactly that call.
fn dropped_name(stmt: &AstNode) -> Option<&str> {
    let call = if *stmt.kind() == NodeKind::Call {
        stmt
    } else if is_other(stmt.kind(), "expression_statement") {
        stmt.first_child().filter(|c| *c.kind() == NodeKind::Call)?
    } else {
        return None;
    };
    let callee = call.first_child()?;
    if *callee.kind() != NodeKind::Identifier || callee.text() != "drop" {
        return None;
    }
    let args = call
        .children()
        .iter()
        .find(|c| is_other(c.kind(), "arguments"))?;
    let [arg] = args.children() else { return None };
    (*arg.kind() == NodeKind::Identifier).then(|| arg.text())
}

/// Every `await_expression` reachable from `node`, without crossing into a
/// nested function or closure (a `.await` inside a spawned closure runs in
/// its own task, not while the enclosing scope's lock guard is alive).
fn collect_awaits<'a>(node: &'a AstNode, out: &mut Vec<&'a AstNode>) {
    for child in node.children() {
        if *child.kind() == NodeKind::FunctionDef {
            continue;
        }
        if is_other(child.kind(), "await_expression") {
            out.push(child);
        }
        collect_awaits(child, out);
    }
}

/// Scans one block's direct statements in order, tracking which
/// lock-guard-bearing locals are still alive (not yet passed to `drop`) and
/// flagging any `.await` reached while at least one is held.
fn scan_block(block: &AstNode) -> Vec<Span> {
    let mut held: Vec<&str> = Vec::new();
    let mut spans = Vec::new();
    for stmt in block.children() {
        if let Some(name) = dropped_name(stmt) {
            held.retain(|h| *h != name);
        }
        if !held.is_empty() {
            let mut awaits = Vec::new();
            collect_awaits(stmt, &mut awaits);
            spans.extend(awaits.into_iter().map(AstNode::span));
        }
        if *stmt.kind() == NodeKind::VariableDecl && locks_a_mutex(stmt) && !awaits_the_lock(stmt) {
            if let Some(name) = declared_identifier(stmt) {
                held.push(name);
            }
        }
    }
    spans
}

/// A `MutexGuard`/`RwLockReadGuard`/`RwLockWriteGuard` bound with `let g =
/// m.lock()...` and still alive across a later `.await` point in the same
/// block keeps the lock held for the whole time the task is suspended —
/// every other task waiting on that lock stalls until this one is polled
/// again and finally drops the guard. Drop the guard (explicitly, or by
/// scoping it in a block) before the `.await`.
pub struct LockHeldAcrossAwaitRule {
    id: RuleId,
}

impl LockHeldAcrossAwaitRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("rust:lock-held-across-await").expect("valid rule id"),
        }
    }
}

impl Default for LockHeldAcrossAwaitRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for LockHeldAcrossAwaitRule {
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
            description: "A lock guard still alive across an `.await` point keeps the lock held \
                for the whole time the task is suspended, stalling every other task waiting on \
                it. Drop the guard before awaiting."
                .into(),
            tags: vec!["concurrency".into(), "async".into(), "rust".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter(|n| is_other(n.kind(), "block"))
            .flat_map(scan_block)
            .map(|span| {
                Finding::new(
                    "a lock guard taken earlier in this block is still held across this \
                    `.await`, stalling any other task waiting on the same lock"
                        .to_string(),
                    span,
                )
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
        LockHeldAcrossAwaitRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_guard_held_across_await() {
        let findings = check(
            "async fn f(m: std::sync::Mutex<i32>) { let g = m.lock().unwrap(); other().await; drop(g); }\n",
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn ignores_a_tokio_async_lock_held_across_await() {
        // The regression this guards: `tokio::sync::Mutex` exists so a
        // guard *can* be held across `.await` — its `lock()` is a future,
        // and tokio's own docs point you at it for exactly this case.
        // Flagging it reported correct, idiomatic async code as a CRITICAL
        // bug (it fired on this repo's own test helpers and failed the
        // quality gate). Awaiting the acquisition is what distinguishes it
        // from a blocking `std::sync` guard.
        assert!(check(
            "async fn f(m: tokio::sync::Mutex<i32>) { let g = m.lock().await; other().await; drop(g); }\n"
        )
        .is_empty());
    }

    #[test]
    fn still_flags_a_blocking_guard_in_a_function_that_also_awaits_a_lock() {
        // The guard on the exemption above: an awaited lock elsewhere in
        // the function must not excuse a genuinely blocking guard.
        let findings = check(
            "async fn f(a: tokio::sync::Mutex<i32>, b: std::sync::Mutex<i32>) { let x = a.lock().await; let g = b.lock().unwrap(); other().await; }\n",
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn ignores_guard_dropped_before_await() {
        assert!(check(
            "async fn f(m: std::sync::Mutex<i32>) { let g = m.lock().unwrap(); drop(g); other().await; }\n"
        )
        .is_empty());
    }

    #[test]
    fn ignores_guard_dropped_via_scope_before_await() {
        assert!(check(
            "async fn f(m: std::sync::Mutex<i32>) { { let g = m.lock().unwrap(); use_it(g); } other().await; }\n"
        )
        .is_empty());
    }

    #[test]
    fn ignores_await_with_no_lock_taken() {
        assert!(check("async fn f() { other().await; }\n").is_empty());
    }

    #[test]
    fn ignores_await_inside_spawned_closure() {
        assert!(check(
            "async fn f(m: std::sync::Mutex<i32>) { let g = m.lock().unwrap(); spawn(|| async { other().await; }); drop(g); }\n"
        )
        .is_empty());
    }
}
