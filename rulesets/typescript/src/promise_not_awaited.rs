//! Rule: flags a bare-statement call to a function declared `async` in the
//! same file, made without `await`, `.then`, `.catch`, `return`, or
//! assignment. Calling a same-file async function this way silently starts
//! it and ignores both its result and any rejection — the same problem
//! `promise_then_without_catch` covers for `.then()` chains, but for direct
//! async-function calls.
//!
//! Narrowed deliberately to *locally declared* async functions: without a
//! type checker there is no reliable way to know whether an arbitrary call
//! expression returns a `Promise`, and guessing from naming conventions
//! alone would be noisy. Seeing the callee's own `async function` /
//! `async` method declaration in the same file is the one case this
//! analyzer can confirm.

use std::collections::HashSet;

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

use crate::common::is_other;

/// Whether `func`'s own text (its keywords, not its body) is an `async
/// function` declaration/expression — as opposed to an `async` arrow
/// function or class method, which don't use the `function` keyword.
/// `NodeKind::FunctionDef` collapses all four grammar kinds into one, so
/// this is the only way left to tell them apart without the original
/// tree-sitter kind name.
fn is_async_function_keyword_form(func: &AstNode) -> bool {
    let text = func.text().trim_start();
    let Some(rest) = text.strip_prefix("async") else {
        return false;
    };
    rest.trim_start().starts_with("function")
}

/// Names of top-level `async function name(...)` declarations and
/// `const name = async (...) => ...` bindings in this file — the two
/// shapes a later bare `name(...)` call can unambiguously be resolved back
/// to.
fn local_async_function_names(ast: &AstNode) -> HashSet<&str> {
    ast.descendants()
        .filter_map(|n| {
            if *n.kind() == NodeKind::FunctionDef && is_async_function_keyword_form(n) {
                return n.first_child().filter(|id| *id.kind() == NodeKind::Identifier);
            }
            if *n.kind() == NodeKind::VariableDecl {
                let [name, value] = n.children() else { return None };
                if *name.kind() == NodeKind::Identifier
                    && *value.kind() == NodeKind::FunctionDef
                    && value.text().trim_start().starts_with("async")
                {
                    return Some(name);
                }
            }
            None
        })
        .map(|id| id.text())
        .collect()
}

fn bare_unawaited_call<'a>(stmt: &'a AstNode, names: &HashSet<&str>) -> Option<&'a AstNode> {
    if !is_other(stmt, "expression_statement") {
        return None;
    }
    let [call] = stmt.children() else { return None };
    if *call.kind() != NodeKind::Call {
        return None;
    }
    let callee = call.first_child()?;
    (*callee.kind() == NodeKind::Identifier && names.contains(callee.text())).then_some(call)
}

pub struct PromiseNotAwaitedRule {
    id: RuleId,
}

impl PromiseNotAwaitedRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("typescript:promise-not-awaited").expect("valid rule id"),
        }
    }
}

impl Default for PromiseNotAwaitedRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for PromiseNotAwaitedRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, lang: &LanguageIdentifier) -> bool {
        *lang == LanguageIdentifier::typescript()
    }

    fn default_severity(&self) -> Severity {
        Severity::Major
    }

    fn issue_type(&self) -> IssueType {
        IssueType::Bug
    }

    fn remediation_effort_minutes(&self) -> u32 {
        5
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "This calls a local `async` function as a bare statement, with no `await`, `.then()`, or `return`. Its result is discarded and any rejection becomes an unhandled promise rejection.".into(),
            tags: vec!["typescript".into(), "reliability".into(), "promise".into()],
            cwe: Some(248),
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        let names = local_async_function_names(ast);
        if names.is_empty() {
            return Vec::new();
        }
        ast.descendants()
            .filter_map(|n| bare_unawaited_call(n, &names))
            .map(|n| {
                Finding::new(
                    format!(
                        "`{}` is an async function called here without `await`; its result and any rejection are silently dropped",
                        n.first_child().map(|c| c.text()).unwrap_or_default()
                    ),
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
        let file = SourceFile::new("t.ts", code, LanguageIdentifier::typescript()).unwrap();
        let ast = vord_parser_typescript::TypeScriptParser::new()
            .parse(&file)
            .unwrap();
        PromiseNotAwaitedRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_bare_call_to_local_async_function() {
        let code = "async function load() { return 1; }\nfunction use() {\n  load();\n}\n";
        assert_eq!(check(code).len(), 1);
    }

    #[test]
    fn allows_awaited_call() {
        let code = "async function load() { return 1; }\nasync function use() {\n  await load();\n}\n";
        assert!(check(code).is_empty());
    }

    #[test]
    fn allows_returned_call() {
        let code = "async function load() { return 1; }\nfunction use() {\n  return load();\n}\n";
        assert!(check(code).is_empty());
    }

    #[test]
    fn allows_assigned_call() {
        let code = "async function load() { return 1; }\nfunction use() {\n  const p = load();\n  return p;\n}\n";
        assert!(check(code).is_empty());
    }

    #[test]
    fn allows_then_chained_call() {
        let code = "async function load() { return 1; }\nfunction use() {\n  load().then(x => x);\n}\n";
        assert!(check(code).is_empty());
    }

    #[test]
    fn allows_call_to_non_async_function() {
        let code = "function load() { return 1; }\nfunction use() {\n  load();\n}\n";
        assert!(check(code).is_empty());
    }
}
