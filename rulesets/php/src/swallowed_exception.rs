//! Rule: flags a `catch` block that is empty, or whose body does nothing
//! but `error_log()` the error, with no re-throw and no other handling.
//! Mirrors `typescript:swallowed-exception` and Python's `bare-except`/
//! `broad-exception-swallowed`: the error is observed and then discarded,
//! hiding a real failure from callers.

use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use yunq_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

use crate::common::is_other;

fn is_error_log_call(call: &AstNode) -> bool {
    call.first_child().is_some_and(|callee| {
        *callee.kind() == NodeKind::Identifier && callee.text() == "error_log"
    })
}

/// Every top-level statement inside a PHP `compound_statement` is an
/// `expression_statement`, which this parser's `map_kind` folds into
/// `NodeKind::Assignment` alongside real assignments (see
/// `rulesets/php/src/common.rs` for the same quirk documented against
/// `callee_node`) — so a bare `error_log(...)` statement surfaces as an
/// `Assignment` node with exactly one child, the `Call` itself.
fn is_error_log_only_statement(stmt: &AstNode) -> bool {
    *stmt.kind() == NodeKind::Assignment
        && stmt.children().len() == 1
        && *stmt.children()[0].kind() == NodeKind::Call
        && is_error_log_call(&stmt.children()[0])
}

/// `throw` is likewise not its own top-level `NodeKind`: `throw $e;` is an
/// `Assignment`-wrapped `Other("throw_expression")`.
fn has_throw(block: &AstNode) -> bool {
    block
        .descendants()
        .any(|n| is_other(n.kind(), "throw_expression"))
}

fn is_swallowed(catch_clause: &AstNode) -> bool {
    let Some(block) = catch_clause
        .children()
        .iter()
        .find(|c| is_other(c.kind(), "compound_statement"))
    else {
        return false;
    };
    if has_throw(block) {
        return false;
    }
    block.children().is_empty() || block.children().iter().all(is_error_log_only_statement)
}

pub struct SwallowedExceptionRule {
    id: RuleId,
}

impl SwallowedExceptionRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("php:swallowed-exception").expect("valid rule id"),
        }
    }
}

impl Default for SwallowedExceptionRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for SwallowedExceptionRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, language: &LanguageIdentifier) -> bool {
        *language == LanguageIdentifier::php()
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

    fn metadata(&self) -> yunq_rules_engine::RuleMetadata {
        yunq_rules_engine::RuleMetadata {
            description: "A catch block that is empty or only logs the error hides a real failure instead of handling it; log with context and recover, or re-throw.".into(),
            tags: vec!["bug".into(), "error-handling".into()],
            cwe: Some(390),
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter(|n| is_other(n.kind(), "catch_clause"))
            .filter(|n| is_swallowed(n))
            .map(|n| {
                Finding::new(
                    "exception is caught and silently discarded (empty, or only logged); handle it, re-throw it, or remove the catch",
                    n.span(),
                )
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use yunq_rules_engine::AstParser;

    use super::*;

    fn findings(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.php", code, LanguageIdentifier::php()).unwrap();
        let ast = yunq_parser_php::PhpParser::new().parse(&file).unwrap();
        SwallowedExceptionRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_empty_catch() {
        let code = "<?php\ntry {\n    doWork();\n} catch (Exception $e) {\n}\n";
        assert_eq!(findings(code).len(), 1);
    }

    #[test]
    fn flags_error_log_only_catch() {
        let code = "<?php\ntry {\n    doWork();\n} catch (Exception $e) {\n    error_log($e->getMessage());\n}\n";
        assert_eq!(findings(code).len(), 1);
    }

    #[test]
    fn allows_catch_that_rethrows_after_logging() {
        let code = "<?php\ntry {\n    doWork();\n} catch (Exception $e) {\n    error_log($e->getMessage());\n    throw $e;\n}\n";
        assert!(findings(code).is_empty());
    }

    #[test]
    fn allows_catch_with_other_handling() {
        let code = "<?php\ntry {\n    doWork();\n} catch (Exception $e) {\n    error_log($e->getMessage());\n    $this->setErrorState($e);\n}\n";
        assert!(findings(code).is_empty());
    }

    #[test]
    fn allows_catch_that_calls_non_error_log_function_only() {
        let code = "<?php\ntry {\n    doWork();\n} catch (Exception $e) {\n    handle($e);\n}\n";
        assert!(findings(code).is_empty());
    }
}
