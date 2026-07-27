//! Rule: flags a `catch` block that is empty, or whose body does nothing
//! but `console.log`/`console.error`/... the error, with no re-throw and no
//! other handling. Mirrors SonarQube's S108 and `python:broad-exception-
//! swallowed`/`python:bare-except` for this language: the error is
//! observed and then discarded, hiding a real failure from callers.

use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use yunq_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

use crate::common::is_other;

fn is_console_call(call: &AstNode) -> bool {
    call.first_child().is_some_and(|callee| {
        *callee.kind() == NodeKind::MemberAccess
            && callee.first_child().is_some_and(|base| base.text() == "console")
    })
}

fn is_console_only_statement(stmt: &AstNode) -> bool {
    is_other(stmt, "expression_statement")
        && stmt.children().len() == 1
        && *stmt.children()[0].kind() == NodeKind::Call
        && is_console_call(&stmt.children()[0])
}

fn has_throw(block: &AstNode) -> bool {
    block.descendants().any(|n| is_other(n, "throw_statement"))
}

fn is_swallowed(catch_clause: &AstNode) -> bool {
    let Some(block) = catch_clause.children().iter().find(|c| is_other(c, "statement_block")) else {
        return false;
    };
    if has_throw(block) {
        return false;
    }
    block.children().is_empty() || block.children().iter().all(is_console_only_statement)
}

pub struct SwallowedExceptionRule {
    id: RuleId,
}

impl SwallowedExceptionRule {
    pub fn new() -> Self {
        Self { id: RuleId::new("typescript:swallowed-exception").expect("valid rule id") }
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
        *language == LanguageIdentifier::typescript()
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
            .filter(|n| is_other(n, "catch_clause"))
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
        let file = SourceFile::new("t.ts", code, LanguageIdentifier::typescript()).unwrap();
        let ast = yunq_parser_typescript::TypeScriptParser::new().parse(&file).unwrap();
        SwallowedExceptionRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_empty_catch() {
        assert_eq!(findings("try {\n  doWork();\n} catch (e) {\n}\n").len(), 1);
    }

    #[test]
    fn flags_bare_empty_catch() {
        assert_eq!(findings("try {\n  doWork();\n} catch {\n}\n").len(), 1);
    }

    #[test]
    fn flags_console_log_only_catch() {
        assert_eq!(findings("try {\n  doWork();\n} catch (e) {\n  console.log(e);\n}\n").len(), 1);
    }

    #[test]
    fn flags_console_error_only_catch() {
        assert_eq!(findings("try {\n  doWork();\n} catch (e) {\n  console.error(e);\n}\n").len(), 1);
    }

    #[test]
    fn allows_catch_that_rethrows_after_logging() {
        assert!(findings(
            "try {\n  doWork();\n} catch (e) {\n  console.log(e);\n  throw e;\n}\n"
        )
        .is_empty());
    }

    #[test]
    fn allows_catch_with_other_handling() {
        assert!(findings(
            "try {\n  doWork();\n} catch (e) {\n  logger.error(\"failed\", e);\n  setErrorState(e);\n}\n"
        )
        .is_empty());
    }

    #[test]
    fn allows_catch_that_calls_non_console_logger_only() {
        // A single non-console call is treated as real handling, not a
        // pure log-and-swallow, since it isn't necessarily just logging.
        assert!(findings("try {\n  doWork();\n} catch (e) {\n  handle(e);\n}\n").is_empty());
    }
}
