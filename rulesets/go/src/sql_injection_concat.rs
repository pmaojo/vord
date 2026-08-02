//! Rule: flags a `database/sql`-shaped query call (`.Query`/`.QueryContext`/
//! `.QueryRow`/`.QueryRowContext`/`.Exec`/`.ExecContext`/`.Prepare`/
//! `.PrepareContext` — method names shared across `database/sql`, `sqlx` and
//! `pgx`) whose query-string argument is built by `+` concatenation or
//! `fmt.Sprintf` instead of a parameterized placeholder. No generic OWASP
//! rule covers this for Go today: `owasp:injection`'s taint analysis is
//! TypeScript-only (per the roadmap's own note), so this closes the same
//! gap `php:sql-injection-concat`/`python:sql-injection-string-building`
//! close for their languages.

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{
    Finding, IssueType, Rule, RuleId, RuleMetadata, Severity, declare_rule_id,
};

use crate::common::{arguments, callee, callee_name, is_other, operator_between};

const METHOD_SINKS: &[&str] = &[
    "Query",
    "QueryContext",
    "QueryRow",
    "QueryRowContext",
    "Exec",
    "ExecContext",
    "Prepare",
    "PrepareContext",
];

fn is_sink_call(call: &AstNode) -> bool {
    callee(call).is_some_and(|c| {
        *c.kind() == NodeKind::MemberAccess
            && callee_name(c).is_some_and(|n| METHOD_SINKS.contains(&n))
    })
}

fn is_plus_concat(node: &AstNode, source: &str) -> bool {
    is_other(node.kind(), "binary_expression")
        && match node.children() {
            [left, right] => operator_between(source, left, right) == "+",
            _ => false,
        }
}

fn is_sprintf_call(node: &AstNode) -> bool {
    *node.kind() == NodeKind::Call && callee(node).is_some_and(|c| c.text() == "fmt.Sprintf")
}

fn built_unsafely(arg: &AstNode, source: &str) -> bool {
    arg.descendants()
        .any(|n| is_plus_concat(n, source) || is_sprintf_call(n))
}

declare_rule_id!(SqlInjectionConcatRule, "go:sql-injection-concat");

impl Rule for SqlInjectionConcatRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, language: &LanguageIdentifier) -> bool {
        *language == LanguageIdentifier::go()
    }

    fn default_severity(&self) -> Severity {
        Severity::Blocker
    }

    fn issue_type(&self) -> IssueType {
        IssueType::Vulnerability
    }

    fn remediation_effort_minutes(&self) -> u32 {
        20
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "Building a SQL query by concatenating a value into the string (`+` or \
                `fmt.Sprintf`) before executing it is SQL injection if that value is ever \
                influenced by external input; use a parameterized query (`?`/`$1` placeholders \
                bound as separate `Query`/`Exec` arguments) instead."
                .into(),
            tags: vec!["security".into(), "injection".into(), "go".into()],
            cwe: Some(89),
            produces_hotspots: false,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter(|n| *n.kind() == NodeKind::Call)
            .filter(|call| is_sink_call(call))
            .filter(|call| {
                arguments(call)
                    .is_some_and(|args| args.iter().any(|arg| built_unsafely(arg, file.content())))
            })
            .map(|call| {
                Finding::new(
                    "query is built by concatenating a value directly into the SQL text \
                    (`+` or `fmt.Sprintf`); use a parameterized query instead"
                        .to_string(),
                    call.span(),
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
        let file = SourceFile::new("t.go", code, LanguageIdentifier::go()).unwrap();
        let ast = vord_parser_go::GoParser::new().parse(&file).unwrap();
        SqlInjectionConcatRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_query_built_by_plus_concat() {
        assert_eq!(
            check(
                "package main\nfunc f(db *sql.DB, id string) {\n\tdb.Query(\"SELECT * FROM t WHERE id=\" + id)\n}\n"
            )
            .len(),
            1
        );
    }

    #[test]
    fn flags_exec_built_by_sprintf() {
        assert_eq!(
            check(
                "package main\nfunc f(db *sql.DB, id string) {\n\tdb.Exec(fmt.Sprintf(\"DELETE FROM t WHERE id=%s\", id))\n}\n"
            )
            .len(),
            1
        );
    }

    #[test]
    fn flags_query_row_context() {
        assert_eq!(
            check(
                "package main\nfunc f(db *sql.DB, id string) {\n\tdb.QueryRowContext(ctx, \"SELECT * FROM t WHERE id=\" + id)\n}\n"
            )
            .len(),
            1
        );
    }

    #[test]
    fn allows_parameterized_query() {
        assert!(check(
            "package main\nfunc f(db *sql.DB, id string) {\n\tdb.Query(\"SELECT * FROM t WHERE id = ?\", id)\n}\n"
        )
        .is_empty());
    }

    #[test]
    fn ignores_unrelated_calls() {
        assert!(
            check("package main\nfunc f(id string) {\n\tstrings.ToLower(\"a\" + id)\n}\n")
                .is_empty()
        );
    }
}
