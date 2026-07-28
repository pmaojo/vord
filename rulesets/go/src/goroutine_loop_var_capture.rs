//! Rule: flags `go func() { ... }()` — a parameterless func literal
//! launched with `go` — whose body directly references its enclosing
//! C-style `for` loop's own loop variable, with no by-value parameter
//! passing it in. Before Go 1.22 every iteration shared one loop-variable
//! storage location, so a goroutine that hadn't run yet by the time the
//! next iteration started would observe a later (often the final) value —
//! the single most common real-world Go concurrency bug, and the reason Go
//! 1.22 changed the language's own per-iteration variable semantics.
//!
//! A security hotspot rather than an unconditional bug: on a project
//! actually targeting Go 1.22+, this exact shape is safe and idiomatic —
//! whether it's a bug at all depends on the module's `go.mod` directive,
//! which this same-file syntactic rule doesn't read. Flagged for review
//! either way, since even on 1.22+ a reviewer benefits from confirming that
//! was the intended, understood behavior. Scoped to the classic C-style
//! `for i := ...; ...; ... {}` clause only — `for range` loops (which
//! share the exact same pre-1.22 pitfall) are a distinct grammar shape
//! (`range_clause`) not handled here, a known gap for a follow-up rule.

use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use yunq_rules_engine::{declare_rule_id, Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

use crate::common::{collect_bounded, is_other, loop_body};

fn is_go_statement(node: &AstNode) -> bool {
    is_other(node.kind(), "go_statement")
}

/// The single name a C-style `for`'s own `init` clause declares
/// (`for i := 0; ...`), or `None` for a `range`-clause loop or a `for` with
/// no init at all — both fall outside this rule's scope.
fn for_clause_loop_var(loop_node: &AstNode) -> Option<&str> {
    let clause = loop_node.children().first()?;
    if !is_other(clause.kind(), "for_clause") {
        return None;
    }
    let decl = clause.children().first()?;
    if *decl.kind() != NodeKind::VariableDecl {
        return None;
    }
    let names = decl.children().first()?;
    let [name] = names.children() else { return None };
    (*name.kind() == NodeKind::Identifier).then(|| name.text())
}

/// The body of a `go func() { ... }()` launched with no parameters — the
/// shape that captures its surrounding scope by reference rather than
/// taking a value explicitly — or `None` for `go func(i int) { ... }(i)`,
/// which already passes the loop variable in by value and is unaffected
/// either way.
fn parameterless_closure_body(go_stmt: &AstNode) -> Option<&AstNode> {
    let call = go_stmt.children().first()?;
    if *call.kind() != NodeKind::Call {
        return None;
    }
    let func_literal = call.children().first()?;
    if *func_literal.kind() != NodeKind::FunctionDef {
        return None;
    }
    let [params, block] = func_literal.children() else { return None };
    params.children().is_empty().then_some(block)
}

fn references_identifier(node: &AstNode, name: &str) -> bool {
    node.descendants().any(|n| *n.kind() == NodeKind::Identifier && n.text() == name)
}

declare_rule_id!(GoroutineLoopVarCaptureRule, "go:goroutine-loop-var-capture");

impl Rule for GoroutineLoopVarCaptureRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, language: &LanguageIdentifier) -> bool {
        *language == LanguageIdentifier::go()
    }

    fn default_severity(&self) -> Severity {
        Severity::Major
    }

    fn issue_type(&self) -> IssueType {
        IssueType::Bug
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "A goroutine launched with no parameters that references the \
                enclosing for loop's own loop variable captures it by reference; before Go \
                1.22 every iteration shared one storage location, so the goroutine can observe \
                a later iteration's value. Safe on Go 1.22+, but confirm the module actually \
                targets it — otherwise pass the value in as a parameter (`go func(i int) \
                {...}(i)`)."
                .into(),
            tags: vec!["go".into(), "concurrency".into()],
            cwe: Some(362),
            produces_hotspots: true,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter(|n| is_other(n.kind(), "for_statement"))
            .filter_map(|loop_node| Some((for_clause_loop_var(loop_node)?, loop_body(loop_node)?)))
            .flat_map(|(var, body)| {
                let mut go_stmts = Vec::new();
                collect_bounded(body, is_go_statement, &mut go_stmts);
                go_stmts
                    .into_iter()
                    .filter(move |g| {
                        parameterless_closure_body(g).is_some_and(|b| references_identifier(b, var))
                    })
                    .collect::<Vec<_>>()
            })
            .map(|go_stmt| {
                Finding::hotspot(
                    "this goroutine captures the enclosing loop variable by reference instead of \
                    taking it as a parameter; confirm this module targets Go 1.22+ (per-iteration \
                    loop variables), otherwise every goroutine can observe a later iteration's value",
                    go_stmt.span(),
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
        let file = SourceFile::new("t.go", code, LanguageIdentifier::go()).unwrap();
        let ast = yunq_parser_go::GoParser::new().parse(&file).unwrap();
        GoroutineLoopVarCaptureRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_parameterless_closure_referencing_loop_var() {
        assert_eq!(
            check("package main\nfunc f() {\n\tfor i := 0; i < 10; i++ {\n\t\tgo func() { println(i) }()\n\t}\n}\n")
                .len(),
            1
        );
    }

    #[test]
    fn allows_loop_var_passed_as_parameter() {
        assert!(check(
            "package main\nfunc f() {\n\tfor i := 0; i < 10; i++ {\n\t\tgo func(i int) { println(i) }(i)\n\t}\n}\n"
        )
        .is_empty());
    }

    #[test]
    fn ignores_closure_not_referencing_the_loop_var() {
        assert!(check(
            "package main\nfunc f() {\n\tfor i := 0; i < 10; i++ {\n\t\tgo func() { println(\"tick\") }()\n\t}\n}\n"
        )
        .is_empty());
    }

    #[test]
    fn ignores_goroutine_outside_any_loop() {
        assert!(check("package main\nfunc f() {\n\ti := 1\n\tgo func() { println(i) }()\n}\n").is_empty());
    }
}
