//! Rule: flags a `defer` statement inside a `for` loop's body. `defer`
//! always runs at the *enclosing function's* return, not at the end of the
//! loop iteration that scheduled it — so a `defer resp.Body.Close()` (or
//! any other cleanup call) inside a loop that runs N times piles up N
//! pending closes/unlocks/frees that all fire together when the function
//! finally returns, not as each iteration finishes, which is both a
//! resource leak for the loop's duration and, for something like a mutex
//! unlock, a correctness risk. Move the deferred call into a helper
//! function called once per iteration instead, so its own `defer` fires at
//! the end of that call.

use yunq_ast::{AstNode, LanguageIdentifier, SourceFile};
use yunq_rules_engine::{
    Finding, IssueType, Rule, RuleId, RuleMetadata, Severity, declare_rule_id,
};

use crate::common::{collect_bounded, is_other, loop_body};

fn is_for_statement(node: &AstNode) -> bool {
    is_other(node.kind(), "for_statement")
}

fn is_defer_statement(node: &AstNode) -> bool {
    is_other(node.kind(), "defer_statement")
}

declare_rule_id!(DeferInLoopRule, "go:defer-in-loop");

impl Rule for DeferInLoopRule {
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
        IssueType::CodeSmell
    }

    fn remediation_effort_minutes(&self) -> u32 {
        15
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "`defer` inside a loop body runs at the enclosing function's return, \
                not at the end of each iteration; every deferred call accumulates until then. \
                Move the deferred call into a per-iteration helper function instead."
                .into(),
            tags: vec!["go".into(), "resource-leak".into()],
            cwe: Some(772),
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter(|n| is_for_statement(n))
            .filter_map(loop_body)
            .flat_map(|body| {
                let mut out = Vec::new();
                collect_bounded(body, is_defer_statement, &mut out);
                out
            })
            .map(|defer_stmt| {
                Finding::new(
                    "`defer` inside a loop body doesn't run until the enclosing function \
                    returns, not at the end of this iteration; call it from a per-iteration \
                    helper function instead"
                        .to_string(),
                    defer_stmt.span(),
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
        DeferInLoopRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_defer_directly_in_loop_body() {
        assert_eq!(
            check("package main\nfunc f(files []string) {\n\tfor _, name := range files {\n\t\tf, _ := os.Open(name)\n\t\tdefer f.Close()\n\t}\n}\n")
                .len(),
            1
        );
    }

    #[test]
    fn ignores_defer_outside_any_loop() {
        assert!(
            check("package main\nfunc f() {\n\tf, _ := os.Open(\"x\")\n\tdefer f.Close()\n}\n")
                .is_empty()
        );
    }

    #[test]
    fn ignores_defer_inside_nested_closure() {
        // The closure's own defer fires when the closure returns, not when
        // the enclosing loop's function returns — a different, unproblematic
        // scope.
        assert!(check(
            "package main\nfunc f(files []string) {\n\tfor _, name := range files {\n\t\tfunc() {\n\t\t\tf, _ := os.Open(name)\n\t\t\tdefer f.Close()\n\t\t}()\n\t}\n}\n"
        )
        .is_empty());
    }

    #[test]
    fn attributes_nested_loop_defer_to_the_inner_loop_only() {
        let findings = check(
            "package main\nfunc f(files [][]string) {\n\tfor _, group := range files {\n\t\tfor _, name := range group {\n\t\t\tf, _ := os.Open(name)\n\t\t\tdefer f.Close()\n\t\t}\n\t}\n}\n",
        );
        assert_eq!(findings.len(), 1);
    }
}
