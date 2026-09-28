//! Rule: flags a long `if`/`else if`/`else if`/... chain — past a handful
//! of branches, a `switch` (or a lookup table/dispatch map) reads far more
//! directly than a cascade of conditionals, since every branch tests the
//! same thing. Mirrors the review comment "Can't this be solved with a
//! switch?" on a long conditional chain.

use std::collections::BTreeSet;

use vord_ast::{AstNode, LanguageIdentifier, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

use crate::common::is_other;

/// Whether `else_clause`'s only content is a single nested `if_statement`
/// (an `else if`, not a plain terminal `else { ... }`).
fn else_if_target(else_clause: &AstNode) -> Option<&AstNode> {
    match else_clause.children() {
        [only] if is_other(only, "if_statement") => Some(only),
        _ => None,
    }
}

/// The number of `if`/`else if` branches in the chain starting at
/// `if_stmt` (a plain terminal `else` at the end doesn't add to the
/// count — it's not a condition being tested).
fn chain_length(if_stmt: &AstNode) -> u32 {
    let mut count = 1;
    let mut current = if_stmt;
    while let Some(else_clause) = current.children().get(2) {
        let Some(next) = else_if_target(else_clause) else {
            break;
        };
        count += 1;
        current = next;
    }
    count
}

pub struct LongIfElseChainRule {
    id: RuleId,
    min_branches: u32,
}

impl LongIfElseChainRule {
    pub fn new(min_branches: u32) -> Self {
        Self {
            id: RuleId::new("typescript:long-if-else-chain").expect("valid rule id"),
            min_branches,
        }
    }
}

impl Default for LongIfElseChainRule {
    fn default() -> Self {
        Self::new(4)
    }
}

impl Rule for LongIfElseChainRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, lang: &LanguageIdentifier) -> bool {
        *lang == LanguageIdentifier::typescript()
    }

    fn default_severity(&self) -> Severity {
        Severity::Minor
    }

    fn issue_type(&self) -> IssueType {
        IssueType::CodeSmell
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "A long `if`/`else if` chain tests the same thing branch after branch; a `switch` (or a lookup table) reads more directly once there are more than a few branches.".into(),
            tags: vec!["typescript".into(), "readability".into(), "complexity".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        if vord_rules_engine::is_test_only_path(file.path()) {
            return Vec::new();
        }

        // An `if_statement` reached as some other `if_statement`'s `else
        // if` target is a continuation, not a chain head; skip it so a
        // 5-branch chain isn't reported once per branch. `Span` has no
        // `Ord`/`Hash`, so its four fields are keyed as a tuple instead.
        let span_key = |s: vord_ast::Span| (s.start_line, s.start_col, s.end_line, s.end_col);
        let continuations: BTreeSet<(u32, u32, u32, u32)> = ast
            .descendants()
            .filter(|n| is_other(n, "else_clause"))
            .filter_map(else_if_target)
            .map(|n| span_key(n.span()))
            .collect();

        ast.descendants()
            .filter(|n| is_other(n, "if_statement"))
            .filter(|n| !continuations.contains(&span_key(n.span())))
            .filter_map(|head| {
                let len = chain_length(head);
                (len >= self.min_branches).then_some((head, len))
            })
            .map(|(head, len)| {
                Finding::new(
                    format!(
                        "{len}-branch `if`/`else if` chain; consider a `switch` (or a lookup table) instead"
                    ),
                    head.span(),
                )
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vord_rules_engine::AstParser;

    fn check(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.ts", code, LanguageIdentifier::typescript()).unwrap();
        let ast = vord_parser_typescript::TypeScriptParser::new()
            .parse(&file)
            .unwrap();
        LongIfElseChainRule::default().check(&file, &ast)
    }

    #[test]
    fn flags_a_four_branch_chain() {
        let findings = check("if (a) {} else if (b) {} else if (c) {} else if (d) {} else {}\n");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("4-branch"));
    }

    #[test]
    fn allows_a_short_chain() {
        let findings = check("if (a) {} else if (b) {} else {}\n");
        assert!(findings.is_empty());
    }

    #[test]
    fn allows_a_plain_if_with_no_else() {
        let findings = check("if (a) { doThing(); }\n");
        assert!(findings.is_empty());
    }

    #[test]
    fn flags_the_chain_once_not_once_per_branch() {
        let findings = check(
            "if (a) {} else if (b) {} else if (c) {} else if (d) {} else if (e) {} else {}\n",
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn independent_chains_are_each_evaluated() {
        let findings = check(
            "if (a) {} else if (b) {}\nfunction f() {\n  if (c) {} else if (d) {} else if (e) {} else if (f) {}\n}\n",
        );
        assert_eq!(findings.len(), 1);
    }
}
