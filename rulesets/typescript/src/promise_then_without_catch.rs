//! Rule: flags a `.then(onFulfilled)` promise chain used as a bare
//! statement — nothing awaits it, returns it, or attaches a `.catch()`/
//! second rejection handler — so any rejection becomes an unhandled
//! promise rejection (Node terminates the process by default; browsers log
//! an unactionable console warning). Only the *terminal* call of a
//! statement is checked (`expression_statement`'s sole child): a chain that
//! ends `.then(a).then(b).catch(c)` is fine, since the terminal call there
//! is `.catch`, not `.then`.

use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use yunq_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

use crate::common::{call_arguments, is_other};

fn bare_then_call(stmt: &AstNode) -> Option<&AstNode> {
    if !is_other(stmt, "expression_statement") {
        return None;
    }
    let [call] = stmt.children() else { return None };
    if *call.kind() != NodeKind::Call {
        return None;
    }
    let callee = call.first_child()?;
    if *callee.kind() != NodeKind::MemberAccess {
        return None;
    }
    let property = callee.children().last()?;
    if !(*property.kind() == NodeKind::Identifier && property.text() == "then") {
        return None;
    }
    // A second argument is a rejection handler — the chain is handled.
    (call_arguments(call).len() == 1).then_some(call)
}

pub struct PromiseThenWithoutCatchRule {
    id: RuleId,
}

impl PromiseThenWithoutCatchRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("typescript:promise-then-without-catch").expect("valid rule id"),
        }
    }
}

impl Default for PromiseThenWithoutCatchRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for PromiseThenWithoutCatchRule {
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

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "A `.then(...)` promise chain used as a bare statement with no `.catch()`, second rejection handler, `await`, or `return` turns any rejection into an unhandled promise rejection.".into(),
            tags: vec!["typescript".into(), "reliability".into(), "promise".into()],
            cwe: Some(248),
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter_map(bare_then_call)
            .map(|call| {
                Finding::new(
                    "`.then(...)` with no `.catch()`, second rejection handler, `await`, or `return` leaves rejections unhandled",
                    call.span(),
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
        let file = SourceFile::new("t.ts", code, LanguageIdentifier::typescript()).unwrap();
        let ast = yunq_parser_typescript::TypeScriptParser::new()
            .parse(&file)
            .unwrap();
        PromiseThenWithoutCatchRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_bare_then_with_no_catch() {
        let findings = check("fetchThing().then(x => use(x));\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn allows_then_followed_by_catch() {
        assert!(check("fetchThing().then(x => use(x)).catch(e => log(e));\n").is_empty());
    }

    #[test]
    fn allows_then_with_rejection_handler() {
        assert!(check("fetchThing().then(x => use(x), e => log(e));\n").is_empty());
    }

    #[test]
    fn allows_awaited_then() {
        assert!(check("async function f() { await fetchThing().then(x => use(x)); }\n").is_empty());
    }

    #[test]
    fn allows_returned_then() {
        assert!(check("function f() { return fetchThing().then(x => use(x)); }\n").is_empty());
    }

    #[test]
    fn allows_chain_ending_in_catch() {
        assert!(check("fetchThing().then(a).then(b).catch(c);\n").is_empty());
    }

    #[test]
    fn allows_assigned_then() {
        assert!(check("const p = fetchThing().then(x => use(x));\n").is_empty());
    }
}
