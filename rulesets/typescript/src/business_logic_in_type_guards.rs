//! Rule: flags a user-defined type guard (`function f(x): x is T`) whose
//! body does more than a small, focused shape check. A type guard's return
//! value drives the compiler's control-flow narrowing, so callers trust it
//! completely and unconditionally — burying side effects, unrelated
//! branching, or real business logic inside one makes the guard's true
//! behavior easy to miss and hard to audit at every call site that relies
//! on it for narrowing.

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

use crate::common::is_other;

const STATEMENT_THRESHOLD: usize = 4;

fn has_type_predicate(func: &AstNode) -> bool {
    func.children()
        .iter()
        .any(|c| is_other(c, "type_predicate_annotation"))
}

fn statement_count(func: &AstNode) -> Option<usize> {
    let body = func
        .children()
        .iter()
        .find(|c| is_other(c, "statement_block"))?;
    Some(body.children().len())
}

fn flagged(node: &AstNode) -> bool {
    *node.kind() == NodeKind::FunctionDef
        && has_type_predicate(node)
        && statement_count(node).is_some_and(|count| count >= STATEMENT_THRESHOLD)
}

pub struct BusinessLogicInTypeGuardsRule {
    id: RuleId,
}

impl BusinessLogicInTypeGuardsRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("typescript:business-logic-in-type-guards").expect("valid rule id"),
        }
    }
}

impl Default for BusinessLogicInTypeGuardsRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for BusinessLogicInTypeGuardsRule {
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

    fn remediation_effort_minutes(&self) -> u32 {
        15
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "This type guard's body has several statements beyond a simple shape check. Callers trust a type guard's boolean result completely for compiler narrowing; keep it to a small, easily-audited predicate and move any other logic elsewhere.".into(),
            tags: vec!["typescript".into(), "clarity".into(), "maintainability".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter(|n| flagged(n))
            .map(|n| {
                Finding::new(
                    "this type guard's body does more than a small shape check; callers trust its result unconditionally for narrowing",
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
        BusinessLogicInTypeGuardsRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_type_guard_with_many_statements() {
        let code = "function isFoo(x: unknown): x is Foo {\n  doSomething();\n  logIt();\n  const y = compute();\n  return y > 0;\n}\n";
        assert_eq!(check(code).len(), 1);
    }

    #[test]
    fn allows_simple_type_guard() {
        let code = "function isFoo(x: unknown): x is Foo {\n  return typeof x === 'object' && x !== null;\n}\n";
        assert!(check(code).is_empty());
    }

    #[test]
    fn allows_arrow_type_guard_with_one_extra_statement() {
        let code = "function isFoo(x: unknown): x is Foo {\n  const obj = x as Foo;\n  return obj.kind === 'foo';\n}\n";
        assert!(check(code).is_empty());
    }

    #[test]
    fn allows_regular_function_with_many_statements() {
        let code = "function run(x: unknown): boolean {\n  doSomething();\n  logIt();\n  const y = compute();\n  return y > 0;\n}\n";
        assert!(check(code).is_empty());
    }
}
