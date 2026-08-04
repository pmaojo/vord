//! Rule: flags a function whose every `return <value>;` returns the exact
//! same expression — a function that can only ever produce one value should
//! either return that constant unconditionally (dropping the dead
//! branching) or the branches were meant to return something different.
//! Return statements belonging to a nested function are not counted: they
//! answer for that nested function, not the one being checked.

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, Rule, RuleId, RuleMetadata, Severity};

use crate::common::is_other;

fn collect_own_returns<'a>(node: &'a AstNode, is_root: bool, out: &mut Vec<&'a AstNode>) {
    if !is_root && *node.kind() == NodeKind::FunctionDef {
        return;
    }
    if is_other(node, "return_statement") {
        out.push(node);
    }
    for child in node.children() {
        collect_own_returns(child, false, out);
    }
}

fn flagged_function(node: &AstNode) -> Option<&AstNode> {
    if *node.kind() != NodeKind::FunctionDef {
        return None;
    }
    let mut returns = Vec::new();
    collect_own_returns(node, true, &mut returns);
    let values: Vec<&str> = returns
        .iter()
        .map(|r| r.children().first().map(|v| v.text().trim()))
        .collect::<Option<Vec<_>>>()?;
    if values.len() < 2 {
        return None;
    }
    let first = values[0];
    values.iter().all(|v| *v == first).then_some(node)
}

pub struct ConstantReturnValueRule {
    id: RuleId,
}

impl ConstantReturnValueRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("typescript:constant-return-value").expect("valid rule id"),
        }
    }
}

impl Default for ConstantReturnValueRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for ConstantReturnValueRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, lang: &LanguageIdentifier) -> bool {
        *lang == LanguageIdentifier::typescript()
    }

    fn default_severity(&self) -> Severity {
        Severity::Major
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "Every `return` in this function produces the same value; either return it unconditionally and drop the dead branching, or the branches were meant to return something different.".into(),
            tags: vec!["typescript".into(), "suspicious".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter_map(flagged_function)
            .map(|n| {
                Finding::new(
                    "refactor this function to not always return the same value",
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
        ConstantReturnValueRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_function_always_returning_null() {
        let findings = check("function f(a) { if (a) { return null; } return null; }\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn allows_function_returning_different_values() {
        assert!(check("function f(a) { if (a) { return 1; } return 2; }\n").is_empty());
    }

    #[test]
    fn allows_single_return() {
        assert!(check("function f() { return null; }\n").is_empty());
    }

    #[test]
    fn ignores_returns_in_nested_function() {
        assert!(
            check("function f(a) { function g() { return 1; } if (a) return g(); return 2; }\n")
                .is_empty()
        );
    }
}
