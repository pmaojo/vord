//! Rule: flags a function hinted `-> None` whose body still `return`s a
//! non-`None` expression. Full return-type checking needs real type
//! inference, but this one case is purely syntactic and unambiguous: the
//! signature promises nothing comes back, and the body hands something
//! back anyway — the annotation and the implementation disagree, so at
//! least one of them is wrong.

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

use crate::common::other_kind_name;

fn is_none_hinted(func: &AstNode) -> bool {
    func.children()
        .iter()
        .find(|c| other_kind_name(c) == Some("type"))
        .is_some_and(|t| t.text() == "None")
}

fn body_block(func: &AstNode) -> Option<&AstNode> {
    func.children().iter().find(|c| other_kind_name(c) == Some("block"))
}

/// Non-`None` `return <expr>` statements in `node`'s own body, not
/// descending into a nested `def`/`lambda` (those are a different
/// function's return type contract).
fn returns_with_value<'a>(node: &'a AstNode, out: &mut Vec<&'a AstNode>) {
    if other_kind_name(node) == Some("return_statement") && !node.children().is_empty() {
        let value = &node.children()[0];
        if value.text() != "None" {
            out.push(node);
        }
        return;
    }
    if *node.kind() == NodeKind::FunctionDef {
        return;
    }
    for child in node.children() {
        returns_with_value(child, out);
    }
}

pub struct TypeHintNoneReturnMismatchRule {
    id: RuleId,
}

impl TypeHintNoneReturnMismatchRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("python:type-hint-mismatch-implementation").expect("valid rule id"),
        }
    }
}

impl Default for TypeHintNoneReturnMismatchRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for TypeHintNoneReturnMismatchRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, lang: &LanguageIdentifier) -> bool {
        *lang == LanguageIdentifier::python()
    }

    fn default_severity(&self) -> Severity {
        Severity::Major
    }

    fn issue_type(&self) -> IssueType {
        IssueType::Bug
    }

    fn remediation_effort_minutes(&self) -> u32 {
        10
    }

    fn metadata(&self) -> vord_rules_engine::RuleMetadata {
        vord_rules_engine::RuleMetadata {
            description: "A function hinted -> None still returns a non-None value; the declared return type and the implementation disagree. Fix the annotation, or drop the returned value.".into(),
            tags: vec!["bug".into(), "type-hints".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter(|n| *n.kind() == NodeKind::FunctionDef)
            .filter(|func| is_none_hinted(func))
            .filter_map(body_block)
            .flat_map(|block| {
                let mut out = Vec::new();
                returns_with_value(block, &mut out);
                out
            })
            .map(|ret| Finding::new("function is hinted `-> None` but returns a value here; the annotation and the implementation disagree", ret.span()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use vord_rules_engine::AstParser;

    use super::*;

    fn findings(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.py", code, LanguageIdentifier::python()).unwrap();
        let ast = vord_parser_python::PythonParser::new()
            .parse(&file)
            .unwrap();
        TypeHintNoneReturnMismatchRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_none_hint_returning_value() {
        assert_eq!(findings("def f() -> None:\n    return 5\n").len(), 1);
    }

    #[test]
    fn allows_none_hint_with_bare_return() {
        assert!(findings("def f() -> None:\n    return\n").is_empty());
    }

    #[test]
    fn allows_none_hint_returning_none_explicitly() {
        assert!(findings("def f() -> None:\n    return None\n").is_empty());
    }

    #[test]
    fn allows_int_hint_returning_value() {
        assert!(findings("def f() -> int:\n    return 5\n").is_empty());
    }

    #[test]
    fn does_not_descend_into_nested_function() {
        let code = "def f() -> None:\n    def g():\n        return 5\n    g()\n";
        assert!(findings(code).is_empty());
    }
}
