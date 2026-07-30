//! Rule: flags a function parameter whose default value is a mutable
//! literal (`[]`, `{}`, `set()`) or a mutable-type constructor call
//! (`list()`, `dict()`, `set()`). The default is evaluated once at
//! `def` time and shared across every call that doesn't override it, so
//! mutations leak between unrelated invocations — one of Python's best
//! known correctness traps.

use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use yunq_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

const MUTABLE_LITERAL_KINDS: &[&str] = &[
    "list",
    "dictionary",
    "set",
    "list_comprehension",
    "dictionary_comprehension",
    "set_comprehension",
];
const MUTABLE_CTORS: &[&str] = &["list", "dict", "set"];

fn other_kind_name(node: &AstNode) -> Option<&str> {
    match node.kind() {
        NodeKind::Other(name) => Some(name.as_ref()),
        _ => None,
    }
}

fn has_mutable_default(default_param: &AstNode) -> bool {
    let Some(value) = default_param.children().get(1) else {
        return false;
    };
    if other_kind_name(value).is_some_and(|k| MUTABLE_LITERAL_KINDS.contains(&k)) {
        return true;
    }
    if *value.kind() == NodeKind::Call {
        return value
            .first_child()
            .is_some_and(|callee| MUTABLE_CTORS.contains(&callee.text()));
    }
    false
}

pub struct MutableDefaultArgumentRule {
    id: RuleId,
}

impl MutableDefaultArgumentRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("python:mutable-default-argument").expect("valid rule id"),
        }
    }
}

impl Default for MutableDefaultArgumentRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for MutableDefaultArgumentRule {
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

    fn metadata(&self) -> yunq_rules_engine::RuleMetadata {
        yunq_rules_engine::RuleMetadata {
            description: "A mutable default argument is evaluated once and shared across every call that doesn't override it; use `None` and create the mutable value inside the function body instead.".into(),
            tags: vec!["bug".into(), "python-idiom".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter(|n| *n.kind() == NodeKind::FunctionDef)
            .flat_map(|func| func.children().iter().find(|c| other_kind_name(c) == Some("parameters")).into_iter().flat_map(|params| params.children().iter()))
            .filter(|param| matches!(other_kind_name(param), Some("default_parameter") | Some("typed_default_parameter")))
            .filter(|param| has_mutable_default(param))
            .map(|param| Finding::new("mutable default argument is shared across calls; default to `None` and build the value inside the function body", param.span()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use yunq_rules_engine::AstParser;

    use super::*;

    fn findings(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.py", code, LanguageIdentifier::python()).unwrap();
        let ast = yunq_parser_python::PythonParser::new()
            .parse(&file)
            .unwrap();
        MutableDefaultArgumentRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_empty_list_default() {
        assert_eq!(findings("def f(x=[]):\n    pass\n").len(), 1);
    }

    #[test]
    fn flags_dict_literal_default() {
        assert_eq!(findings("def f(x={}):\n    pass\n").len(), 1);
    }

    #[test]
    fn flags_list_constructor_default() {
        assert_eq!(findings("def f(x=list()):\n    pass\n").len(), 1);
    }

    #[test]
    fn allows_none_default() {
        assert!(findings("def f(x=None):\n    pass\n").is_empty());
    }

    #[test]
    fn allows_immutable_default() {
        assert!(findings("def f(x=0, y='a', z=(1, 2)):\n    pass\n").is_empty());
    }
}
