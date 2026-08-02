//! Rule: flags a mutable literal assigned directly in a class body
//! (`class Foo: items = []`). Unlike an instance attribute set in
//! `__init__`, a class-body assignment creates one object shared by
//! every instance — mutating it through one instance leaks into all the
//! others, the class-level twin of the mutable-default-argument trap.

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

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

fn is_mutable_value(value: &AstNode) -> bool {
    if other_kind_name(value).is_some_and(|k| MUTABLE_LITERAL_KINDS.contains(&k)) {
        return true;
    }
    *value.kind() == NodeKind::Call
        && value
            .first_child()
            .is_some_and(|callee| MUTABLE_CTORS.contains(&callee.text()))
}

fn class_body_assignments(class_def: &AstNode) -> impl Iterator<Item = &AstNode> {
    class_def
        .children()
        .iter()
        .find(|c| other_kind_name(c) == Some("block"))
        .into_iter()
        .flat_map(|block| block.children().iter())
        .filter_map(|stmt| {
            (other_kind_name(stmt) == Some("expression_statement"))
                .then(|| stmt.first_child())
                .flatten()
        })
        .filter(|n| *n.kind() == NodeKind::Assignment)
}

pub struct MutableClassAttributeRule {
    id: RuleId,
}

impl MutableClassAttributeRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("python:mutable-class-attribute").expect("valid rule id"),
        }
    }
}

impl Default for MutableClassAttributeRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for MutableClassAttributeRule {
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
            description: "A mutable literal assigned directly in a class body is one object shared by every instance; mutating it through one instance leaks into all the others. Assign it in __init__ instead.".into(),
            tags: vec!["bug".into(), "python-idiom".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter(|n| other_kind_name(n) == Some("class_definition"))
            .flat_map(class_body_assignments)
            .filter(|assignment| assignment.children().get(1).is_some_and(is_mutable_value))
            .map(|assignment| Finding::new("mutable class attribute is shared by every instance; assign it in __init__ instead", assignment.span()))
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
        MutableClassAttributeRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_class_body_list_literal() {
        assert_eq!(findings("class Foo:\n    items = []\n").len(), 1);
    }

    #[test]
    fn allows_instance_attribute_in_init() {
        assert!(
            findings("class Foo:\n    def __init__(self):\n        self.items = []\n").is_empty()
        );
    }

    #[test]
    fn allows_immutable_class_attribute() {
        assert!(findings("class Foo:\n    name = 'default'\n").is_empty());
    }
}
