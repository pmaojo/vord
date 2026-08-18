//! Rule: flags a `@dataclass` field annotated with a mutable literal
//! default (`items: list = []`) instead of `field(default_factory=list)`.
//! `@dataclass` raises `ValueError` for a bare mutable *literal* default on
//! `list`/`dict`/`set`, but a mutable *constructor call* default
//! (`items: list = list()`) or a custom mutable type still slips through
//! at class-definition time and is shared by every instance exactly like
//! the classic mutable-default-argument trap — this rule is distinct from
//! `python:mutable-class-attribute`, which only inspects unannotated class
//! body assignments and never looks at the value of a typed field.

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

use crate::common::other_kind_name;

const MUTABLE_LITERAL_KINDS: &[&str] = &[
    "list",
    "dictionary",
    "set",
    "list_comprehension",
    "dictionary_comprehension",
    "set_comprehension",
];
const MUTABLE_CTORS: &[&str] = &["list", "dict", "set"];

fn is_mutable_value(value: &AstNode) -> bool {
    if other_kind_name(value).is_some_and(|k| MUTABLE_LITERAL_KINDS.contains(&k)) {
        return true;
    }
    value.kind() == &NodeKind::Call
        && value
            .first_child()
            .is_some_and(|callee| MUTABLE_CTORS.contains(&callee.text()))
}

fn is_dataclass_decorated(decorated: &AstNode) -> bool {
    decorated.children().iter().any(|c| {
        other_kind_name(c) == Some("decorator")
            && c.children().first().is_some_and(|d| {
                let callee = if d.kind() == &NodeKind::Call {
                    d.first_child()
                } else {
                    Some(d)
                };
                callee.is_some_and(|c| c.text() == "dataclass" || c.text().ends_with(".dataclass"))
            })
    })
}

fn annotated_field_assignments(class_def: &AstNode) -> impl Iterator<Item = &AstNode> {
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
        .filter(|n| n.kind() == &NodeKind::Assignment && n.children().len() == 3)
}

pub struct MutableDefaultInDataclassFieldRule {
    id: RuleId,
}

impl MutableDefaultInDataclassFieldRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("python:mutable-default-in-dataclass-field").expect("valid rule id"),
        }
    }
}

impl Default for MutableDefaultInDataclassFieldRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for MutableDefaultInDataclassFieldRule {
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
            description: "A @dataclass field defaulting to a mutable constructor call (or a custom mutable value) is evaluated once and shared by every instance; use field(default_factory=...) instead.".into(),
            tags: vec!["bug".into(), "python-idiom".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter(|n| other_kind_name(n) == Some("decorated_definition"))
            .filter(|n| is_dataclass_decorated(n))
            .filter_map(|n| n.children().iter().find(|c| other_kind_name(c) == Some("class_definition")))
            .flat_map(annotated_field_assignments)
            .filter(|assignment| assignment.children().last().is_some_and(is_mutable_value))
            .map(|assignment| Finding::new("dataclass field defaults to a mutable value shared by every instance; use field(default_factory=...) instead", assignment.span()))
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
        MutableDefaultInDataclassFieldRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_mutable_ctor_default() {
        assert_eq!(
            findings("@dataclass\nclass Foo:\n    items: list = list()\n").len(),
            1
        );
    }

    #[test]
    fn flags_dict_ctor_default() {
        assert_eq!(
            findings("@dataclasses.dataclass\nclass Foo:\n    data: dict = dict()\n").len(),
            1
        );
    }

    #[test]
    fn allows_default_factory() {
        assert!(findings(
            "@dataclass\nclass Foo:\n    items: list = field(default_factory=list)\n"
        )
        .is_empty());
    }

    #[test]
    fn allows_immutable_default() {
        assert!(findings("@dataclass\nclass Foo:\n    name: str = 'x'\n").is_empty());
    }

    #[test]
    fn ignores_undecorated_class() {
        assert!(findings("class Foo:\n    items: list = list()\n").is_empty());
    }
}
