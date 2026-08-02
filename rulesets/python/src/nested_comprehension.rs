//! Rule: flags a comprehension (list/dict/set/generator) with two or
//! more `for` clauses. Each additional clause reads as another level of
//! nested loop packed onto one line — past the first, a plain nested
//! `for` loop communicates the same computation more clearly.

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, Rule, RuleId, Severity};

const COMPREHENSION_KINDS: &[&str] = &[
    "list_comprehension",
    "dictionary_comprehension",
    "set_comprehension",
    "generator_expression",
];

fn other_kind_name(node: &AstNode) -> Option<&str> {
    match node.kind() {
        NodeKind::Other(name) => Some(name.as_ref()),
        _ => None,
    }
}

fn for_clause_count(comprehension: &AstNode) -> usize {
    comprehension
        .children()
        .iter()
        .filter(|c| other_kind_name(c) == Some("for_in_clause"))
        .count()
}

pub struct NestedComprehensionRule {
    id: RuleId,
}

impl NestedComprehensionRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("python:nested-comprehension-too-deep").expect("valid rule id"),
        }
    }
}

impl Default for NestedComprehensionRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for NestedComprehensionRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, lang: &LanguageIdentifier) -> bool {
        *lang == LanguageIdentifier::python()
    }

    fn default_severity(&self) -> Severity {
        Severity::Minor
    }

    fn remediation_effort_minutes(&self) -> u32 {
        15
    }

    fn metadata(&self) -> vord_rules_engine::RuleMetadata {
        vord_rules_engine::RuleMetadata {
            description: "A comprehension with more than one `for` clause packs a nested loop onto one line; past the first clause, a plain nested for loop communicates the same computation more clearly.".into(),
            tags: vec!["maintainability".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter(|n| other_kind_name(n).is_some_and(|k| COMPREHENSION_KINDS.contains(&k)))
            .filter(|n| for_clause_count(n) >= 2)
            .map(|n| Finding::new("comprehension nests more than one `for` clause; a plain nested for loop reads more clearly", n.span()))
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
        NestedComprehensionRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_two_for_clauses() {
        assert_eq!(findings("result = [x for x in a for y in b]\n").len(), 1);
    }

    #[test]
    fn allows_single_for_clause() {
        assert!(findings("result = [x for x in a]\n").is_empty());
    }

    #[test]
    fn flags_nested_dict_comprehension() {
        assert_eq!(findings("result = {x: y for x in a for y in b}\n").len(), 1);
    }
}
