//! Rule: flags a module-level `def`/`class` whose name doesn't start with
//! `_` (public API) with no docstring as the first statement in its body.
//! A public function or class with no docstring gives callers, `help()`,
//! and IDE tooltips nothing to go on — the only way to learn what it does
//! is to read the implementation.

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, Rule, RuleId, Severity};

use crate::common::other_kind_name;

fn public_name(node: &AstNode) -> Option<&str> {
    let name = node.children().first()?;
    (name.kind() == &NodeKind::Identifier && !name.text().starts_with('_')).then(|| name.text())
}

fn has_leading_docstring(node: &AstNode) -> bool {
    let Some(block) = node.children().iter().find(|c| other_kind_name(c) == Some("block")) else {
        return false;
    };
    let Some(first_stmt) = block.children().first() else {
        return false;
    };
    other_kind_name(first_stmt) == Some("expression_statement")
        && first_stmt
            .first_child()
            .is_some_and(|expr| expr.kind() == &NodeKind::StringLiteral)
}

pub struct MissingDocstringOnPublicApiRule {
    id: RuleId,
}

impl MissingDocstringOnPublicApiRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("python:missing-docstring-on-public-api").expect("valid rule id"),
        }
    }
}

impl Default for MissingDocstringOnPublicApiRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for MissingDocstringOnPublicApiRule {
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
        5
    }

    fn metadata(&self) -> vord_rules_engine::RuleMetadata {
        vord_rules_engine::RuleMetadata {
            description: "A public module-level function or class with no docstring gives callers, help(), and IDE tooltips nothing to go on; add a one-line summary of what it does.".into(),
            tags: vec!["documentation".into(), "maintainability".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        if crate::common::is_test_file(file.path()) {
            return Vec::new();
        }
        ast.children()
            .iter()
            .map(|top| {
                // A decorated def/class is one level down, under decorated_definition.
                if other_kind_name(top) == Some("decorated_definition") {
                    top.children()
                        .iter()
                        .find(|c| *c.kind() == NodeKind::FunctionDef || other_kind_name(c) == Some("class_definition"))
                        .unwrap_or(top)
                } else {
                    top
                }
            })
            .filter(|node| *node.kind() == NodeKind::FunctionDef || other_kind_name(node) == Some("class_definition"))
            .filter_map(|node| public_name(node).map(|_| node))
            .filter(|node| !has_leading_docstring(node))
            .map(|node| Finding::new("public API has no docstring; add a one-line summary of what it does", node.span()))
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
        MissingDocstringOnPublicApiRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_public_function_without_docstring() {
        assert_eq!(findings("def run(cmd):\n    return cmd\n").len(), 1);
    }

    #[test]
    fn flags_public_class_without_docstring() {
        assert_eq!(findings("class Runner:\n    def go(self):\n        pass\n").len(), 1);
    }

    #[test]
    fn allows_function_with_docstring() {
        assert!(findings("def run(cmd):\n    \"\"\"Run cmd.\"\"\"\n    return cmd\n").is_empty());
    }

    #[test]
    fn allows_private_function() {
        assert!(findings("def _run(cmd):\n    return cmd\n").is_empty());
    }

    #[test]
    fn ignores_nested_function() {
        let code = "def outer():\n    \"\"\"Outer.\"\"\"\n    def inner():\n        return 1\n    return inner()\n";
        assert!(findings(code).is_empty());
    }
}
