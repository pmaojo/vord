//! Rule: flags a `for` loop whose single-name target is never
//! referenced in the loop body. If the value itself doesn't matter,
//! naming it `_` says so; a real name that goes unused reads as if the
//! body forgot to use it.

use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use yunq_rules_engine::{Finding, Rule, RuleId, Severity};

fn other_kind_name(node: &AstNode) -> Option<&str> {
    match node.kind() {
        NodeKind::Other(name) => Some(name.as_ref()),
        _ => None,
    }
}

fn is_referenced_in(block: &AstNode, name: &str) -> bool {
    block.descendants().any(|n| *n.kind() == NodeKind::Identifier && n.text() == name)
}

pub struct UnusedLoopVariableRule {
    id: RuleId,
}

impl UnusedLoopVariableRule {
    pub fn new() -> Self {
        Self { id: RuleId::new("python:unused-loop-variable").expect("valid rule id") }
    }
}

impl Default for UnusedLoopVariableRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for UnusedLoopVariableRule {
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
        2
    }

    fn metadata(&self) -> yunq_rules_engine::RuleMetadata {
        yunq_rules_engine::RuleMetadata {
            description: "A for-loop target that's never referenced in the body reads as if the value was forgotten; name it `_` if the value genuinely doesn't matter.".into(),
            tags: vec!["maintainability".into(), "python-idiom".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter(|n| other_kind_name(n) == Some("for_statement"))
            .filter_map(|for_stmt| {
                let target = for_stmt.first_child()?;
                if *target.kind() != NodeKind::Identifier || target.text() == "_" {
                    return None;
                }
                let block = for_stmt.children().iter().find(|c| other_kind_name(c) == Some("block"))?;
                (!is_referenced_in(block, target.text())).then(|| Finding::new(format!("loop variable `{}` is never used in the body; name it `_` if intentional", target.text()), for_stmt.span()))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use yunq_rules_engine::AstParser;

    use super::*;

    fn findings(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.py", code, LanguageIdentifier::python()).unwrap();
        let ast = yunq_parser_python::PythonParser::new().parse(&file).unwrap();
        UnusedLoopVariableRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_unused_target() {
        assert_eq!(findings("for i in range(10):\n    print('x')\n").len(), 1);
    }

    #[test]
    fn allows_used_target() {
        assert!(findings("for i in range(10):\n    print(i)\n").is_empty());
    }

    #[test]
    fn allows_underscore_target() {
        assert!(findings("for _ in range(10):\n    print('x')\n").is_empty());
    }

    #[test]
    fn ignores_tuple_targets() {
        assert!(findings("for i, j in pairs:\n    print(i)\n").is_empty());
    }
}
