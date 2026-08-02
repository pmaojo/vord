//! Rule: flags the `global` statement. Rebinding a module-level name from
//! inside a function hides a hidden dependency between unrelated call
//! sites and makes the function's behavior depend on mutable state the
//! signature doesn't reveal.

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, Rule, RuleId, Severity};

fn other_kind_name(node: &AstNode) -> Option<&str> {
    match node.kind() {
        NodeKind::Other(name) => Some(name.as_ref()),
        _ => None,
    }
}

pub struct GlobalStatementRule {
    id: RuleId,
}

impl GlobalStatementRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("python:global-statement-usage").expect("valid rule id"),
        }
    }
}

impl Default for GlobalStatementRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for GlobalStatementRule {
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
        20
    }

    fn metadata(&self) -> vord_rules_engine::RuleMetadata {
        vord_rules_engine::RuleMetadata {
            description: "`global` lets a function mutate module-level state that its signature doesn't reveal, creating a hidden dependency between unrelated call sites; pass the value in and return it out instead.".into(),
            tags: vec!["maintainability".into(), "python-idiom".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter(|n| other_kind_name(n) == Some("global_statement"))
            .map(|n| Finding::new("`global` rebinds module-level state from inside a function, hiding a dependency the signature doesn't reveal", n.span()))
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
        GlobalStatementRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_global_statement() {
        assert_eq!(
            findings("def f():\n    global counter\n    counter += 1\n").len(),
            1
        );
    }

    #[test]
    fn allows_no_global() {
        assert!(findings("def f(counter):\n    return counter + 1\n").is_empty());
    }
}
