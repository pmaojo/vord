//! Rule: flags a `raise NewException(...)` inside an `except` block with
//! no `from` clause. Without it, Python still attaches the original
//! exception as `__context__`, but the traceback reads as "during
//! handling of the above exception" noise instead of an explicit causal
//! chain — `from e` (or `from None` to deliberately suppress it) says
//! which one was intended.

use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use yunq_rules_engine::{Finding, Rule, RuleId, Severity};

fn other_kind_name(node: &AstNode) -> Option<&str> {
    match node.kind() {
        NodeKind::Other(name) => Some(name.as_ref()),
        _ => None,
    }
}

fn raises_new_exception_without_from(raise_stmt: &AstNode) -> bool {
    raise_stmt.children().len() == 1 && raise_stmt.first_child().is_some_and(|c| *c.kind() == NodeKind::Call)
}

pub struct RaiseWithoutFromRule {
    id: RuleId,
}

impl RaiseWithoutFromRule {
    pub fn new() -> Self {
        Self { id: RuleId::new("python:raise-without-from-in-except").expect("valid rule id") }
    }
}

impl Default for RaiseWithoutFromRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for RaiseWithoutFromRule {
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

    fn metadata(&self) -> yunq_rules_engine::RuleMetadata {
        yunq_rules_engine::RuleMetadata {
            description: "Raising a new exception inside an except block with no `from` clause leaves the causal chain implicit; use `raise NewError(...) from e` (or `from None` to deliberately suppress the original) to make it explicit.".into(),
            tags: vec!["maintainability".into(), "error-handling".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter(|n| other_kind_name(n) == Some("except_clause"))
            .flat_map(|except_clause| except_clause.descendants())
            .filter(|n| other_kind_name(n) == Some("raise_statement"))
            .filter(|n| raises_new_exception_without_from(n))
            .map(|n| Finding::new("raising a new exception here loses the explicit causal chain; add `from e` (or `from None` to suppress it deliberately)", n.span()))
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
        RaiseWithoutFromRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_new_exception_without_from() {
        let code = "try:\n    f()\nexcept ValueError as e:\n    raise RuntimeError('wrapped')\n";
        assert_eq!(findings(code).len(), 1);
    }

    #[test]
    fn allows_explicit_from() {
        let code = "try:\n    f()\nexcept ValueError as e:\n    raise RuntimeError('wrapped') from e\n";
        assert!(findings(code).is_empty());
    }

    #[test]
    fn allows_bare_reraise() {
        let code = "try:\n    f()\nexcept ValueError:\n    raise\n";
        assert!(findings(code).is_empty());
    }

    #[test]
    fn ignores_raise_outside_except() {
        assert!(findings("def f():\n    raise ValueError('boom')\n").is_empty());
    }
}
