//! Rule: flags `raise Exception(...)` / `raise BaseException(...)`.
//! Raising the most generic exception type forces every caller that
//! wants to handle this failure specifically to catch broadly too (or
//! parse the message), since there's no distinct type left to match on.

use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use yunq_rules_engine::{Finding, Rule, RuleId, Severity};

const GENERIC_EXCEPTIONS: &[&str] = &["Exception", "BaseException"];

fn other_kind_name(node: &AstNode) -> Option<&str> {
    match node.kind() {
        NodeKind::Other(name) => Some(name.as_ref()),
        _ => None,
    }
}

fn raises_generic_exception(raise_stmt: &AstNode) -> bool {
    raise_stmt.first_child().is_some_and(|first| *first.kind() == NodeKind::Call && first.first_child().is_some_and(|callee| GENERIC_EXCEPTIONS.contains(&callee.text())))
}

pub struct RaiseGenericExceptionRule {
    id: RuleId,
}

impl RaiseGenericExceptionRule {
    pub fn new() -> Self {
        Self { id: RuleId::new("python:raise-generic-exception").expect("valid rule id") }
    }
}

impl Default for RaiseGenericExceptionRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for RaiseGenericExceptionRule {
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
        10
    }

    fn metadata(&self) -> yunq_rules_engine::RuleMetadata {
        yunq_rules_engine::RuleMetadata {
            description: "Raising Exception/BaseException gives callers no specific type to match on, forcing them to catch broadly or parse the message; raise (or define) a more specific exception type instead.".into(),
            tags: vec!["maintainability".into(), "error-handling".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter(|n| other_kind_name(n) == Some("raise_statement"))
            .filter(|n| raises_generic_exception(n))
            .map(|n| Finding::new("raising Exception/BaseException gives callers no specific type to match on; raise a more specific exception", n.span()))
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
        RaiseGenericExceptionRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_raise_exception() {
        assert_eq!(findings("raise Exception('boom')\n").len(), 1);
    }

    #[test]
    fn flags_raise_base_exception() {
        assert_eq!(findings("raise BaseException('boom')\n").len(), 1);
    }

    #[test]
    fn allows_specific_exception() {
        assert!(findings("raise ValueError('boom')\n").is_empty());
    }
}
