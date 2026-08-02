//! Rule: flags `x is 5` / `x is 'foo'` — using `is` against an int, float,
//! or string literal. CPython caches small ints and interned strings, so
//! this can appear to work in one run and silently break in another; only
//! `None`/`True`/`False`/enum-member identity checks are meant to use
//! `is`. Equality (`==`) is what the author almost always means.

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

fn other_kind_name(node: &AstNode) -> Option<&str> {
    match node.kind() {
        NodeKind::Other(name) => Some(name.as_ref()),
        _ => None,
    }
}

fn is_identity_check(comparison: &AstNode) -> bool {
    comparison.text().contains(" is ")
}

fn compares_to_literal(comparison: &AstNode) -> bool {
    comparison.children().iter().any(|c| {
        *c.kind() == NodeKind::StringLiteral
            || matches!(other_kind_name(c), Some("integer") | Some("float"))
    })
}

pub struct LiteralIdentityComparisonRule {
    id: RuleId,
}

impl LiteralIdentityComparisonRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("python:literal-identity-comparison").expect("valid rule id"),
        }
    }
}

impl Default for LiteralIdentityComparisonRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for LiteralIdentityComparisonRule {
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
        5
    }

    fn metadata(&self) -> vord_rules_engine::RuleMetadata {
        vord_rules_engine::RuleMetadata {
            description: "`is` against an int/float/string literal relies on CPython's small-int and string interning, an implementation detail that can differ between runs; use `==` unless an identity check against None/True/False/a singleton is genuinely intended.".into(),
            tags: vec!["bug".into(), "python-idiom".into()],
            cwe: Some(697),
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter(|n| other_kind_name(n) == Some("comparison_operator"))
            .filter(|n| is_identity_check(n) && compares_to_literal(n))
            .map(|n| Finding::new("`is` against a literal relies on CPython interning, an implementation detail; use `==` instead", n.span()))
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
        LiteralIdentityComparisonRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_is_with_integer_literal() {
        assert_eq!(findings("if x is 5:\n    pass\n").len(), 1);
    }

    #[test]
    fn flags_is_with_string_literal() {
        assert_eq!(findings("if x is 'foo':\n    pass\n").len(), 1);
    }

    #[test]
    fn allows_is_none() {
        assert!(findings("if x is None:\n    pass\n").is_empty());
    }

    #[test]
    fn allows_equality_with_literal() {
        assert!(findings("if x == 5:\n    pass\n").is_empty());
    }
}
