//! Rule: flags a narrowly-typed `except SomeError:` clause whose body is
//! literally just `pass`. Naming a specific exception type looks
//! intentional, but discarding it with no logging, re-raise, or recovery
//! still hides a real failure — the narrow type just means it hides one
//! particular failure instead of everything. Complements
//! `python:broad-exception-swallowed`, which covers the same empty-body
//! smell but only for `except Exception:`/`except BaseException:`; this
//! rule covers every other named type so the two never double-report the
//! same clause.

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

const BROAD_TYPES: &[&str] = &["Exception", "BaseException"];

fn other_kind_name(node: &AstNode) -> Option<&str> {
    match node.kind() {
        NodeKind::Other(name) => Some(name.as_ref()),
        _ => None,
    }
}

fn is_bare(except_clause: &AstNode) -> bool {
    let children = except_clause.children();
    children.len() == 1 && other_kind_name(&children[0]) == Some("block")
}

fn names_narrow_type(except_clause: &AstNode) -> bool {
    !is_bare(except_clause)
        && except_clause.children().iter().any(|c| {
            c.kind() == &NodeKind::Identifier && !BROAD_TYPES.contains(&c.text())
        })
}

fn block_only_passes(block: &AstNode) -> bool {
    !block.children().is_empty()
        && block
            .children()
            .iter()
            .all(|stmt| other_kind_name(stmt) == Some("pass_statement"))
}

pub struct ExceptionSwallowedPassOnlyRule {
    id: RuleId,
}

impl ExceptionSwallowedPassOnlyRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("python:exception-swallowed-pass-only").expect("valid rule id"),
        }
    }
}

impl Default for ExceptionSwallowedPassOnlyRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for ExceptionSwallowedPassOnlyRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, lang: &LanguageIdentifier) -> bool {
        *lang == LanguageIdentifier::python()
    }

    fn default_severity(&self) -> Severity {
        Severity::Minor
    }

    fn issue_type(&self) -> IssueType {
        IssueType::CodeSmell
    }

    fn remediation_effort_minutes(&self) -> u32 {
        10
    }

    fn metadata(&self) -> vord_rules_engine::RuleMetadata {
        vord_rules_engine::RuleMetadata {
            description: "A narrowly-typed except clause whose body is just `pass` still discards a real failure with no logging, re-raise, or recovery; at minimum log it, or add a comment explaining why it's safe to ignore.".into(),
            tags: vec!["code-smell".into(), "error-handling".into()],
            cwe: Some(390),
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter(|n| other_kind_name(n) == Some("except_clause"))
            .filter(|n| names_narrow_type(n))
            .filter_map(|n| {
                let block = n.children().iter().find(|c| other_kind_name(c) == Some("block"))?;
                block_only_passes(block).then(|| Finding::new("except clause names a specific exception type but its body is only `pass`; the failure is discarded with no logging, re-raise, or recovery", n.span()))
            })
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
        ExceptionSwallowedPassOnlyRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_narrow_except_pass() {
        assert_eq!(
            findings("try:\n    f()\nexcept ValueError:\n    pass\n").len(),
            1
        );
    }

    #[test]
    fn allows_narrow_except_with_logging() {
        assert!(findings("try:\n    f()\nexcept ValueError:\n    log.warning('skip')\n").is_empty());
    }

    #[test]
    fn does_not_double_report_broad_except() {
        // Covered by python:broad-exception-swallowed instead.
        assert!(findings("try:\n    f()\nexcept Exception:\n    pass\n").is_empty());
    }

    #[test]
    fn does_not_double_report_bare_except() {
        assert!(findings("try:\n    f()\nexcept:\n    pass\n").is_empty());
    }
}
