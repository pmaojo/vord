//! Rule: flags `except Exception:` / `except BaseException:` whose body
//! does nothing but `pass` — an error is caught and then silently
//! discarded, with no logging, re-raise, or recovery. This hides real
//! failures instead of handling them.

use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use yunq_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

const BROAD_TYPES: &[&str] = &["Exception", "BaseException"];

fn other_kind_name(node: &AstNode) -> Option<&str> {
    match node.kind() {
        NodeKind::Other(name) => Some(name.as_ref()),
        _ => None,
    }
}

fn catches_broad_type(except_clause: &AstNode) -> bool {
    except_clause
        .children()
        .iter()
        .any(|c| *c.kind() == NodeKind::Identifier && BROAD_TYPES.contains(&c.text()))
}

fn block_only_passes(block: &AstNode) -> bool {
    !block.children().is_empty()
        && block
            .children()
            .iter()
            .all(|stmt| other_kind_name(stmt) == Some("pass_statement"))
}

pub struct BroadExceptionSwallowedRule {
    id: RuleId,
}

impl BroadExceptionSwallowedRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("python:broad-exception-swallowed").expect("valid rule id"),
        }
    }
}

impl Default for BroadExceptionSwallowedRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for BroadExceptionSwallowedRule {
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
        15
    }

    fn metadata(&self) -> yunq_rules_engine::RuleMetadata {
        yunq_rules_engine::RuleMetadata {
            description: "Catching a broad exception and doing nothing with it hides real failures; at minimum log the exception, or narrow the caught type.".into(),
            tags: vec!["bug".into(), "error-handling".into()],
            cwe: Some(390),
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter(|n| matches!(n.kind(), NodeKind::Other(name) if name.as_ref() == "except_clause"))
            .filter(|n| catches_broad_type(n))
            .filter_map(|n| {
                let block = n.children().iter().find(|c| other_kind_name(c) == Some("block"))?;
                block_only_passes(block).then(|| Finding::new("exception is caught and silently discarded; log it, re-raise it, or narrow the caught type", n.span()))
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
        let ast = yunq_parser_python::PythonParser::new()
            .parse(&file)
            .unwrap();
        BroadExceptionSwallowedRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_exception_pass() {
        assert_eq!(
            findings("try:\n    f()\nexcept Exception:\n    pass\n").len(),
            1
        );
    }

    #[test]
    fn flags_base_exception_pass() {
        assert_eq!(
            findings("try:\n    f()\nexcept BaseException:\n    pass\n").len(),
            1
        );
    }

    #[test]
    fn allows_exception_with_logging() {
        assert!(findings("try:\n    f()\nexcept Exception:\n    log.error('boom')\n").is_empty());
    }

    #[test]
    fn allows_narrow_except_pass() {
        assert!(findings("try:\n    f()\nexcept ValueError:\n    pass\n").is_empty());
    }
}
