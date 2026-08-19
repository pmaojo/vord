//! Rule: flags `DEBUG = True` at module level in a Django settings file.
//! Django's debug page reflects request data, local variables, and
//! settings back into an HTML error page; if this ships to production it
//! hands an anonymous visitor a stack trace of the running process on the
//! first unhandled exception.

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

use crate::common::other_kind_name;

fn is_debug_true_assignment(assignment: &AstNode) -> bool {
    let Some(target) = assignment.children().first() else {
        return false;
    };
    let Some(value) = assignment.children().last() else {
        return false;
    };
    target.kind() == &NodeKind::Identifier
        && target.text() == "DEBUG"
        && other_kind_name(value) == Some("true")
}

pub struct DjangoDebugTrueRule {
    id: RuleId,
}

impl DjangoDebugTrueRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("python:django-debug-true").expect("valid rule id"),
        }
    }
}

impl Default for DjangoDebugTrueRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for DjangoDebugTrueRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, lang: &LanguageIdentifier) -> bool {
        *lang == LanguageIdentifier::python()
    }

    fn default_severity(&self) -> Severity {
        Severity::Blocker
    }

    fn issue_type(&self) -> IssueType {
        IssueType::Vulnerability
    }

    fn remediation_effort_minutes(&self) -> u32 {
        5
    }

    fn metadata(&self) -> vord_rules_engine::RuleMetadata {
        vord_rules_engine::RuleMetadata {
            description: "Django's DEBUG=True reflects request data, local variables, and settings into the error page; if it ships to production, any visitor who triggers an unhandled exception sees a full stack trace of the running process.".into(),
            tags: vec!["security".into(), "cwe".into()],
            cwe: Some(489),
            produces_hotspots: false,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        if !file.path().to_lowercase().contains("settings") {
            return Vec::new();
        }
        ast.descendants()
            .filter(|n| *n.kind() == NodeKind::Assignment)
            .filter(|n| is_debug_true_assignment(n))
            .map(|n| Finding::new("DEBUG=True in a Django settings file exposes a full interactive traceback to anyone who triggers an unhandled exception in production", n.span()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use vord_rules_engine::AstParser;

    use super::*;

    fn findings_in(path: &str, code: &str) -> Vec<Finding> {
        let file = SourceFile::new(path, code, LanguageIdentifier::python()).unwrap();
        let ast = vord_parser_python::PythonParser::new()
            .parse(&file)
            .unwrap();
        DjangoDebugTrueRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_debug_true_in_settings_file() {
        assert_eq!(findings_in("myapp/settings.py", "DEBUG = True\n").len(), 1);
    }

    #[test]
    fn allows_debug_false() {
        assert!(findings_in("myapp/settings.py", "DEBUG = False\n").is_empty());
    }

    #[test]
    fn ignores_non_settings_files() {
        assert!(findings_in("myapp/views.py", "DEBUG = True\n").is_empty());
    }

    #[test]
    fn allows_env_derived_debug() {
        assert!(findings_in("myapp/settings.py", "DEBUG = os.environ.get('DEBUG') == '1'\n").is_empty());
    }
}
