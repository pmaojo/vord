//! Rule: flags `app.secret_key = "..."` or `app.config['SECRET_KEY'] = "..."`
//! assigned a string literal. Flask's secret key signs session cookies; a
//! value baked into the source is checked into version control and shared
//! by every environment, so anyone who reads the repo can forge a session.

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

fn is_secret_key_target(target: &AstNode) -> bool {
    let text = target.text();
    text.ends_with(".secret_key") || text.contains("['SECRET_KEY']") || text.contains("[\"SECRET_KEY\"]")
}

fn is_secret_key_assignment(assignment: &AstNode) -> bool {
    let Some(target) = assignment.children().first() else {
        return false;
    };
    let Some(value) = assignment.children().last() else {
        return false;
    };
    is_secret_key_target(target) && value.kind() == &NodeKind::StringLiteral
}

pub struct FlaskSecretKeyHardcodedRule {
    id: RuleId,
}

impl FlaskSecretKeyHardcodedRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("python:flask-secret-key-hardcoded").expect("valid rule id"),
        }
    }
}

impl Default for FlaskSecretKeyHardcodedRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for FlaskSecretKeyHardcodedRule {
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
        10
    }

    fn metadata(&self) -> vord_rules_engine::RuleMetadata {
        vord_rules_engine::RuleMetadata {
            description: "A Flask secret key hardcoded as a string literal is checked into version control and shared by every environment; anyone who reads the repo can forge session cookies. Load it from an environment variable or secret store instead.".into(),
            tags: vec!["security".into(), "hardcoded-credential".into(), "cwe".into()],
            cwe: Some(798),
            produces_hotspots: false,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        if crate::common::is_test_file(file.path()) {
            return Vec::new();
        }
        ast.descendants()
            .filter(|n| *n.kind() == NodeKind::Assignment)
            .filter(|n| is_secret_key_assignment(n))
            .map(|n| Finding::new("Flask secret key is a hardcoded string literal; load it from an environment variable or secret store instead", n.span()))
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
        FlaskSecretKeyHardcodedRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_attribute_form() {
        assert_eq!(findings("app.secret_key = 'super-secret'\n").len(), 1);
    }

    #[test]
    fn flags_config_subscript_form() {
        assert_eq!(findings("app.config['SECRET_KEY'] = 'super-secret'\n").len(), 1);
    }

    #[test]
    fn allows_env_derived_secret() {
        assert!(findings("app.secret_key = os.environ['SECRET_KEY']\n").is_empty());
    }

    #[test]
    fn ignores_unrelated_assignment() {
        assert!(findings("app.debug = True\n").is_empty());
    }
}
