//! Rule: flags a string literal that looks like an absolute path specific
//! to one developer's machine (`/Users/<name>/...`, `/home/<name>/...`,
//! `C:\Users\<name>\...`). Code that only runs where that exact path
//! exists breaks the moment it reaches another machine, a CI runner, or a
//! teammate's laptop.

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

use crate::common::other_kind_name;

fn literal_string_value(node: &AstNode) -> Option<String> {
    if node.kind() != &NodeKind::StringLiteral {
        return None;
    }
    Some(
        node.children()
            .iter()
            .filter(|c| other_kind_name(c) == Some("string_content"))
            .map(|c| c.text())
            .collect(),
    )
}

fn looks_like_local_dev_path(text: &str) -> bool {
    text.starts_with("/Users/")
        || text.starts_with("/home/")
        || text.to_lowercase().starts_with(r"c:\users\")
}

pub struct HardcodedLocalPathRule {
    id: RuleId,
}

impl HardcodedLocalPathRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("python:hardcoded-local-path").expect("valid rule id"),
        }
    }
}

impl Default for HardcodedLocalPathRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for HardcodedLocalPathRule {
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
        IssueType::CodeSmell
    }

    fn remediation_effort_minutes(&self) -> u32 {
        5
    }

    fn metadata(&self) -> vord_rules_engine::RuleMetadata {
        vord_rules_engine::RuleMetadata {
            description: "A string literal hardcoding one developer's home directory only works on that exact machine; derive the path from a config value, environment variable, or Path.home() instead.".into(),
            tags: vec!["portability".into(), "maintainability".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        if crate::common::is_test_file(file.path()) {
            return Vec::new();
        }
        ast.descendants()
            .filter(|n| *n.kind() == NodeKind::StringLiteral)
            .filter_map(|n| literal_string_value(n).map(|v| (n, v)))
            .filter(|(_, value)| looks_like_local_dev_path(value))
            .map(|(n, _)| Finding::new("hardcoded path is specific to one developer's machine; derive it from a config value, environment variable, or Path.home() instead", n.span()))
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
        HardcodedLocalPathRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_macos_home_path() {
        assert_eq!(findings("path = '/Users/alice/data/input.csv'\n").len(), 1);
    }

    #[test]
    fn flags_linux_home_path() {
        assert_eq!(findings("path = '/home/bob/scripts/run.py'\n").len(), 1);
    }

    #[test]
    fn flags_windows_home_path() {
        assert_eq!(findings(r#"path = r"C:\Users\carol\data.csv""#).len(), 1);
    }

    #[test]
    fn allows_relative_or_config_derived_path() {
        assert!(findings("path = os.path.join(BASE_DIR, 'data.csv')\n").is_empty());
    }

    #[test]
    fn allows_unrelated_string_literal() {
        assert!(findings("message = 'hello world'\n").is_empty());
    }
}
