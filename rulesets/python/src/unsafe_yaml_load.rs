//! Rule: flags `yaml.load(data)` without an explicit safe `Loader`.
//! PyYAML's default loader can construct arbitrary Python objects from
//! the document, so loading untrusted YAML with it is equivalent to
//! deserializing an untrusted pickle.

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

use crate::common::other_kind_name;

fn has_loader_argument(call: &AstNode) -> bool {
    let Some(args) = call
        .children()
        .iter()
        .find(|c| other_kind_name(c) == Some("argument_list"))
    else {
        return false;
    };
    args.children().iter().any(|arg| {
        other_kind_name(arg) == Some("keyword_argument")
            && arg
                .children()
                .first()
                .is_some_and(|name| name.text() == "Loader")
    })
}

pub struct UnsafeYamlLoadRule {
    id: RuleId,
}

impl UnsafeYamlLoadRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("python:unsafe-yaml-load").expect("valid rule id"),
        }
    }
}

impl Default for UnsafeYamlLoadRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for UnsafeYamlLoadRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, lang: &LanguageIdentifier) -> bool {
        *lang == LanguageIdentifier::python()
    }

    fn default_severity(&self) -> Severity {
        Severity::Critical
    }

    fn issue_type(&self) -> IssueType {
        IssueType::Vulnerability
    }

    fn remediation_effort_minutes(&self) -> u32 {
        10
    }

    fn metadata(&self) -> vord_rules_engine::RuleMetadata {
        vord_rules_engine::RuleMetadata {
            description: "yaml.load without an explicit Loader uses PyYAML's full loader, which can construct arbitrary Python objects from the document; use yaml.safe_load or pass Loader=yaml.SafeLoader.".into(),
            tags: vec!["security".into(), "deserialization".into(), "cwe".into()],
            cwe: Some(502),
            produces_hotspots: false,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        if crate::common::is_test_file(file.path()) {
            return Vec::new();
        }
        ast.descendants()
            .filter(|n| *n.kind() == NodeKind::Call)
            .filter(|call| call.first_child().is_some_and(|callee| callee.text() == "yaml.load"))
            .filter(|call| !has_loader_argument(call))
            .map(|call| Finding::new("yaml.load without an explicit safe Loader can construct arbitrary Python objects; use yaml.safe_load or Loader=yaml.SafeLoader", call.span()))
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
        UnsafeYamlLoadRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_load_without_loader() {
        assert_eq!(findings("yaml.load(data)\n").len(), 1);
    }

    #[test]
    fn allows_load_with_safe_loader() {
        assert!(findings("yaml.load(data, Loader=yaml.SafeLoader)\n").is_empty());
    }

    #[test]
    fn allows_safe_load() {
        assert!(findings("yaml.safe_load(data)\n").is_empty());
    }
}
