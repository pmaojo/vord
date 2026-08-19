//! Rule: flags `pickle.load(...)`/`pickle.loads(...)`. Unpickling runs
//! arbitrary code as a side effect of deserializing: a crafted pickle can
//! call any importable callable with attacker-chosen arguments during
//! `__reduce__`, so deserializing pickle data from anywhere other than a
//! source you fully trust is equivalent to running that source's code.

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

const PICKLE_LOAD_CALLEES: &[&str] = &["pickle.load", "pickle.loads", "cPickle.load", "cPickle.loads"];

pub struct PickleLoadUntrustedDataRule {
    id: RuleId,
}

impl PickleLoadUntrustedDataRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("python:pickle-load-untrusted-data").expect("valid rule id"),
        }
    }
}

impl Default for PickleLoadUntrustedDataRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for PickleLoadUntrustedDataRule {
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
        20
    }

    fn metadata(&self) -> vord_rules_engine::RuleMetadata {
        vord_rules_engine::RuleMetadata {
            description: "Unpickling can execute arbitrary code as a side effect of deserializing (via __reduce__); loading pickle data from anywhere other than a fully trusted source is equivalent to running that source's code. Use a data-only format (JSON) or sign/verify the payload first.".into(),
            tags: vec!["security".into(), "deserialization".into(), "cwe".into()],
            cwe: Some(502),
            produces_hotspots: true,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        if crate::common::is_test_file(file.path()) {
            return Vec::new();
        }
        ast.descendants()
            .filter(|n| *n.kind() == NodeKind::Call)
            .filter(|call| call.first_child().is_some_and(|callee| PICKLE_LOAD_CALLEES.contains(&callee.text())))
            .map(|call| Finding::hotspot("unpickling can execute arbitrary code during deserialization; confirm this data comes from a fully trusted source", call.span()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use vord_rules_engine::{AstParser, FindingKind};

    use super::*;

    fn findings(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.py", code, LanguageIdentifier::python()).unwrap();
        let ast = vord_parser_python::PythonParser::new()
            .parse(&file)
            .unwrap();
        PickleLoadUntrustedDataRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_pickle_load() {
        let f = findings("data = pickle.load(f)\n");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].kind, FindingKind::Hotspot);
    }

    #[test]
    fn flags_pickle_loads() {
        assert_eq!(findings("data = pickle.loads(raw)\n").len(), 1);
    }

    #[test]
    fn allows_pickle_dump() {
        assert!(findings("pickle.dump(data, f)\n").is_empty());
    }

    #[test]
    fn ignores_unrelated_calls() {
        assert!(findings("json.loads(raw)\n").is_empty());
    }
}
