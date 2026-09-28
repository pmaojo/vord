//! Rule: flags `os.system(...)`. It runs the command through `/bin/sh`
//! with no way to pass arguments separately from the command string, so
//! any shell metacharacter reaching it from external input is command
//! injection — the same risk `subprocess.*(shell=True)` carries, but
//! `os.system` offers no way to opt out of the shell at all.

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

pub struct OsSystemUsageRule {
    id: RuleId,
}

impl OsSystemUsageRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("python:os-system-usage").expect("valid rule id"),
        }
    }
}

impl Default for OsSystemUsageRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for OsSystemUsageRule {
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
        15
    }

    fn metadata(&self) -> vord_rules_engine::RuleMetadata {
        vord_rules_engine::RuleMetadata {
            description: "os.system() always runs its argument through a shell with no way to separate the command from its arguments, so any shell metacharacter reaching it from external input is command injection; use subprocess.run() with an argument list instead.".into(),
            tags: vec!["security".into(), "injection".into(), "cwe".into(), "owasp-top10".into()],
            cwe: Some(78),
            produces_hotspots: false,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        if crate::common::is_test_file(file.path()) {
            return Vec::new();
        }
        ast.descendants()
            .filter(|n| *n.kind() == NodeKind::Call)
            .filter(|call| call.first_child().is_some_and(|callee| callee.text() == "os.system"))
            .map(|call| Finding::new("os.system() always runs through a shell; use subprocess.run() with an argument list instead", call.span()))
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
        OsSystemUsageRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_os_system() {
        assert_eq!(findings("os.system('ls -l')\n").len(), 1);
    }

    #[test]
    fn ignores_unrelated_calls() {
        assert!(findings("subprocess.run(['ls', '-l'])\n").is_empty());
    }
}
