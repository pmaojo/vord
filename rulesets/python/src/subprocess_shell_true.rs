//! Rule: flags `subprocess.*(..., shell=True)`. Running a subprocess
//! through a shell lets any shell metacharacter in the command string
//! (`;`, `|`, `` ` ``, `$(...)`) execute arbitrary commands if any part of
//! the string is influenced by external input.

use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use yunq_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

fn other_kind_name(node: &AstNode) -> Option<&str> {
    match node.kind() {
        NodeKind::Other(name) => Some(name.as_ref()),
        _ => None,
    }
}

fn has_shell_true_argument(call: &AstNode) -> bool {
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
                .is_some_and(|name| name.text() == "shell")
            && arg
                .children()
                .get(1)
                .is_some_and(|value| other_kind_name(value) == Some("true"))
    })
}

pub struct SubprocessShellTrueRule {
    id: RuleId,
}

impl SubprocessShellTrueRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("python:subprocess-shell-true").expect("valid rule id"),
        }
    }
}

impl Default for SubprocessShellTrueRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for SubprocessShellTrueRule {
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

    fn metadata(&self) -> yunq_rules_engine::RuleMetadata {
        yunq_rules_engine::RuleMetadata {
            description: "subprocess with shell=True runs the command string through the shell, so any shell metacharacter reaching it (from user input, config, or another process) can execute arbitrary commands; pass a list of arguments and drop shell=True instead.".into(),
            tags: vec!["security".into(), "injection".into(), "cwe".into(), "owasp-top10".into()],
            cwe: Some(78),
            produces_hotspots: false,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        if yunq_rules_engine::is_test_only_path(file.path()) {
            return Vec::new();
        }
        ast.descendants()
            .filter(|n| *n.kind() == NodeKind::Call)
            .filter(|call| call.first_child().is_some_and(|callee| callee.text().starts_with("subprocess.")))
            .filter(|call| has_shell_true_argument(call))
            .map(|call| Finding::new("subprocess call with shell=True is vulnerable to shell injection if the command is ever influenced by external input", call.span()))
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
        SubprocessShellTrueRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_run_with_shell_true() {
        assert_eq!(findings("subprocess.run(cmd, shell=True)\n").len(), 1);
    }

    #[test]
    fn flags_popen_with_shell_true() {
        assert_eq!(findings("subprocess.Popen(cmd, shell=True)\n").len(), 1);
    }

    #[test]
    fn allows_shell_false() {
        assert!(findings("subprocess.run(cmd, shell=False)\n").is_empty());
    }

    #[test]
    fn allows_no_shell_argument() {
        assert!(findings("subprocess.run(['ls', '-l'])\n").is_empty());
    }
}
