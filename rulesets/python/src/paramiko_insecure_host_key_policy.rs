//! Rule: flags `set_missing_host_key_policy(AutoAddPolicy())` (or
//! `WarningPolicy()`). Both accept and trust any host key the server
//! presents on first connect, defeating host key verification entirely —
//! an attacker who can intercept the connection can impersonate the
//! server without the client ever noticing.

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

use crate::common::other_kind_name;

const INSECURE_POLICIES: &[&str] = &["AutoAddPolicy", "WarningPolicy"];

fn uses_insecure_policy(call: &AstNode) -> bool {
    let Some(args) = call
        .children()
        .iter()
        .find(|c| other_kind_name(c) == Some("argument_list"))
    else {
        return false;
    };
    args.children().iter().any(|arg| {
        arg.kind() == &NodeKind::Call
            && arg.first_child().is_some_and(|callee| {
                let text = callee.text();
                INSECURE_POLICIES
                    .iter()
                    .any(|policy| text == *policy || text.ends_with(&format!(".{policy}")))
            })
    })
}

pub struct ParamikoInsecureHostKeyPolicyRule {
    id: RuleId,
}

impl ParamikoInsecureHostKeyPolicyRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("python:paramiko-insecure-host-key-policy").expect("valid rule id"),
        }
    }
}

impl Default for ParamikoInsecureHostKeyPolicyRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for ParamikoInsecureHostKeyPolicyRule {
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
            description: "AutoAddPolicy/WarningPolicy accept and trust any SSH host key the server presents, defeating host key verification; load known hosts and use RejectPolicy (or a pinned policy) instead.".into(),
            tags: vec!["security".into(), "cwe".into()],
            cwe: Some(295),
            produces_hotspots: false,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        if crate::common::is_test_file(file.path()) {
            return Vec::new();
        }
        ast.descendants()
            .filter(|n| *n.kind() == NodeKind::Call)
            .filter(|call| call.first_child().is_some_and(|callee| callee.text().ends_with("set_missing_host_key_policy")))
            .filter(|call| uses_insecure_policy(call))
            .map(|call| Finding::new("AutoAddPolicy/WarningPolicy trust any SSH host key on first connect, defeating host key verification; use a pinned or reject policy instead", call.span()))
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
        ParamikoInsecureHostKeyPolicyRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_auto_add_policy() {
        assert_eq!(
            findings("ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())\n").len(),
            1
        );
    }

    #[test]
    fn flags_warning_policy() {
        assert_eq!(
            findings("ssh.set_missing_host_key_policy(WarningPolicy())\n").len(),
            1
        );
    }

    #[test]
    fn allows_reject_policy() {
        assert!(findings("ssh.set_missing_host_key_policy(paramiko.RejectPolicy())\n").is_empty());
    }

    #[test]
    fn ignores_unrelated_calls() {
        assert!(findings("ssh.connect(host)\n").is_empty());
    }
}
