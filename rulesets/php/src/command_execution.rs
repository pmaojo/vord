use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

use crate::common::callee_node;

const SHELL_SINKS: &[&str] = &[
    "system",
    "exec",
    "shell_exec",
    "passthru",
    "popen",
    "proc_open",
    "pcntl_exec",
];

/// Security hotspot: these PHP builtins run a string as an OS shell
/// command. None of the generic `owasp:command-execution` rule's sinks
/// cover PHP — its list is Rust/Go/Python/TypeScript-specific — so this
/// fills that gap for PHP directly. A reviewer must confirm the command
/// and every argument are safe (not built from request input without
/// `escapeshellarg`/`escapeshellcmd`, ideally not shelled out to at all).
pub struct CommandExecutionRule {
    id: RuleId,
}

impl CommandExecutionRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("php:command-execution").expect("valid rule id"),
        }
    }
}

impl Default for CommandExecutionRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for CommandExecutionRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, language: &LanguageIdentifier) -> bool {
        *language == LanguageIdentifier::php()
    }

    fn default_severity(&self) -> Severity {
        Severity::Major
    }

    fn issue_type(&self) -> IssueType {
        IssueType::Vulnerability
    }

    fn remediation_effort_minutes(&self) -> u32 {
        15
    }

    fn metadata(&self) -> vord_rules_engine::RuleMetadata {
        vord_rules_engine::RuleMetadata {
            description: "Constructing an OS command is security-sensitive; confirm the \
                command and every argument are safe, escaped with \
                `escapeshellarg`/`escapeshellcmd` if any part comes from outside the process."
                .into(),
            tags: vec!["security".into(), "owasp-a03".into(), "php".into()],
            cwe: Some(78),
            produces_hotspots: true,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter(|n| *n.kind() == NodeKind::Call)
            .filter(|call| {
                callee_node(call).is_some_and(|c| {
                    *c.kind() == NodeKind::Identifier && SHELL_SINKS.contains(&c.text())
                })
            })
            .map(|call| {
                Finding::hotspot(
                    "make sure this OS command and its arguments are safe here",
                    call.span(),
                )
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use vord_ast::SourceFile;
    use vord_rules_engine::AstParser;

    use super::*;

    fn check(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.php", code, LanguageIdentifier::php()).unwrap();
        let ast = vord_parser_php::PhpParser::new().parse(&file).unwrap();
        CommandExecutionRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_system_call() {
        assert_eq!(check("<?php\nsystem($cmd);\n").len(), 1);
    }

    #[test]
    fn flags_shell_exec_call() {
        assert_eq!(check("<?php\n$out = shell_exec($cmd);\n").len(), 1);
    }

    #[test]
    fn ignores_unrelated_calls() {
        assert!(check("<?php\nstrtolower($cmd);\n").is_empty());
    }
}
