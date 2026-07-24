use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use yunq_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

const TS_SINKS: &[&str] = &["exec", "execSync", "spawn", "spawnSync"];

/// Security hotspot: constructing OS commands is security-sensitive and
/// must be reviewed by a human — it is not automatically a bug, which is
/// exactly what distinguishes a hotspot from an issue.
pub struct CommandExecHotspotRule {
    id: RuleId,
}

impl CommandExecHotspotRule {
    pub fn new() -> Self {
        Self { id: RuleId::new("owasp:command-execution").expect("valid rule id") }
    }
}

impl Default for CommandExecHotspotRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for CommandExecHotspotRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, _language: &LanguageIdentifier) -> bool {
        true
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

    fn metadata(&self) -> yunq_rules_engine::RuleMetadata {
        yunq_rules_engine::RuleMetadata {
            description: "Constructing OS commands is security-sensitive; a reviewer must confirm the command and its arguments are safe.".into(),
            tags: vec!["security".into(), "owasp-a03".into()],
            cwe: Some(78),
            produces_hotspots: true,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        let python = *file.language() == LanguageIdentifier::python();
        let ts = *file.language() == LanguageIdentifier::typescript();
        ast.descendants()
            .filter(|n| *n.kind() == NodeKind::Call)
            .filter_map(|call| {
                let callee = call.first_child()?;
                let text = callee.text();
                let sensitive =
                    // Rust: `Command::new(...)` (scoped path arrives as Other).
                    text.ends_with("Command::new")
                    // Go: `exec.Command(...)` / `exec.CommandContext(...)`.
                    || text.starts_with("exec.Command")
                    // Python: os.system/os.popen and the subprocess module.
                    || (python && (text.starts_with("os.system") || text.starts_with("os.popen") || text.starts_with("subprocess.")))
                    // TS: exec/execSync/spawn/spawnSync, bare or as method.
                    || (ts && match callee.kind() {
                        NodeKind::Identifier => TS_SINKS.contains(&text),
                        NodeKind::MemberAccess => callee
                            .children()
                            .iter()
                            .rev()
                            .find(|c| *c.kind() == NodeKind::Identifier)
                            .is_some_and(|ident| TS_SINKS.contains(&ident.text())),
                        _ => false,
                    });
                sensitive.then(|| {
                    Finding::hotspot(
                        "make sure this OS command and its arguments are safe here",
                        call.span(),
                    )
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use yunq_ast::SourceFile;
    use yunq_rules_engine::{AstParser, FindingKind};

    use super::*;

    #[test]
    fn flags_rust_command_new_as_hotspot() {
        let file = SourceFile::new(
            "t.rs",
            "fn f() { let out = std::process::Command::new(\"ls\").output(); }\n",
            LanguageIdentifier::rust(),
        )
        .unwrap();
        let ast = yunq_parser_rust::RustParser::new().parse(&file).unwrap();
        let findings = CommandExecHotspotRule::new().check(&file, &ast);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, FindingKind::Hotspot);
    }

    #[test]
    fn flags_ts_child_process_calls() {
        let file = SourceFile::new(
            "t.ts",
            "import cp from 'child_process';\ncp.execSync(cmd);\nspawn(cmd);\nconsole.log(x);\n",
            LanguageIdentifier::typescript(),
        )
        .unwrap();
        let ast = yunq_parser_typescript::TypeScriptParser::new().parse(&file).unwrap();
        let findings = CommandExecHotspotRule::new().check(&file, &ast);
        assert_eq!(findings.len(), 2);
    }
}
