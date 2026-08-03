use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, Rule, RuleId, Severity};

fn exit_kind(callee_text: &str) -> Option<&'static str> {
    if callee_text.ends_with("process::exit") {
        Some("process::exit")
    } else if callee_text.ends_with("process::abort") {
        Some("process::abort")
    } else {
        None
    }
}

/// `process::exit`/`process::abort` terminate the process immediately,
/// running no destructors (`exit`) or none at all (`abort`) — any `Drop`
/// impl relying on cleanup (flushing buffers, releasing locks, closing
/// files) is skipped. Prefer returning a `Result`/`ExitCode` from `main` so
/// the normal unwind path runs, or document why the abrupt exit is
/// deliberate (e.g. a fatal-signal handler).
pub struct ProcessExitRule {
    id: RuleId,
}

impl ProcessExitRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("rust:process-exit").expect("valid rule id"),
        }
    }
}

impl Default for ProcessExitRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for ProcessExitRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, language: &LanguageIdentifier) -> bool {
        *language == LanguageIdentifier::rust()
    }

    fn default_severity(&self) -> Severity {
        Severity::Minor
    }

    fn metadata(&self) -> vord_rules_engine::RuleMetadata {
        vord_rules_engine::RuleMetadata {
            description: "`process::exit`/`process::abort` terminate the process without \
                running (all) destructors; prefer returning a `Result` or `ExitCode` from \
                `main` so `Drop` cleanup still runs."
                .into(),
            tags: vec!["reliability".into(), "rust".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        let test_ranges = vord_rules_engine::rust_test_module_ranges(file.content());

        ast.descendants()
            .filter(|n| *n.kind() == NodeKind::Call)
            .filter_map(|call| {
                if vord_rules_engine::in_ranges(&test_ranges, call.span().start_line) {
                    return None;
                }
                let callee = call.first_child()?;
                let kind = exit_kind(callee.text())?;
                Some(Finding::new(
                    format!("`{kind}` skips destructors; prefer returning a `Result`/`ExitCode` from `main`"),
                    call.span(),
                ))
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
        let file = SourceFile::new("t.rs", code, LanguageIdentifier::rust()).unwrap();
        let ast = vord_parser_rust::RustParser::new().parse(&file).unwrap();
        ProcessExitRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_process_exit() {
        let findings = check("fn f() { std::process::exit(1); }\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_process_abort() {
        let findings = check("fn f() { process::abort(); }\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn ignores_unrelated_calls() {
        assert!(check("fn f() { std::process::id(); }\n").is_empty());
    }

    #[test]
    fn ignores_process_exit_inside_a_cfg_test_module() {
        let code = "fn prod() {}\n\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn t() {\n        std::process::exit(1);\n    }\n}\n";
        assert!(check(code).is_empty());
    }
}
