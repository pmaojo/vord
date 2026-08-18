use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

use crate::common::is_other;

/// Free functions and macros with a well-known, unconditionally fallible
/// signature (`Result<_, _>`) where silently dropping the result is almost
/// always a mistake: a failed write, rename, or directory creation fails
/// silently instead of surfacing. Restricted to this narrow, unambiguous
/// set rather than guessing from arbitrary method names, which would need
/// real type information to avoid flagging infallible calls.
fn is_fallible_bare_call(callee_text: &str) -> bool {
    const FS_MUTATORS: &[&str] = &[
        "fs::write",
        "fs::remove_file",
        "fs::remove_dir",
        "fs::remove_dir_all",
        "fs::create_dir",
        "fs::create_dir_all",
        "fs::rename",
        "fs::copy",
        "fs::set_permissions",
        "fs::hard_link",
    ];
    if FS_MUTATORS.iter().any(|m| callee_text.ends_with(m)) {
        return true;
    }
    let name = callee_text.trim_end_matches('!');
    let name = name.rsplit("::").next().unwrap_or(name);
    name == "write" || name == "writeln"
}

/// A bare statement-position call (`foo();`, not `let x = foo();`,
/// `foo()?;`, or `let _ = foo();` — those are different node shapes that
/// this filter never matches) to a known-fallible operation silently drops
/// its `Result`: a failed filesystem write or a `write!` that couldn't
/// flush to a full buffer disappears without a trace. Propagate the error
/// with `?`, handle it, or make the discard explicit with `let _ = ..`.
pub struct MissingResultHandlingRule {
    id: RuleId,
}

impl MissingResultHandlingRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("rust:missing-result-handling").expect("valid rule id"),
        }
    }
}

impl Default for MissingResultHandlingRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for MissingResultHandlingRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, language: &LanguageIdentifier) -> bool {
        *language == LanguageIdentifier::rust()
    }

    fn default_severity(&self) -> Severity {
        Severity::Major
    }

    fn issue_type(&self) -> IssueType {
        IssueType::Bug
    }

    fn remediation_effort_minutes(&self) -> u32 {
        5
    }

    fn metadata(&self) -> vord_rules_engine::RuleMetadata {
        vord_rules_engine::RuleMetadata {
            description: "A bare statement-position call to a known-fallible operation \
                (`std::fs::write`, `write!`, ...) silently drops its `Result`; a failure \
                disappears without a trace. Propagate the error with `?`, handle it, or make \
                the discard explicit with `let _ = ..`."
                .into(),
            tags: vec!["reliability".into(), "error-handling".into(), "rust".into()],
            cwe: Some(252),
            produces_hotspots: false,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        let test_ranges = vord_rules_engine::rust_test_module_ranges(file.content());

        ast.descendants()
            .filter(|n| is_other(n.kind(), "expression_statement"))
            .filter(|n| !vord_rules_engine::in_ranges(&test_ranges, n.span().start_line))
            .filter_map(|stmt| {
                let call = stmt.first_child()?;
                if *call.kind() != NodeKind::Call {
                    return None;
                }
                let callee = call.first_child()?;
                is_fallible_bare_call(callee.text()).then(|| {
                    Finding::new(
                        "this call's `Result` is silently dropped; propagate it with `?`, \
                        handle it, or discard it explicitly with `let _ = ..`"
                            .to_string(),
                        call.span(),
                    )
                })
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
        MissingResultHandlingRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_bare_fs_write_statement() {
        let findings = check("fn f() { std::fs::write(\"a\", \"b\"); }\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_bare_remove_file_statement() {
        let findings = check("fn f() { fs::remove_file(\"a\"); }\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_bare_writeln_macro_statement() {
        let findings = check("fn f(w: &mut String) { writeln!(w, \"x\"); }\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn ignores_question_mark_propagated_call() {
        assert!(
            check("fn f() -> std::io::Result<()> { std::fs::write(\"a\", \"b\")?; Ok(()) }\n")
                .is_empty()
        );
    }

    #[test]
    fn ignores_explicit_discard() {
        assert!(check("fn f() { let _ = std::fs::write(\"a\", \"b\"); }\n").is_empty());
    }

    #[test]
    fn ignores_let_bound_call() {
        assert!(check("fn f() { let r = std::fs::write(\"a\", \"b\"); r.unwrap(); }\n").is_empty());
    }

    #[test]
    fn ignores_unwrapped_call() {
        assert!(check("fn f() { std::fs::write(\"a\", \"b\").unwrap(); }\n").is_empty());
    }

    #[test]
    fn ignores_unrelated_bare_call() {
        assert!(check("fn f() { println!(\"hi\"); }\n").is_empty());
    }

    #[test]
    fn ignores_missing_result_handling_inside_a_cfg_test_module() {
        let code = "fn prod() {}\n\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn t() {\n        std::fs::write(\"a\", \"b\");\n    }\n}\n";
        assert!(check(code).is_empty());
    }
}
