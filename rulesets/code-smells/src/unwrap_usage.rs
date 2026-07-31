use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use yunq_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

/// Flags bare `.unwrap()` in Rust code: a potential panic that should be
/// handled or justified. `.expect(msg)` is deliberately not flagged — the
/// message is itself the human justification this rule exists to require,
/// so a codebase-wide policy of "use `.expect()` with a reason" already
/// satisfies the intent. Test code (`tests/*.rs`, `#[cfg(test)] mod`
/// blocks) is exempt: panicking on unexpected state is the normal,
/// intended behavior of a test.
pub struct UnwrapUsageRule {
    id: RuleId,
}

impl UnwrapUsageRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("smells:unwrap-usage").expect("valid rule id"),
        }
    }
}

impl Default for UnwrapUsageRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for UnwrapUsageRule {
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

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        if yunq_rules_engine::is_test_only_path(file.path()) {
            return Vec::new();
        }
        let test_ranges = yunq_rules_engine::rust_test_module_ranges(file.content());

        ast.descendants()
            .filter(|n| *n.kind() == NodeKind::Call)
            .filter_map(|call| {
                if yunq_rules_engine::in_ranges(&test_ranges, call.span().start_line) {
                    return None;
                }
                let callee = call.first_child()?;
                if *callee.kind() != NodeKind::MemberAccess {
                    return None;
                }
                let method = callee
                    .children()
                    .iter()
                    .rev()
                    .find(|c| *c.kind() == NodeKind::Identifier)?
                    .text();
                match method {
                    "unwrap" => Some(Finding::new(
                        "`.unwrap()` may panic; handle the error or switch to `.expect(\"reason\")`".to_string(),
                        call.span(),
                    )),
                    _ => None,
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use yunq_ast::SourceFile;
    use yunq_rules_engine::AstParser;

    use super::*;

    fn check(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.rs", code, LanguageIdentifier::rust()).unwrap();
        let ast = yunq_parser_rust::RustParser::new().parse(&file).unwrap();
        UnwrapUsageRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_bare_unwrap() {
        let findings = check("fn f() { let a = g().unwrap(); }\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn does_not_flag_a_justified_expect() {
        assert!(
            check("fn f() { let a = g().expect(\"connection pool is never empty\"); }\n")
                .is_empty()
        );
    }

    #[test]
    fn ignores_other_methods() {
        assert!(check("fn f() { let a = g().unwrap_or_default(); }\n").is_empty());
    }

    #[test]
    fn ignores_unwrap_inside_a_cfg_test_module() {
        let code = "fn prod() {}\n\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn t() {\n        let a = g().unwrap();\n    }\n}\n";
        assert!(check(code).is_empty());
    }
}
