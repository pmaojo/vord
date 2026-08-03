use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

fn is_forget_path(callee_text: &str) -> bool {
    callee_text.ends_with("mem::forget")
}

/// Security hotspot: `mem::forget` runs a value's destructor never, leaking
/// whatever it owns (memory, file handles, locks) and — for types with
/// safety invariants that rely on `Drop` running (e.g. scope guards) —
/// potentially breaking soundness. A human needs to confirm the leak is
/// intentional and bounded.
pub struct MemForgetRule {
    id: RuleId,
}

impl MemForgetRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("rust:mem-forget").expect("valid rule id"),
        }
    }
}

impl Default for MemForgetRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for MemForgetRule {
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
        10
    }

    fn metadata(&self) -> vord_rules_engine::RuleMetadata {
        vord_rules_engine::RuleMetadata {
            description: "`mem::forget` skips a value's destructor, leaking whatever it owns; \
                confirm the leak is intentional (e.g. handing ownership across an FFI boundary) \
                rather than a missed cleanup path."
                .into(),
            tags: vec!["security".into(), "resource-leak".into(), "rust".into()],
            cwe: Some(401),
            produces_hotspots: true,
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
                is_forget_path(callee.text()).then(|| {
                    Finding::hotspot(
                        "confirm this `mem::forget` is an intentional, bounded leak",
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
        MemForgetRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_qualified_forget() {
        let findings = check("fn f(v: Vec<u8>) { std::mem::forget(v); }\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn ignores_unrelated_calls() {
        assert!(check("fn f(v: Vec<u8>) { drop(v); }\n").is_empty());
    }

    #[test]
    fn ignores_mem_forget_inside_a_cfg_test_module() {
        let code = "fn prod() {}\n\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn t(v: Vec<u8>) {\n        std::mem::forget(v);\n    }\n}\n";
        assert!(check(code).is_empty());
    }
}
