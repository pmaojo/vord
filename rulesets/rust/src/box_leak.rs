use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use yunq_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

fn is_box_leak_path(callee_text: &str) -> bool {
    callee_text.ends_with("Box::leak")
}

/// Security hotspot: `Box::leak` hands back a `'static` reference by
/// deliberately never running the box's destructor — the memory it owns is
/// never freed for the rest of the process. Same failure mode as
/// `mem::forget` (`rust:mem-forget`), reached through the allocator API
/// instead of the `mem` module; a human needs to confirm the leak is
/// intentional and bounded (e.g. a one-time global, not something built in
/// a loop).
pub struct BoxLeakRule {
    id: RuleId,
}

impl BoxLeakRule {
    pub fn new() -> Self {
        Self { id: RuleId::new("rust:box-leak").expect("valid rule id") }
    }
}

impl Default for BoxLeakRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for BoxLeakRule {
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

    fn metadata(&self) -> yunq_rules_engine::RuleMetadata {
        yunq_rules_engine::RuleMetadata {
            description: "`Box::leak` intentionally skips freeing its allocation to hand back a \
                `'static` reference; confirm the leak is a bounded, one-time cost (e.g. \
                initializing a global) rather than something that runs repeatedly."
                .into(),
            tags: vec!["security".into(), "resource-leak".into(), "rust".into()],
            cwe: Some(401),
            produces_hotspots: true,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter(|n| *n.kind() == NodeKind::Call)
            .filter_map(|call| {
                let callee = call.first_child()?;
                is_box_leak_path(callee.text()).then(|| {
                    Finding::hotspot(
                        "confirm this `Box::leak` is a bounded, one-time leak, not one that runs repeatedly",
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
    use yunq_rules_engine::AstParser;

    use super::*;

    fn check(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.rs", code, LanguageIdentifier::rust()).unwrap();
        let ast = yunq_parser_rust::RustParser::new().parse(&file).unwrap();
        BoxLeakRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_box_leak() {
        let findings = check("fn f() { let r = Box::leak(Box::new(1)); }\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn ignores_unrelated_calls() {
        assert!(check("fn f() { let r = Box::new(1); }\n").is_empty());
    }
}
