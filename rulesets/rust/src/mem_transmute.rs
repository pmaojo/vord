use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use yunq_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

fn is_transmute_path(callee_text: &str) -> bool {
    let base = callee_text.split("::<").next().unwrap_or(callee_text);
    base.ends_with("mem::transmute")
}

/// Security hotspot: `mem::transmute` reinterprets a value's bits as a
/// different type, bypassing the type checker entirely — a mismatched size,
/// alignment, or invariant is undefined behavior, not a panic. Almost every
/// use has a safe replacement (`as`, `from_bits`, `try_into`, a dedicated
/// cast method); the rare legitimate use still needs a human to confirm the
/// layouts actually match.
pub struct MemTransmuteRule {
    id: RuleId,
}

impl MemTransmuteRule {
    pub fn new() -> Self {
        Self { id: RuleId::new("rust:mem-transmute").expect("valid rule id") }
    }
}

impl Default for MemTransmuteRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for MemTransmuteRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, language: &LanguageIdentifier) -> bool {
        *language == LanguageIdentifier::rust()
    }

    fn default_severity(&self) -> Severity {
        Severity::Critical
    }

    fn issue_type(&self) -> IssueType {
        IssueType::Bug
    }

    fn remediation_effort_minutes(&self) -> u32 {
        20
    }

    fn metadata(&self) -> yunq_rules_engine::RuleMetadata {
        yunq_rules_engine::RuleMetadata {
            description: "`mem::transmute` reinterprets bits as another type with no layout or \
                validity check; a mismatch is undefined behavior. Confirm a safe conversion \
                (`as`, `try_into`, a typed constructor) can't replace it."
                .into(),
            tags: vec!["security".into(), "unsafe".into(), "rust".into()],
            cwe: Some(704),
            produces_hotspots: true,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter(|n| *n.kind() == NodeKind::Call)
            .filter_map(|call| {
                let callee = call.first_child()?;
                is_transmute_path(callee.text()).then(|| {
                    Finding::hotspot(
                        "confirm this `transmute` is sound: source and target layouts must match exactly",
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
        MemTransmuteRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_qualified_transmute() {
        let findings = check("fn f() { let x: i8 = unsafe { std::mem::transmute(1u8) }; }\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_transmute_with_turbofish() {
        let findings = check("fn f() { unsafe { std::mem::transmute::<u8, i8>(1); } }\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn ignores_unrelated_calls() {
        assert!(check("fn f() { let x = std::mem::size_of::<u8>(); }\n").is_empty());
    }
}
