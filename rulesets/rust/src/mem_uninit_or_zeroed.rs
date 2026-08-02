use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

fn message_for(callee_text: &str) -> Option<&'static str> {
    let base = callee_text.split("::<").next().unwrap_or(callee_text);
    if base.ends_with("mem::uninitialized") {
        Some(
            "`mem::uninitialized` is deprecated and instant undefined behavior for almost \
            every type (any type without a valid all-bits-uninit representation); use \
            `MaybeUninit` instead",
        )
    } else if base.ends_with("mem::zeroed") {
        Some(
            "`mem::zeroed` is undefined behavior unless every bit pattern — including \
            all-zero — is a valid value of the target type (references, `NonNull`, `bool`, \
            most enums are not); confirm the type is zero-valid or use `MaybeUninit`",
        )
    } else {
        None
    }
}

/// Security hotspot: `mem::uninitialized`/`mem::zeroed` conjure a value out
/// of raw bits with no validity check. `mem::uninitialized` is deprecated
/// outright (Rust 1.39); `mem::zeroed` is still sound for plain-old-data
/// types (integers, `Option<Box<T>>` via niche optimization aside) but
/// instant UB for anything with a non-zero validity invariant. Either way a
/// human needs to confirm the target type actually tolerates the bit
/// pattern being produced.
pub struct MemUninitOrZeroedRule {
    id: RuleId,
}

impl MemUninitOrZeroedRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("rust:mem-uninit-or-zeroed").expect("valid rule id"),
        }
    }
}

impl Default for MemUninitOrZeroedRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for MemUninitOrZeroedRule {
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

    fn metadata(&self) -> vord_rules_engine::RuleMetadata {
        vord_rules_engine::RuleMetadata {
            description: "`mem::uninitialized`/`mem::zeroed` produce a value with no validity \
                check against its type; confirm the target type actually tolerates the bit \
                pattern, or use `MaybeUninit`."
                .into(),
            tags: vec!["security".into(), "unsafe".into(), "rust".into()],
            cwe: Some(457),
            produces_hotspots: true,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter(|n| *n.kind() == NodeKind::Call)
            .filter_map(|call| {
                let callee = call.first_child()?;
                let message = message_for(callee.text())?;
                Some(Finding::hotspot(message, call.span()))
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
        MemUninitOrZeroedRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_mem_uninitialized() {
        let findings = check("fn f() { let x: u8 = unsafe { std::mem::uninitialized() }; }\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_mem_zeroed() {
        let findings = check("fn f() { let x: u8 = unsafe { std::mem::zeroed() }; }\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn ignores_unrelated_calls() {
        assert!(check("fn f() { let x = std::mem::size_of::<u8>(); }\n").is_empty());
    }
}
