use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

/// Whether the contiguous run of comment lines directly above `start_line`
/// (1-based) mentions `SAFETY`. Stops at the first line that is neither a
/// `//` comment nor blank, so an unrelated `SAFETY` comment documenting an
/// earlier, different `unsafe` block doesn't count for this one.
fn has_safety_comment_directly_above(lines: &[&str], start_line: u32) -> bool {
    let mut found = false;
    for line in lines[..start_line.saturating_sub(1) as usize].iter().rev() {
        let trimmed = line.trim();
        if !trimmed.starts_with("//") {
            break;
        }
        if trimmed.to_ascii_lowercase().contains("safety") {
            found = true;
        }
    }
    found
}

/// Security hotspot: an `unsafe` block with no nearby `SAFETY` comment
/// explaining why the invariants it relies on actually hold. Mirrors the
/// convention codified by Rust's own API guidelines and
/// `clippy::undocumented_unsafe_blocks`.
pub struct UnsafeUndocumentedRule {
    id: RuleId,
}

impl UnsafeUndocumentedRule {
    pub fn new() -> Self {
        Self { id: RuleId::new("rust:unsafe-undocumented").expect("valid rule id") }
    }
}

impl Default for UnsafeUndocumentedRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for UnsafeUndocumentedRule {
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
            description: "An `unsafe` block must carry a `SAFETY` comment explaining why the \
                invariants it depends on hold; without one a reviewer has to reconstruct the \
                soundness argument from scratch."
                .into(),
            tags: vec!["security".into(), "unsafe".into(), "rust".into()],
            cwe: None,
            produces_hotspots: true,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        let lines: Vec<&str> = file.content().lines().collect();

        ast.descendants()
            .filter(|n| *n.kind() == NodeKind::Other("unsafe_block".into()))
            .filter(|block| !has_safety_comment_directly_above(&lines, block.span().start_line))
            .map(|block| {
                Finding::hotspot(
                    "`unsafe` block has no `SAFETY` comment explaining why it's sound",
                    block.span(),
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
        let file = SourceFile::new("t.rs", code, LanguageIdentifier::rust()).unwrap();
        let ast = vord_parser_rust::RustParser::new().parse(&file).unwrap();
        UnsafeUndocumentedRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_unsafe_block_without_safety_comment() {
        let findings = check("fn f() { unsafe { g(); } }\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn accepts_unsafe_block_with_directly_preceding_safety_comment() {
        let findings =
            check("fn f() {\n    // SAFETY: ptr is non-null and aligned\n    unsafe { g(); }\n}\n");
        assert!(findings.is_empty());
    }

    #[test]
    fn accepts_multi_line_safety_comment_directly_above() {
        let findings = check(
            "fn f() {\n    // SAFETY:\n    // ptr came from Box::into_raw and is still valid.\n    unsafe { g(); }\n}\n",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn unrelated_comment_does_not_count_as_documentation() {
        let findings = check("fn f() {\n    // call the ffi helper\n    unsafe { g(); }\n}\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn only_undocumented_blocks_are_flagged() {
        let findings = check(
            "fn f() {\n    // SAFETY: invariant holds\n    unsafe { g(); }\n    unsafe { h(); }\n}\n",
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn ignores_non_rust_languages() {
        assert!(!UnsafeUndocumentedRule::new().applies_to(&LanguageIdentifier::typescript()));
    }
}
