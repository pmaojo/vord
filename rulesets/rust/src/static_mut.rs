use vord_ast::{AstNode, LanguageIdentifier, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

use crate::common::is_other;

/// `static mut` is unsynchronized global mutable state: any two threads (or,
/// pre-2024-edition, even a single-threaded program with an aliased `&mut`)
/// that touch it concurrently have a data race, which is undefined behavior
/// regardless of whether it's wrapped in `unsafe`. `AtomicT`, `OnceLock`, or
/// a `Mutex`/`RwLock` give the same "shared global" capability with real
/// synchronization.
pub struct StaticMutRule {
    id: RuleId,
}

impl StaticMutRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("rust:static-mut").expect("valid rule id"),
        }
    }
}

impl Default for StaticMutRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for StaticMutRule {
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
        20
    }

    fn metadata(&self) -> vord_rules_engine::RuleMetadata {
        vord_rules_engine::RuleMetadata {
            description: "`static mut` is unsynchronized global mutable state — concurrent \
                access from more than one thread is a data race. Use an atomic type, \
                `OnceLock`, or a `Mutex`/`RwLock` instead."
                .into(),
            tags: vec!["reliability".into(), "concurrency".into(), "rust".into()],
            cwe: Some(362),
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter(|n| is_other(n.kind(), "static_item"))
            .filter(|s| {
                s.children()
                    .iter()
                    .any(|c| is_other(c.kind(), "mutable_specifier"))
            })
            .map(|s| {
                Finding::new(
                    "`static mut` allows unsynchronized global mutable state; use an atomic \
                    type, `OnceLock`, or a `Mutex`/`RwLock`"
                        .to_string(),
                    s.span(),
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
        StaticMutRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_static_mut() {
        let findings = check("static mut COUNTER: u32 = 0;\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn ignores_immutable_static() {
        assert!(check("static COUNTER: u32 = 0;\n").is_empty());
    }

    #[test]
    fn ignores_local_mut_binding() {
        assert!(check("fn f() { let mut x = 0; x += 1; }\n").is_empty());
    }
}
