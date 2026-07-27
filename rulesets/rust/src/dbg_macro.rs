use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use yunq_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

/// `dbg!` is a debugging tool by design: it prints the file, line, and
/// value to stderr on every call and moves-then-returns its argument. Left
/// in committed code it leaks debug output (and a values-may-be-cloned-or-
/// moved surprise) into production logs. Mirrors `clippy::dbg_macro`.
pub struct DbgMacroRule {
    id: RuleId,
}

impl DbgMacroRule {
    pub fn new() -> Self {
        Self { id: RuleId::new("rust:dbg-macro").expect("valid rule id") }
    }
}

impl Default for DbgMacroRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for DbgMacroRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, language: &LanguageIdentifier) -> bool {
        *language == LanguageIdentifier::rust()
    }

    fn default_severity(&self) -> Severity {
        Severity::Minor
    }

    fn issue_type(&self) -> IssueType {
        IssueType::CodeSmell
    }

    fn remediation_effort_minutes(&self) -> u32 {
        2
    }

    fn metadata(&self) -> yunq_rules_engine::RuleMetadata {
        yunq_rules_engine::RuleMetadata {
            description: "`dbg!` prints to stderr with file/line on every call — a debugging \
                aid, not something to ship. Remove it or replace it with a real logging call."
                .into(),
            tags: vec!["debug-leftover".into(), "rust".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter(|n| *n.kind() == NodeKind::Call)
            .filter(|call| call.first_child().is_some_and(|c| *c.kind() == NodeKind::Identifier && c.text() == "dbg"))
            .map(|call| {
                Finding::new(
                    "`dbg!` left in code; remove it or replace it with a real logging call"
                        .to_string(),
                    call.span(),
                )
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
        DbgMacroRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_dbg_macro() {
        let findings = check("fn f(x: u32) -> u32 { dbg!(x) }\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn ignores_unrelated_macro() {
        assert!(check("fn f(x: u32) -> u32 { println!(\"{x}\"); x }\n").is_empty());
    }

    #[test]
    fn ignores_identifier_named_dbg() {
        assert!(check("fn f() { let dbg = 1; let _ = dbg; }\n").is_empty());
    }
}
