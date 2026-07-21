use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use yunq_rules_engine::{Finding, Rule, RuleId, Severity};

/// Flags `.unwrap()` / `.expect()` in Rust code: potential panics that
/// should be handled or justified.
pub struct UnwrapUsageRule {
    id: RuleId,
}

impl UnwrapUsageRule {
    pub fn new() -> Self {
        Self { id: RuleId::new("smells:unwrap-usage").expect("valid rule id") }
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

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter(|n| *n.kind() == NodeKind::Call)
            .filter_map(|call| {
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
                    "unwrap" | "expect" => Some(Finding::new(
                        format!("`.{method}()` may panic; handle the error instead"),
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
    fn flags_unwrap_and_expect() {
        let findings =
            check("fn f() { let a = g().unwrap(); let b = h().expect(\"boom\"); }\n");
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn ignores_other_methods() {
        assert!(check("fn f() { let a = g().unwrap_or_default(); }\n").is_empty());
    }
}
