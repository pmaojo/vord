use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

use crate::common::is_other;

fn is_drop_call(callee_text: &str) -> bool {
    callee_text == "drop" || callee_text.ends_with("::drop")
}

fn sole_argument(call: &AstNode) -> Option<&AstNode> {
    let args = call
        .children()
        .iter()
        .find(|c| is_other(c.kind(), "arguments"))?;
    match args.children() {
        [only] => Some(only),
        _ => None,
    }
}

/// `drop(&x)`/`drop(&mut x)` drops the reference itself, which has no
/// destructor of its own — the value `x` points to is untouched and keeps
/// living out its normal scope. This is essentially always a mistake: either
/// the author meant to drop the owned value (`drop(x)`), or meant to end a
/// borrow early for the borrow checker's sake, which a reference's `Drop`
/// impl (there is none) can never do anyway.
pub struct DropOnReferenceRule {
    id: RuleId,
}

impl DropOnReferenceRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("rust:drop-on-reference").expect("valid rule id"),
        }
    }
}

impl Default for DropOnReferenceRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for DropOnReferenceRule {
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

    fn metadata(&self) -> vord_rules_engine::RuleMetadata {
        vord_rules_engine::RuleMetadata {
            description: "`drop(&x)`/`drop(&mut x)` drops the reference, not the value it \
                points to; the referenced value keeps living until its own scope ends. Drop the \
                owned value instead, or remove the call if it isn't needed."
                .into(),
            tags: vec!["correctness".into(), "rust".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter(|n| *n.kind() == NodeKind::Call)
            .filter(|call| call.first_child().is_some_and(|c| is_drop_call(c.text())))
            .filter_map(|call| {
                let arg = sole_argument(call)?;
                is_other(arg.kind(), "reference_expression").then(|| {
                    Finding::new(
                        format!(
                            "`drop({})` drops the reference itself, not the value it points to \
                            — this is almost certainly a no-op bug; drop the owned value instead",
                            arg.text()
                        ),
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
        DropOnReferenceRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_drop_on_shared_reference() {
        let findings = check("fn f() { let x = 1; drop(&x); }\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_drop_on_mutable_reference() {
        let findings = check("fn f() { let mut x = 1; drop(&mut x); }\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_qualified_mem_drop_on_reference() {
        let findings = check("fn f() { let x = 1; std::mem::drop(&x); }\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn ignores_drop_on_owned_value() {
        assert!(check("fn f() { let x = vec![1]; drop(x); }\n").is_empty());
    }

    #[test]
    fn ignores_unrelated_calls() {
        assert!(check("fn f() { let x = 1; let _ = &x; }\n").is_empty());
    }
}
