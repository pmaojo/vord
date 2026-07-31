use yunq_ast::{AstNode, LanguageIdentifier, SourceFile};
use yunq_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

use crate::common::{impl_trait_is, is_other};

/// `impl From<A> for B` gets `Into<B> for A` for free from the standard
/// library's blanket `impl<T, U: From<T>> Into<U> for T`. Implementing
/// `Into` directly instead is strictly worse: it doesn't give you `From` in
/// return, so callers stuck with only an `Into` bound (or wanting
/// `B::from(a)` instead of `a.into()`) can't use the type, and generic code
/// written against `From` bounds — the far more common convention — won't
/// pick it up. Mirrors `clippy::from_over_into`.
pub struct FromOverIntoRule {
    id: RuleId,
}

impl FromOverIntoRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("rust:from-over-into").expect("valid rule id"),
        }
    }
}

impl Default for FromOverIntoRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for FromOverIntoRule {
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

    fn metadata(&self) -> yunq_rules_engine::RuleMetadata {
        yunq_rules_engine::RuleMetadata {
            description: "Implement `From` instead of `Into`: `impl From<A> for B` gives you \
                `Into<B> for A` for free via the standard library's blanket impl, but a manual \
                `Into` impl doesn't give you `From` back and won't satisfy the far more common \
                `From`-bounded generic code."
                .into(),
            tags: vec!["idiom".into(), "rust".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter(|n| is_other(n.kind(), "impl_item"))
            .filter(|n| impl_trait_is(n, "Into"))
            .map(|n| {
                Finding::new(
                    "implement `From` for the target type instead of `Into`; `From` gives you \
                    `Into` for free and satisfies `From`-bounded generic code, which a manual \
                    `Into` impl doesn't"
                        .to_string(),
                    n.span(),
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
        FromOverIntoRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_manual_into_impl() {
        let findings =
            check("impl Into<String> for Foo {\n    fn into(self) -> String { self.0 }\n}\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_scoped_into_path() {
        let findings = check(
            "impl std::convert::Into<String> for Foo {\n    fn into(self) -> String { self.0 }\n}\n",
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn ignores_from_impl() {
        assert!(
            check("impl From<Foo> for String {\n    fn from(f: Foo) -> String { f.0 }\n}\n")
                .is_empty()
        );
    }

    #[test]
    fn ignores_unrelated_trait_impls() {
        assert!(check("impl Clone for Foo { fn clone(&self) -> Self { Self } }\n").is_empty());
    }
}
