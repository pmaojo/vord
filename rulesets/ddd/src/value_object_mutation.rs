//! Rule: a value object with a method that writes to its own field after
//! construction. `Money::add(other)` that does `self.amount += other.amount`
//! looks like an ordinary mutator, but a value object is defined by having no
//! identity — only its values — so two `Money`s that once compared equal must
//! keep comparing equal forever, or every place that stored, cached, or
//! compared one silently goes stale. The fix is always the same shape: return
//! a new instance instead of writing to `self`.
//!
//! Deliberately broader than `ddd:public-entity-setter`'s setter-shaped-name
//! detection: a value object gets no exemption for a private mutator, a
//! well-named one (`apply`, `merge`), or one that also does something else
//! before writing — none of that changes whether the identity comparison it
//! quietly breaks is still guarded. It also has nothing to do with the
//! constructor, which is where a value object's fields are legitimately
//! written the only time that is ever legal.

use std::collections::BTreeSet;

use vord_ast::{AstNode, SourceFile};
use vord_rules_engine::{CrossFileRule, Finding, IssueType, RuleId, RuleMetadata, Severity};
use vord_symbols::ClassRegistry;

use crate::common::{declared_methods, field_mutations, field_names, is_value_object};
use vord_import_graph::LayerTaxonomy;

pub struct ValueObjectMutationRule {
    id: RuleId,
    taxonomy: LayerTaxonomy,
}

impl ValueObjectMutationRule {
    pub fn new() -> Self {
        Self::with_taxonomy(LayerTaxonomy::default())
    }

    /// Same rule, recognizing the domain layer through a project's declared
    /// `[[architecture.layer]]` taxonomy as well as the zero-config
    /// heuristic — see `HexagonalLayerRule::with_taxonomy` for why this is a
    /// strict extension of [`Self::new`].
    pub fn with_taxonomy(taxonomy: LayerTaxonomy) -> Self {
        Self {
            id: RuleId::new("ddd:value-object-mutation").expect("valid rule id"),
            taxonomy,
        }
    }
}

impl Default for ValueObjectMutationRule {
    fn default() -> Self {
        Self::new()
    }
}

impl CrossFileRule for ValueObjectMutationRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn default_severity(&self) -> Severity {
        Severity::Major
    }

    fn remediation_effort_minutes(&self) -> u32 {
        20
    }

    fn issue_type(&self) -> IssueType {
        IssueType::CodeSmell
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "A value object writes to one of its own fields outside its constructor, so two instances that once compared equal can silently drift apart. Return a new instance instead of mutating this one.".into(),
            tags: vec!["ddd".into(), "value-object".into(), "immutability".into(), "cross-file".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, files: &[(SourceFile, AstNode)]) -> Vec<(usize, Finding)> {
        let domain: Vec<&(SourceFile, AstNode)> = files
            .iter()
            .filter(|(file, _)| self.taxonomy.is_domain(file.path()))
            .filter(|(file, _)| !vord_rules_engine::is_test_only_path(file.path()))
            .collect();
        if domain.is_empty() {
            return Vec::new();
        }
        let views: Vec<(&str, &AstNode)> = domain
            .iter()
            .map(|(file, ast)| (file.path(), ast))
            .collect();
        let registry = ClassRegistry::build_cross_file(&views);
        let mut findings = Vec::new();
        for class in registry.iter() {
            if !is_value_object(class) {
                continue;
            }
            let Some(index) = files.iter().position(|(file, _)| file.path() == class.file) else {
                continue;
            };
            let fields: BTreeSet<String> = field_names(class);
            for method in declared_methods(class) {
                for span in field_mutations(method, &fields) {
                    findings.push((
                        index,
                        Finding::new(
                            format!(
                                "`{}::{}` writes to `{}`'s own field — a value object has no identity, so mutating it in place makes every copy taken before the call silently stale; return a new `{}` instead",
                                class.name, method.name, class.name, class.name
                            ),
                            span,
                        ),
                    ));
                }
            }
        }
        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vord_ast::LanguageIdentifier;
    use vord_rules_engine::AstParser;

    fn check(path: &str, code: &str, language: LanguageIdentifier) -> Vec<Finding> {
        let file = SourceFile::new(path, code, language.clone()).unwrap();
        let ast = if language == LanguageIdentifier::typescript() {
            vord_parser_typescript::TypeScriptParser::new()
                .parse(&file)
                .unwrap()
        } else if language == LanguageIdentifier::python() {
            vord_parser_python::PythonParser::new()
                .parse(&file)
                .unwrap()
        } else if language == LanguageIdentifier::go() {
            vord_parser_go::GoParser::new().parse(&file).unwrap()
        } else {
            vord_parser_rust::RustParser::new().parse(&file).unwrap()
        };
        ValueObjectMutationRule::new()
            .check(&[(file, ast)])
            .into_iter()
            .map(|(_, f)| f)
            .collect()
    }

    #[test]
    fn flags_a_typescript_value_object_that_mutates_in_place() {
        let code = "export class Money {\n  private amount: number;\n  constructor(amount: number) {\n    this.amount = amount;\n  }\n  add(other: Money): void {\n    this.amount = this.amount + other.amount;\n  }\n}\n";
        let findings = check(
            "src/domain/money.ts",
            code,
            LanguageIdentifier::typescript(),
        );
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert!(
            findings[0].message.contains("`Money::add`"),
            "{}",
            findings[0].message
        );
    }

    #[test]
    fn silent_on_the_constructor_itself() {
        let code = "export class Money {\n  private amount: number;\n  constructor(amount: number) {\n    this.amount = amount;\n  }\n}\n";
        assert!(
            check(
                "src/domain/money.ts",
                code,
                LanguageIdentifier::typescript()
            )
            .is_empty()
        );
    }

    #[test]
    fn silent_when_the_method_returns_a_new_instance() {
        let code = "export class Money {\n  private amount: number;\n  constructor(amount: number) {\n    this.amount = amount;\n  }\n  add(other: Money): Money {\n    return new Money(this.amount + other.amount);\n  }\n}\n";
        assert!(
            check(
                "src/domain/money.ts",
                code,
                LanguageIdentifier::typescript()
            )
            .is_empty()
        );
    }

    #[test]
    fn flags_a_mutation_that_is_not_the_methods_only_statement() {
        // The whole reason this rule walks every descendant rather than
        // `accessor_of`'s single-statement body: a guard clause ahead of the
        // write must not hide the mutation from the rule.
        let code = "export class Money {\n  private amount: number;\n  constructor(amount: number) {\n    this.amount = amount;\n  }\n  apply(delta: number): void {\n    if (delta === 0) {\n      return;\n    }\n    this.amount = this.amount + delta;\n  }\n}\n";
        let findings = check(
            "src/domain/money.ts",
            code,
            LanguageIdentifier::typescript(),
        );
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert!(findings[0].message.contains("`Money::apply`"));
    }

    #[test]
    fn an_entity_with_identity_is_not_this_rules_business() {
        // `ddd:public-entity-setter` covers setters; an entity is allowed to
        // change its own state through a well-named behavior.
        let code = "export class Order {\n  private id: string;\n  private status: string = 'draft';\n  constructor(id: string) {\n    this.id = id;\n  }\n  ship(): void {\n    this.status = 'shipped';\n  }\n}\n";
        assert!(
            check(
                "src/domain/order.ts",
                code,
                LanguageIdentifier::typescript()
            )
            .is_empty()
        );
    }

    #[test]
    fn silent_outside_the_domain_layer() {
        let code = "export class Money {\n  private amount: number;\n  constructor(amount: number) {\n    this.amount = amount;\n  }\n  add(other: Money): void {\n    this.amount = this.amount + other.amount;\n  }\n}\n";
        assert!(
            check(
                "src/adapters/http/money.ts",
                code,
                LanguageIdentifier::typescript()
            )
            .is_empty()
        );
    }

    #[test]
    fn flags_a_rust_value_object_that_mutates_through_mut_self() {
        let code = "pub struct Money {\n    amount: i64,\n}\n\nimpl Money {\n    pub fn new(amount: i64) -> Self {\n        Self { amount }\n    }\n    pub fn add(&mut self, other: &Money) {\n        self.amount += other.amount;\n    }\n}\n";
        let findings = check("src/domain/money.rs", code, LanguageIdentifier::rust());
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert!(
            findings[0].message.contains("Money::add"),
            "{}",
            findings[0].message
        );
    }

    #[test]
    fn silent_on_a_rust_builder_that_returns_a_new_value() {
        let code = "pub struct Money {\n    amount: i64,\n}\n\nimpl Money {\n    pub fn new(amount: i64) -> Self {\n        Self { amount }\n    }\n    pub fn add(&self, other: &Money) -> Self {\n        Self { amount: self.amount + other.amount }\n    }\n}\n";
        assert!(check("src/domain/money.rs", code, LanguageIdentifier::rust()).is_empty());
    }

    #[test]
    fn flags_a_python_value_object_that_mutates_in_place() {
        let code = "class Money:\n    def __init__(self, amount):\n        self.amount = amount\n\n    def add(self, other):\n        self.amount = self.amount + other.amount\n";
        let findings = check("src/domain/money.py", code, LanguageIdentifier::python());
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert!(findings[0].message.contains("Money::add"));
    }

    #[test]
    fn flags_a_go_value_object_that_mutates_through_its_receiver() {
        let code = "package domain\n\ntype Money struct {\n\tAmount int64\n}\n\nfunc (m *Money) Add(other Money) {\n\tm.Amount = m.Amount + other.Amount\n}\n";
        let findings = check("internal/domain/money.go", code, LanguageIdentifier::go());
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert!(
            findings[0].message.contains("Money::Add"),
            "{}",
            findings[0].message
        );
    }

    #[test]
    fn a_class_with_no_fields_is_not_claimed_to_be_a_value_object() {
        let code = "export class Placeholder {\n  touch(): void {\n    this.state = 'x';\n  }\n}\n";
        assert!(
            check(
                "src/domain/placeholder.ts",
                code,
                LanguageIdentifier::typescript()
            )
            .is_empty()
        );
    }
}
