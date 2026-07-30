//! Rule: a domain type holds a direct field reference to another type that
//! has its own repository — evidence it is a separate aggregate root, reached
//! the wrong way. `class Order { customer: Customer }` lets a caller load an
//! `Order` and walk straight into a `Customer` object graph that belongs to a
//! transaction of its own; `class Order { customerId: CustomerId }` cannot.
//! One transaction should touch one aggregate root, and that discipline is
//! only enforceable if crossing an aggregate boundary always goes through an
//! id, never a live reference.
//!
//! Deliberately narrow about what counts as "another aggregate": a type
//! referencing *itself* (`Category { children: Category[] }`, a composite/tree
//! shape) is not flagged, because that reference never leaves the aggregate it
//! is already part of. Nor is a plain nested value object or a child entity
//! that has no repository of its own — the model has no evidence such a type
//! is ever loaded, saved, or transacted on independently, and a rule that
//! flagged every nested object would make `Order { lines: OrderLine[] }`, the
//! ordinary shape of an aggregate's internal parts, indistinguishable from the
//! defect. `common::repository_backed_names` is exactly that evidence: a type
//! only gets a repository when something in the codebase persists it on its
//! own.

use std::collections::BTreeSet;

use yunq_ast::{AstNode, SourceFile};
use yunq_rules_engine::{CrossFileRule, Finding, IssueType, RuleId, RuleMetadata, Severity};
use yunq_symbols::{type_identifiers, ClassRegistry};

use crate::common::{field_declared_type, is_domain_path, repository_backed_names};

pub struct AggregateReferenceByIdRule {
    id: RuleId,
}

impl AggregateReferenceByIdRule {
    pub fn new() -> Self {
        Self { id: RuleId::new("ddd:aggregate-reference-by-id").expect("valid rule id") }
    }
}

impl Default for AggregateReferenceByIdRule {
    fn default() -> Self {
        Self::new()
    }
}

impl CrossFileRule for AggregateReferenceByIdRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn default_severity(&self) -> Severity {
        Severity::Major
    }

    fn remediation_effort_minutes(&self) -> u32 {
        30
    }

    fn issue_type(&self) -> IssueType {
        IssueType::CodeSmell
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "A domain type holds a direct field reference to another type that has its own repository — a separate aggregate root reached the wrong way. Store its id and load it through its own repository instead.".into(),
            tags: vec!["ddd".into(), "aggregate".into(), "domain-model".into(), "cross-file".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, files: &[(SourceFile, AstNode)]) -> Vec<(usize, Finding)> {
        let domain: Vec<&(SourceFile, AstNode)> = files
            .iter()
            .filter(|(file, _)| is_domain_path(file.path()))
            .filter(|(file, _)| !yunq_rules_engine::is_test_only_path(file.path()))
            .collect();
        if domain.is_empty() {
            return Vec::new();
        }
        // The repository scan runs over every file, not just `domain`: a port
        // conventionally lives outside the domain layer, and restricting the
        // scan to it would make this rule blind to the one signal it needs.
        let repository_backed = repository_backed_names(files);
        if repository_backed.is_empty() {
            return Vec::new();
        }
        let views: Vec<(&str, &AstNode)> = domain.iter().map(|(file, ast)| (file.path(), ast)).collect();
        let registry = ClassRegistry::build_cross_file(&views);
        let mut findings = Vec::new();
        for class in registry.iter() {
            let Some(index) = files.iter().position(|(file, _)| file.path() == class.file) else { continue };
            for field in &class.fields {
                let Some(declared) = field_declared_type(class, field) else { continue };
                let referenced: BTreeSet<&str> = type_identifiers(declared)
                    .into_iter()
                    .filter(|name| *name != class.name)
                    .filter(|name| repository_backed.contains(*name))
                    .collect();
                for name in referenced {
                    findings.push((
                        index,
                        Finding::new(
                            format!(
                                "`{}::{}` holds a direct reference to `{name}`, which has its own repository — cross-aggregate references must go through `{name}Id`, not the object itself",
                                class.name, field.name
                            ),
                            field.span,
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
    use yunq_ast::LanguageIdentifier;
    use yunq_rules_engine::AstParser;

    fn parse(path: &str, code: &str, language: LanguageIdentifier) -> (SourceFile, AstNode) {
        let file = SourceFile::new(path, code, language.clone()).unwrap();
        let ast = if language == LanguageIdentifier::typescript() {
            yunq_parser_typescript::TypeScriptParser::new().parse(&file).unwrap()
        } else if language == LanguageIdentifier::python() {
            yunq_parser_python::PythonParser::new().parse(&file).unwrap()
        } else if language == LanguageIdentifier::go() {
            yunq_parser_go::GoParser::new().parse(&file).unwrap()
        } else {
            yunq_parser_rust::RustParser::new().parse(&file).unwrap()
        };
        (file, ast)
    }

    fn check(files: Vec<(SourceFile, AstNode)>) -> Vec<Finding> {
        AggregateReferenceByIdRule::new().check(&files).into_iter().map(|(_, f)| f).collect()
    }

    #[test]
    fn flags_a_typescript_aggregate_holding_another_aggregate_by_reference() {
        let files = vec![
            parse(
                "src/domain/order.ts",
                "export class Order {\n  private customer: Customer;\n}\n",
                LanguageIdentifier::typescript(),
            ),
            parse(
                "src/ports/customer_repository.ts",
                "export interface CustomerRepository {\n  findById(id: string): Customer;\n}\n",
                LanguageIdentifier::typescript(),
            ),
        ];
        let findings = check(files);
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert!(findings[0].message.contains("`Order::customer`"), "{}", findings[0].message);
        assert!(findings[0].message.contains("`Customer`"));
        assert!(findings[0].message.contains("`CustomerId`"));
    }

    #[test]
    fn silent_when_no_repository_backs_the_referenced_type() {
        // `Customer` here is a plain nested part with no evidence it is ever
        // loaded or saved on its own — the ordinary shape of an aggregate's
        // internals, not the defect.
        let files = vec![parse(
            "src/domain/order.ts",
            "export class Order {\n  private customer: Customer;\n}\n",
            LanguageIdentifier::typescript(),
        )];
        assert!(check(files).is_empty());
    }

    #[test]
    fn a_self_referencing_composite_is_not_flagged() {
        let files = vec![
            parse(
                "src/domain/category.ts",
                "export class Category {\n  private children: Category[];\n}\n",
                LanguageIdentifier::typescript(),
            ),
            parse(
                "src/ports/category_repository.ts",
                "export interface CategoryRepository {\n  findById(id: string): Category;\n}\n",
                LanguageIdentifier::typescript(),
            ),
        ];
        assert!(check(files).is_empty());
    }

    #[test]
    fn an_id_field_is_not_a_direct_reference() {
        let files = vec![
            parse(
                "src/domain/order.ts",
                "export class Order {\n  private customerId: CustomerId;\n}\n",
                LanguageIdentifier::typescript(),
            ),
            parse(
                "src/ports/customer_repository.ts",
                "export interface CustomerRepository {\n  findById(id: string): Customer;\n}\n",
                LanguageIdentifier::typescript(),
            ),
        ];
        assert!(check(files).is_empty());
    }

    #[test]
    fn silent_outside_the_domain_layer() {
        let files = vec![
            parse(
                "src/adapters/http/order_view.ts",
                "export class OrderView {\n  private customer: Customer;\n}\n",
                LanguageIdentifier::typescript(),
            ),
            parse(
                "src/ports/customer_repository.ts",
                "export interface CustomerRepository {\n  findById(id: string): Customer;\n}\n",
                LanguageIdentifier::typescript(),
            ),
        ];
        assert!(check(files).is_empty());
    }

    #[test]
    fn flags_a_rust_aggregate_across_a_trait_declared_in_another_file() {
        let files = vec![
            parse(
                "src/domain/order.rs",
                "pub struct Order {\n    customer: Customer,\n}\n",
                LanguageIdentifier::rust(),
            ),
            parse(
                "src/ports/customer_repository.rs",
                "pub trait CustomerRepository {\n    fn find_by_id(&self, id: &str) -> Customer;\n}\n",
                LanguageIdentifier::rust(),
            ),
        ];
        let findings = check(files);
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert!(findings[0].message.contains("Order::customer"));
    }

    #[test]
    fn flags_a_python_aggregate_referencing_a_repository_backed_class() {
        let files = vec![
            parse(
                "src/domain/order.py",
                "class Order:\n    def __init__(self, customer: Customer):\n        self.customer = customer\n",
                LanguageIdentifier::python(),
            ),
            parse(
                "src/ports/customer_repository.py",
                "class CustomerRepository:\n    def find_by_id(self, id):\n        pass\n",
                LanguageIdentifier::python(),
            ),
        ];
        let findings = check(files);
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert!(findings[0].message.contains("Order::customer"));
    }

    #[test]
    fn flags_a_go_aggregate_referencing_a_repository_backed_interface() {
        let files = vec![
            parse(
                "internal/domain/order.go",
                "package domain\n\ntype Order struct {\n\tCustomer Customer\n}\n",
                LanguageIdentifier::go(),
            ),
            parse(
                "internal/ports/customer_repository.go",
                "package ports\n\ntype CustomerRepository interface {\n\tFindByID(id string) Customer\n}\n",
                LanguageIdentifier::go(),
            ),
        ];
        let findings = check(files);
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert!(findings[0].message.contains("Order::Customer"));
    }

    #[test]
    fn flags_a_collection_field_of_a_repository_backed_type() {
        let files = vec![
            parse(
                "src/domain/order.ts",
                "export class Order {\n  private customers: Customer[];\n}\n",
                LanguageIdentifier::typescript(),
            ),
            parse(
                "src/ports/customer_repository.ts",
                "export interface CustomerRepository {\n  findById(id: string): Customer;\n}\n",
                LanguageIdentifier::typescript(),
            ),
        ];
        let findings = check(files);
        assert_eq!(findings.len(), 1, "{findings:?}");
    }
}
