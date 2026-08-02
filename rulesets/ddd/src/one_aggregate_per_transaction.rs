//! Rule: an application-service method that writes to more than one
//! aggregate's repository. `placeOrder` that calls both `this.orders.save(..)`
//! and `this.inventory.save(..)` has folded two aggregates' consistency rules
//! into a single local transaction — exactly what aggregate boundaries exist
//! to prevent. If saving the order succeeds and saving the inventory fails
//! (or the other way around), the two are now inconsistent with each other and
//! nothing owns fixing that. The correct shape publishes a domain event after
//! committing the first aggregate and lets a handler update the second in its
//! own transaction.
//!
//! Scoped to the application layer (`common::is_application_path`), not the
//! domain layer every other rule in this crate asks about: a well-formed
//! aggregate holds no repository of its own to call in the first place, so
//! this defect can only ever appear in the code that orchestrates aggregates,
//! not the aggregates themselves.
//!
//! Detection is intra-file only. A repository-typed field is one whose
//! declared type resolves to `<Name>Repository` (the same convention
//! `ddd:aggregate-reference-by-id` reads); a write is a call to one of a
//! fixed, lower-cased set of persistence-verb method names
//! (`save`/`persist`/`add`/`update`/`delete`/`remove`/`insert`/`create`/`store`)
//! on that field. Two write calls to the *same* repository (`orders.save(a);
//! orders.save(b);`) are one aggregate touched twice, not two aggregates, and
//! are not flagged — this rule counts distinct aggregate types, not call
//! sites.

use std::collections::{BTreeMap, BTreeSet};

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};
use vord_symbols::{ClassInfo, ClassRegistry, MethodInfo, type_identifiers};

use crate::common::{accessed_field, declared_methods, field_declared_type, is_application_path};

const WRITE_METHODS: &[&str] = &[
    "save", "persist", "add", "update", "delete", "remove", "insert", "create", "store",
];

fn is_write_call(method_name: &str) -> bool {
    WRITE_METHODS.contains(&method_name.to_ascii_lowercase().as_str())
}

/// Every field on `class` whose type is `<Aggregate>Repository`, keyed by
/// field name.
fn repository_fields(class: &ClassInfo<'_>) -> BTreeMap<String, String> {
    class
        .fields
        .iter()
        .filter_map(|field| {
            let declared = field_declared_type(class, field)?;
            let aggregate = type_identifiers(declared).into_iter().find_map(|name| {
                name.strip_suffix("Repository")
                    .filter(|prefix| !prefix.is_empty())
            })?;
            Some((field.name.clone(), aggregate.to_string()))
        })
        .collect()
}

/// The distinct aggregates `method` calls a write operation against, through
/// one of `repository_fields`.
fn aggregates_written(
    method: &MethodInfo<'_>,
    repository_fields: &BTreeMap<String, String>,
) -> BTreeSet<String> {
    let receiver = method.receiver.as_deref();
    method
        .node
        .descendants()
        .filter(|node| *node.kind() == NodeKind::Call)
        .filter_map(|call| {
            let callee = call.first_child()?;
            if *callee.kind() != NodeKind::MemberAccess {
                return None;
            }
            let base = callee.first_child()?;
            let method_name = callee.children().get(1)?;
            if !is_write_call(method_name.text()) {
                return None;
            }
            let field = accessed_field(base, receiver)?;
            repository_fields.get(field).cloned()
        })
        .collect()
}

pub struct OneAggregatePerTransactionRule {
    id: RuleId,
}

impl OneAggregatePerTransactionRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("ddd:one-aggregate-per-transaction").expect("valid rule id"),
        }
    }
}

impl Default for OneAggregatePerTransactionRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for OneAggregatePerTransactionRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, _language: &LanguageIdentifier) -> bool {
        true
    }

    fn default_severity(&self) -> Severity {
        Severity::Major
    }

    fn remediation_effort_minutes(&self) -> u32 {
        45
    }

    fn issue_type(&self) -> IssueType {
        IssueType::CodeSmell
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "An application-service method writes to more than one aggregate's repository in what reads as a single local transaction. Commit one aggregate, publish a domain event, and let the other aggregate's own transaction react to it.".into(),
            tags: vec!["ddd".into(), "aggregate".into(), "transaction-boundary".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        if !is_application_path(file.path()) || vord_rules_engine::is_test_only_path(file.path()) {
            return Vec::new();
        }
        let registry = ClassRegistry::build(ast);
        let mut findings = Vec::new();
        for class in registry.iter() {
            let repository_fields = repository_fields(class);
            let distinct_aggregates: BTreeSet<&String> = repository_fields.values().collect();
            if distinct_aggregates.len() < 2 {
                continue;
            }
            for method in declared_methods(class) {
                let touched = aggregates_written(method, &repository_fields);
                if touched.len() <= 1 {
                    continue;
                }
                let names: Vec<&str> = touched.iter().map(String::as_str).collect();
                findings.push(Finding::new(
                    format!(
                        "`{}::{}` writes to {} aggregates in what reads as one transaction ({}) — commit one and let the others react to a domain event instead",
                        class.name,
                        method.name,
                        touched.len(),
                        names.join(", ")
                    ),
                    method.span,
                ));
            }
        }
        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
        OneAggregatePerTransactionRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_a_typescript_service_that_saves_two_aggregates() {
        let code = "export class PlaceOrder {\n  private orders: OrderRepository;\n  private inventory: InventoryRepository;\n  constructor(orders: OrderRepository, inventory: InventoryRepository) {\n    this.orders = orders;\n    this.inventory = inventory;\n  }\n  execute(order: Order): void {\n    this.orders.save(order);\n    this.inventory.save(order);\n  }\n}\n";
        let findings = check(
            "src/application/place_order.ts",
            code,
            LanguageIdentifier::typescript(),
        );
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert!(
            findings[0].message.contains("`PlaceOrder::execute`"),
            "{}",
            findings[0].message
        );
        assert!(findings[0].message.contains("Order"));
        assert!(findings[0].message.contains("Inventory"));
    }

    #[test]
    fn silent_when_the_same_aggregate_is_saved_twice() {
        let code = "export class PlaceOrder {\n  private orders: OrderRepository;\n  private inventory: InventoryRepository;\n  constructor(orders: OrderRepository, inventory: InventoryRepository) {\n    this.orders = orders;\n    this.inventory = inventory;\n  }\n  execute(a: Order, b: Order): void {\n    this.orders.save(a);\n    this.orders.save(b);\n  }\n}\n";
        assert!(
            check(
                "src/application/place_order.ts",
                code,
                LanguageIdentifier::typescript()
            )
            .is_empty()
        );
    }

    #[test]
    fn silent_when_only_reads_touch_the_second_repository() {
        let code = "export class PlaceOrder {\n  private orders: OrderRepository;\n  private inventory: InventoryRepository;\n  constructor(orders: OrderRepository, inventory: InventoryRepository) {\n    this.orders = orders;\n    this.inventory = inventory;\n  }\n  execute(order: Order): void {\n    this.inventory.findById(order.id);\n    this.orders.save(order);\n  }\n}\n";
        assert!(
            check(
                "src/application/place_order.ts",
                code,
                LanguageIdentifier::typescript()
            )
            .is_empty()
        );
    }

    #[test]
    fn silent_outside_the_application_layer() {
        let code = "export class PlaceOrder {\n  private orders: OrderRepository;\n  private inventory: InventoryRepository;\n  constructor(orders: OrderRepository, inventory: InventoryRepository) {\n    this.orders = orders;\n    this.inventory = inventory;\n  }\n  execute(order: Order): void {\n    this.orders.save(order);\n    this.inventory.save(order);\n  }\n}\n";
        assert!(
            check(
                "src/domain/place_order.ts",
                code,
                LanguageIdentifier::typescript()
            )
            .is_empty()
        );
    }

    #[test]
    fn flags_a_rust_service_that_saves_two_aggregates() {
        let code = "pub struct PlaceOrder {\n    orders: std::sync::Arc<dyn OrderRepository>,\n    inventory: std::sync::Arc<dyn InventoryRepository>,\n}\n\nimpl PlaceOrder {\n    pub fn execute(&self, order: &Order) {\n        self.orders.save(order);\n        self.inventory.save(order);\n    }\n}\n";
        let findings = check(
            "src/application/place_order.rs",
            code,
            LanguageIdentifier::rust(),
        );
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert!(findings[0].message.contains("PlaceOrder::execute"));
    }

    #[test]
    fn flags_a_python_service_that_saves_two_aggregates_via_constructor_injection() {
        let code = "class PlaceOrder:\n    def __init__(self, orders: OrderRepository, inventory: InventoryRepository):\n        self.orders = orders\n        self.inventory = inventory\n\n    def execute(self, order):\n        self.orders.save(order)\n        self.inventory.save(order)\n";
        let findings = check(
            "src/application/place_order.py",
            code,
            LanguageIdentifier::python(),
        );
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert!(findings[0].message.contains("PlaceOrder::execute"));
    }

    #[test]
    fn flags_a_go_service_that_saves_two_aggregates() {
        let code = "package application\n\ntype PlaceOrder struct {\n\tOrders    OrderRepository\n\tInventory InventoryRepository\n}\n\nfunc (p *PlaceOrder) Execute(order Order) {\n\tp.Orders.Save(order)\n\tp.Inventory.Save(order)\n}\n";
        let findings = check(
            "internal/application/place_order.go",
            code,
            LanguageIdentifier::go(),
        );
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert!(findings[0].message.contains("PlaceOrder::Execute"));
    }

    #[test]
    fn silent_with_only_one_repository_in_the_service() {
        let code = "export class PlaceOrder {\n  private orders: OrderRepository;\n  constructor(orders: OrderRepository) {\n    this.orders = orders;\n  }\n  execute(order: Order): void {\n    this.orders.save(order);\n  }\n}\n";
        assert!(
            check(
                "src/application/place_order.ts",
                code,
                LanguageIdentifier::typescript()
            )
            .is_empty()
        );
    }
}
