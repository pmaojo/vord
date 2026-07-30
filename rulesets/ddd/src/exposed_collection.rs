//! Rule: an aggregate that hands out its internal collection. `order.getItems()`
//! returning the very list the order keeps means any caller can `push`, `pop` or
//! clear it — the aggregate's rules ("a confirmed order cannot gain items", "no
//! more than fifty lines") never run, and its invariants hold only as long as
//! nobody takes the offer.
//!
//! This is the aggregate-boundary counterpart to `ddd:public-entity-setter`: a
//! setter replaces state, an exposed collection lets state be edited in place,
//! which is harder to see and just as final.
//!
//! Language-honest by design:
//! - TypeScript/Python: returning the field itself aliases it, so it is a
//!   finding. A getter that copies (`[...this.items]`, `list(self._items)`,
//!   `this.items.slice()`) does not read as handing the field out at all and is
//!   silently correct.
//! - Rust: `&Vec<T>` cannot be mutated through a shared borrow, so only
//!   `&mut self.items` is a hole. The borrow checker already enforces what this
//!   rule has to check by hand elsewhere.

use std::collections::BTreeSet;

use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use yunq_rules_engine::{CrossFileRule, Finding, IssueType, RuleId, RuleMetadata, Severity};
use yunq_symbols::{ClassInfo, ClassRegistry};

use crate::common::{accessor_of, field_names, is_domain_path, is_public, AccessorKind, CONSTRUCTOR_NAMES};

/// Declared types that are collections, across the three languages' spellings.
const COLLECTION_TYPES: &[&str] = &[
    "Array", "ReadonlyArray", "Set", "Map", "WeakMap", "WeakSet", "Record", "List", "Sequence",
    "Iterable", "Dict", "list", "dict", "set", "frozenset", "tuple", "Vec", "VecDeque", "HashMap",
    "HashSet", "BTreeMap", "BTreeSet", "IndexMap", "IndexSet",
];

/// Initializers that create an empty collection — how a field's collection-ness
/// is recognized when it carries no declared type (Python instance attributes,
/// plain JavaScript).
const COLLECTION_INITIALIZERS: &[&str] = &[
    "[", "list(", "dict(", "set(", "frozenset(", "new Map(", "new Set(", "new Array(", "vec![",
    "Vec::new(", "VecDeque::new(", "HashMap::new(", "HashSet::new(", "BTreeMap::new(",
    "BTreeSet::new(", "Vec::with_capacity(",
];

fn is_collection_type(declared: &str) -> bool {
    let text = declared.trim().trim_start_matches('&').trim_start_matches("mut ").trim();
    if text.contains("[]") {
        return true;
    }
    COLLECTION_TYPES.iter().any(|name| {
        text.strip_prefix(name).is_some_and(|rest| {
            rest.is_empty() || rest.starts_with('<') || rest.starts_with('[') || rest.starts_with("::")
        })
    })
}

/// The fields of `class` that hold a collection, by declared type or by what the
/// constructor assigns them.
fn collection_fields(class: &ClassInfo<'_>) -> BTreeSet<String> {
    let mut fields: BTreeSet<String> = class
        .fields
        .iter()
        .filter(|field| field.declared_type.as_deref().is_some_and(is_collection_type))
        .map(|field| field.name.clone())
        .collect();
    let declared = field_names(class);
    for constructor in class.methods.iter().filter(|m| CONSTRUCTOR_NAMES.contains(&m.name.as_str())) {
        for assignment in constructor.node.descendants().filter(|n| *n.kind() == NodeKind::Assignment) {
            let Some(target) = assignment.first_child() else { continue };
            if *target.kind() != NodeKind::MemberAccess {
                continue;
            }
            let Some(base) = target.first_child() else { continue };
            let Some(name) = target.children().get(1) else { continue };
            if !matches!(base.text(), "self" | "this") || !declared.contains(name.text()) {
                continue;
            }
            let Some(value) = assignment.children().get(1) else { continue };
            let value_text = value.text().trim_start();
            if COLLECTION_INITIALIZERS.iter().any(|init| value_text.starts_with(init)) {
                fields.insert(name.text().to_string());
            }
        }
    }
    fields
}

pub struct ExposedCollectionRule {
    id: RuleId,
}

impl ExposedCollectionRule {
    pub fn new() -> Self {
        Self { id: RuleId::new("ddd:aggregate-exposes-internal-collection").expect("valid rule id") }
    }
}

impl Default for ExposedCollectionRule {
    fn default() -> Self {
        Self::new()
    }
}

impl CrossFileRule for ExposedCollectionRule {
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
            description: "An aggregate returns its internal collection, letting callers mutate its contents without the aggregate's rules running. Return a copy or a read-only view and expose intent-revealing methods for changes.".into(),
            tags: vec!["ddd".into(), "aggregate".into(), "encapsulation".into(), "invariants".into(), "cross-file".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, files: &[(SourceFile, AstNode)]) -> Vec<(usize, Finding)> {
        let views: Vec<(&str, &AstNode)> = files
            .iter()
            .filter(|(file, _)| is_domain_path(file.path()))
            .filter(|(file, _)| !yunq_rules_engine::is_test_only_path(file.path()))
            .map(|(file, ast)| (file.path(), ast))
            .collect();
        if views.is_empty() {
            return Vec::new();
        }
        let registry = ClassRegistry::build_cross_file(&views);
        let mut findings = Vec::new();
        for class in registry.iter() {
            let Some(index) = files.iter().position(|(file, _)| file.path() == class.file) else { continue };
            let is_rust = *files[index].0.language() == LanguageIdentifier::rust();
            let fields = field_names(class);
            let collections = collection_fields(class);
            for method in &class.methods {
                let Some(accessor) = accessor_of(method, &fields) else { continue };
                if accessor.kind != AccessorKind::Getter || !collections.contains(&accessor.field) {
                    continue;
                }
                if !is_public(method, is_rust) {
                    continue;
                }
                // In Rust a shared borrow is already immutable; only a mutable
                // one hands out the ability to change the aggregate's interior.
                if is_rust && !accessor.returns_mutable_reference {
                    continue;
                }
                findings.push((
                    index,
                    Finding::new(
                        format!(
                            "`{}::{}` hands out the aggregate's own `{}` collection — a caller can add or remove elements with none of `{}`'s rules running; return a copy or read-only view and expose the operations that are actually allowed",
                            class.name, method.name, accessor.field, class.name
                        ),
                        method.span,
                    ),
                ));
            }
        }
        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use yunq_rules_engine::AstParser;

    fn check(path: &str, code: &str, language: LanguageIdentifier) -> Vec<Finding> {
        let file = SourceFile::new(path, code, language.clone()).unwrap();
        let ast = if language == LanguageIdentifier::typescript() {
            yunq_parser_typescript::TypeScriptParser::new().parse(&file).unwrap()
        } else if language == LanguageIdentifier::python() {
            yunq_parser_python::PythonParser::new().parse(&file).unwrap()
        } else {
            yunq_parser_rust::RustParser::new().parse(&file).unwrap()
        };
        ExposedCollectionRule::new().check(&[(file, ast)]).into_iter().map(|(_, f)| f).collect()
    }

    #[test]
    fn flags_a_typescript_getter_returning_the_internal_array() {
        let code = "export class Order {\n  private items: OrderLine[] = [];\n  getItems(): OrderLine[] {\n    return this.items;\n  }\n}\n";
        let findings = check("src/domain/order.ts", code, LanguageIdentifier::typescript());
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("`Order::getItems`"), "{}", findings[0].message);
        assert!(findings[0].message.contains("`items`"));
    }

    #[test]
    fn silent_when_the_getter_copies_the_collection() {
        let code = "export class Order {\n  private items: OrderLine[] = [];\n  getItems(): OrderLine[] {\n    return [...this.items];\n  }\n}\n";
        assert!(check("src/domain/order.ts", code, LanguageIdentifier::typescript()).is_empty());
    }

    #[test]
    fn silent_when_the_getter_returns_a_slice_copy() {
        let code = "export class Order {\n  private items: OrderLine[] = [];\n  getItems(): OrderLine[] {\n    return this.items.slice();\n  }\n}\n";
        assert!(check("src/domain/order.ts", code, LanguageIdentifier::typescript()).is_empty());
    }

    #[test]
    fn silent_on_a_scalar_field() {
        let code = "export class Order {\n  private total: number = 0;\n  getTotal(): number {\n    return this.total;\n  }\n}\n";
        assert!(check("src/domain/order.ts", code, LanguageIdentifier::typescript()).is_empty());
    }

    #[test]
    fn silent_outside_the_domain_layer() {
        let code = "export class OrderView {\n  private items: OrderLine[] = [];\n  getItems(): OrderLine[] {\n    return this.items;\n  }\n}\n";
        assert!(check("src/adapters/order_view.ts", code, LanguageIdentifier::typescript()).is_empty());
    }

    #[test]
    fn flags_a_python_getter_of_a_list_field_inferred_from_the_constructor() {
        let code = "class Order:\n    def __init__(self):\n        self.items = []\n\n    def get_items(self):\n        return self.items\n";
        let findings = check("src/domain/order.py", code, LanguageIdentifier::python());
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("`items`"));
    }

    #[test]
    fn silent_when_the_python_getter_copies() {
        let code = "class Order:\n    def __init__(self):\n        self.items = []\n\n    def get_items(self):\n        return list(self.items)\n";
        assert!(check("src/domain/order.py", code, LanguageIdentifier::python()).is_empty());
    }

    #[test]
    fn rust_shared_borrow_is_fine_but_a_mutable_one_is_not() {
        let shared = "pub struct Order {\n    items: Vec<OrderLine>,\n}\n\nimpl Order {\n    pub fn items(&self) -> &Vec<OrderLine> {\n        &self.items\n    }\n}\n";
        assert!(check("src/domain/order.rs", shared, LanguageIdentifier::rust()).is_empty());

        let mutable = "pub struct Order {\n    items: Vec<OrderLine>,\n}\n\nimpl Order {\n    pub fn items_mut(&mut self) -> &mut Vec<OrderLine> {\n        &mut self.items\n    }\n}\n";
        let findings = check("src/domain/order.rs", mutable, LanguageIdentifier::rust());
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("`Order::items_mut`"));
    }

    #[test]
    fn silent_on_a_private_getter() {
        let code = "export class Order {\n  private items: OrderLine[] = [];\n  private getItems(): OrderLine[] {\n    return this.items;\n  }\n}\n";
        assert!(check("src/domain/order.ts", code, LanguageIdentifier::typescript()).is_empty());
    }

    #[test]
    fn collection_type_spellings_are_recognized() {
        assert!(is_collection_type("OrderLine[]"));
        assert!(is_collection_type("Array<OrderLine>"));
        assert!(is_collection_type("Map<string, OrderLine>"));
        assert!(is_collection_type("list[OrderLine]"));
        assert!(is_collection_type("&mut Vec<OrderLine>"));
        assert!(!is_collection_type("Money"));
        assert!(!is_collection_type("number"));
    }
}
