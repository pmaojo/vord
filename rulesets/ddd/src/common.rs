//! The two questions every rule in this ruleset asks: *is this file inside the
//! model?* and *is this method behavior or plumbing?*
//!
//! Accessor recognition is the load-bearing part. A getter or setter is
//! recognized structurally — a single-statement body that does nothing but hand
//! a field out or take one in — rather than by name, because naming conventions
//! disagree across the three languages (`getTotal`, `total`, `total()`,
//! `@property def total`) while the shape does not. That keeps
//! `set_visibility`-style methods that actually *do* something out of the
//! findings, which is what separates an anemic model from a model with
//! accessors.

use std::collections::BTreeSet;

use yunq_ast::{AstNode, NodeKind};
use yunq_import_graph::{layer_of, HexLayer};
use yunq_symbols::{ClassInfo, MethodInfo};

/// Constructor names across the three grammars (`new` for Rust, by universal
/// convention).
pub const CONSTRUCTOR_NAMES: &[&str] = &["constructor", "__init__", "new"];

pub fn is_other(node: &AstNode, kind: &str) -> bool {
    matches!(node.kind(), NodeKind::Other(k) if k.as_ref() == kind)
}

/// Whether a path names code inside the model — the domain layer proper, where
/// entities, aggregates and value objects live.
///
/// Deliberately narrower than `architecture:framework-in-domain`'s inner ring:
/// tactical DDD patterns are claims about the *model*, and an application
/// service being a thin orchestrator with no behavior of its own is correct
/// design, not an anemic one.
pub fn is_domain_path(path: &str) -> bool {
    layer_of(path) == HexLayer::Domain
}

/// The statements making up a method's body: TS `statement_block`, Python and
/// Rust `block`.
pub fn body_statements(method: &AstNode) -> Vec<&AstNode> {
    method
        .children()
        .iter()
        .find(|c| is_other(c, "statement_block") || is_other(c, "block"))
        .map(|body| body.children().iter().collect())
        .unwrap_or_default()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccessorKind {
    /// Hands a field out unchanged.
    Getter,
    /// Takes a value in and stores it on a field, unchanged.
    Setter,
}

/// A method that only moves one field in or out.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Accessor {
    pub field: String,
    pub kind: AccessorKind,
    /// Rust `&mut self.field` — the getter hands out a mutable borrow, so the
    /// caller can mutate the aggregate's interior directly.
    pub returns_mutable_reference: bool,
}

/// Strips the syntax that surrounds a bare field read without changing what is
/// read: `return`, a borrow, a trailing `;`, and the copy-free "conversions"
/// that still alias or clone the very same field.
fn normalize_field_read(statement: &str) -> (String, bool) {
    let text = statement.trim();
    let text = text.strip_suffix(';').unwrap_or(text).trim();
    let text = text.strip_prefix("return").map(str::trim).unwrap_or(text);
    let (text, mutable) = match text.strip_prefix("&mut ") {
        Some(rest) => (rest.trim(), true),
        None => (text.strip_prefix('&').map(str::trim).unwrap_or(text), false),
    };
    let text = text.strip_suffix("()").map(str::trim).unwrap_or(text);
    let text = ["\u{2e}clone", ".to_vec", ".to_string", ".as_str", ".as_slice", ".iter", ".copied"]
        .iter()
        .fold(text, |acc, suffix| acc.strip_suffix(suffix).map(str::trim).unwrap_or(acc));
    (text.trim().to_string(), mutable)
}

/// The field a `self.x`/`this.x` read names, if the text is exactly that.
fn read_field(text: &str) -> Option<&str> {
    ["self.", "this."].iter().find_map(|prefix| {
        let rest = text.strip_prefix(prefix)?;
        (!rest.is_empty() && rest.chars().all(|c| c.is_alphanumeric() || c == '_')).then_some(rest)
    })
}

/// Whether `method` is a getter or a setter for one of `fields`, and nothing
/// else. `None` for any method with real behavior — including one that reads a
/// field *and* does something with it.
pub fn accessor_of(method: &MethodInfo<'_>, fields: &BTreeSet<String>) -> Option<Accessor> {
    let statements = body_statements(method.node);
    let [only] = statements.as_slice() else { return None };

    // An assignment statement is wrapped in an `expression_statement` in all
    // three grammars (the same "declaration wrapper" shape
    // `core/rules-engine::structural_metrics` documents); unwrap one level.
    let assignment = if *only.kind() == NodeKind::Assignment {
        Some(*only)
    } else {
        only.first_child().filter(|child| *child.kind() == NodeKind::Assignment)
    };
    if let Some(only) = assignment {
        let target = only.first_child()?;
        if *target.kind() != NodeKind::MemberAccess {
            return None;
        }
        let (base, field) = (target.first_child()?, target.children().get(1)?);
        if !matches!(base.text(), "self" | "this") || !fields.contains(field.text()) {
            return None;
        }
        let value = only.children().get(1)?;
        let assigns_a_parameter = *value.kind() == NodeKind::Identifier
            && method.params.iter().any(|param| param.name == value.text());
        return assigns_a_parameter.then(|| Accessor {
            field: field.text().to_string(),
            kind: AccessorKind::Setter,
            returns_mutable_reference: false,
        });
    }

    let (normalized, mutable) = normalize_field_read(only.text());
    let field = read_field(&normalized)?;
    fields.contains(field).then(|| Accessor {
        field: field.to_string(),
        kind: AccessorKind::Getter,
        returns_mutable_reference: mutable,
    })
}

/// Whether a method is reachable from outside its own type — the only kind
/// whose existence says anything about the type's public design.
///
/// Rust: a `pub` visibility modifier. TypeScript: no `private`/`protected`
/// modifier and no `#private` name. Python: no leading underscore (the
/// convention the language has instead of a keyword).
pub fn is_public(method: &MethodInfo<'_>, language_is_rust: bool) -> bool {
    let text = method.node.text().trim_start();
    if language_is_rust {
        return text.starts_with("pub");
    }
    if method.name.starts_with('#') || method.name.starts_with('_') && !method.name.starts_with("__") {
        return false;
    }
    !method
        .node
        .children()
        .iter()
        .any(|child| is_other(child, "accessibility_modifier") && child.text() != "public")
}

/// A class's declared field names.
pub fn field_names(class: &ClassInfo<'_>) -> BTreeSet<String> {
    class.fields.iter().map(|field| field.name.clone()).collect()
}

/// The methods that say something about how the type was designed: not
/// constructors (whose shape is dictated by the fields) and not trait
/// obligations (whose shape is dictated by the trait) — the same exclusion
/// `smells:low-cohesion` documents and for the same reason.
pub fn declared_methods<'a, 'b>(class: &'b ClassInfo<'a>) -> Vec<&'b MethodInfo<'a>> {
    class
        .methods
        .iter()
        .filter(|method| !CONSTRUCTOR_NAMES.contains(&method.name.as_str()) && !method.is_trait_impl())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use yunq_ast::{LanguageIdentifier, SourceFile};
    use yunq_rules_engine::AstParser;
    use yunq_symbols::ClassRegistry;

    fn parse(path: &str, code: &str, language: LanguageIdentifier) -> AstNode {
        let file = SourceFile::new(path, code, language.clone()).unwrap();
        if language == LanguageIdentifier::typescript() {
            yunq_parser_typescript::TypeScriptParser::new().parse(&file).unwrap()
        } else if language == LanguageIdentifier::python() {
            yunq_parser_python::PythonParser::new().parse(&file).unwrap()
        } else {
            yunq_parser_rust::RustParser::new().parse(&file).unwrap()
        }
    }

    fn accessors(code: &str, language: LanguageIdentifier, class_name: &str) -> Vec<(String, Accessor)> {
        let ast = parse("t", code, language);
        let registry = ClassRegistry::build(&ast);
        let class = registry.get(class_name).expect("class in registry");
        let fields = field_names(class);
        class
            .methods
            .iter()
            .filter_map(|method| {
                accessor_of(method, &fields).map(|accessor| (method.name.clone(), accessor))
            })
            .collect()
    }

    #[test]
    fn typescript_getter_and_setter_are_recognized() {
        let found = accessors(
            "class Order {\n  private total: number = 0;\n  getTotal(): number {\n    return this.total;\n  }\n  setTotal(total: number): void {\n    this.total = total;\n  }\n}\n",
            LanguageIdentifier::typescript(),
            "Order",
        );
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].1.kind, AccessorKind::Getter);
        assert_eq!(found[1].1.kind, AccessorKind::Setter);
        assert_eq!(found[0].1.field, "total");
    }

    #[test]
    fn a_method_with_behavior_is_not_an_accessor() {
        let found = accessors(
            "class Order {\n  private total: number = 0;\n  confirm(): void {\n    this.total = this.total + 1;\n    this.audit();\n  }\n}\n",
            LanguageIdentifier::typescript(),
            "Order",
        );
        assert!(found.is_empty());
    }

    #[test]
    fn a_setter_that_validates_is_not_an_accessor() {
        let found = accessors(
            "class Order {\n  private total: number = 0;\n  setTotal(total: number): void {\n    if (total < 0) {\n      throw new Error('negative');\n    }\n    this.total = total;\n  }\n}\n",
            LanguageIdentifier::typescript(),
            "Order",
        );
        assert!(found.is_empty(), "a guarded setter enforces an invariant: {found:?}");
    }

    #[test]
    fn python_property_getter_is_recognized() {
        let found = accessors(
            "class Order:\n    def __init__(self):\n        self.total = 0\n\n    @property\n    def total_value(self):\n        return self.total\n",
            LanguageIdentifier::python(),
            "Order",
        );
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].1.kind, AccessorKind::Getter);
    }

    #[test]
    fn rust_borrowing_getters_are_recognized_and_mutability_is_kept() {
        let found = accessors(
            "pub struct Order {\n    items: Vec<Item>,\n}\n\nimpl Order {\n    pub fn items(&self) -> &Vec<Item> {\n        &self.items\n    }\n    pub fn items_mut(&mut self) -> &mut Vec<Item> {\n        &mut self.items\n    }\n}\n",
            LanguageIdentifier::rust(),
            "Order",
        );
        assert_eq!(found.len(), 2);
        assert!(!found[0].1.returns_mutable_reference);
        assert!(found[1].1.returns_mutable_reference);
    }

    #[test]
    fn a_cloning_getter_still_hands_the_same_field_out() {
        let found = accessors(
            "pub struct Order {\n    items: Vec<Item>,\n}\n\nimpl Order {\n    pub fn items(&self) -> Vec<Item> {\n        self.items.clone()\n    }\n}\n",
            LanguageIdentifier::rust(),
            "Order",
        );
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].1.kind, AccessorKind::Getter);
    }

    #[test]
    fn visibility_is_read_per_language() {
        let ast = parse(
            "t.rs",
            "pub struct Order {\n    total: i64,\n}\n\nimpl Order {\n    pub fn total(&self) -> i64 {\n        self.total\n    }\n    fn internal(&self) -> i64 {\n        self.total\n    }\n}\n",
            LanguageIdentifier::rust(),
        );
        let registry = ClassRegistry::build(&ast);
        let order = registry.get("Order").unwrap();
        assert!(is_public(order.method("total").unwrap(), true));
        assert!(!is_public(order.method("internal").unwrap(), true));

        let ts = parse(
            "t.ts",
            "class Order {\n  private hidden(): void {}\n  shown(): void {}\n}\n",
            LanguageIdentifier::typescript(),
        );
        let ts_registry = ClassRegistry::build(&ts);
        let ts_order = ts_registry.get("Order").unwrap();
        assert!(!is_public(ts_order.method("hidden").unwrap(), false));
        assert!(is_public(ts_order.method("shown").unwrap(), false));
    }

    #[test]
    fn domain_paths_are_the_model_only() {
        assert!(is_domain_path("src/domain/order.ts"));
        assert!(is_domain_path("src/entities/order.py"));
        assert!(!is_domain_path("src/application/place_order.ts"));
        assert!(!is_domain_path("src/infrastructure/orders.ts"));
        assert!(!is_domain_path("src/lib/util.ts"));
    }
}
