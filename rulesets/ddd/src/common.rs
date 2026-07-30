//! The two questions every rule in this ruleset asks: *is this file inside the
//! model?* and *is this method behavior or plumbing?*
//!
//! Accessor recognition is the load-bearing part. A getter or setter is
//! recognized *structurally* — a single-statement body that does nothing but
//! hand a field out or take one in — rather than by name, because naming
//! conventions disagree across the four languages (`getTotal`, `total`,
//! `total()`, `@property def total`, `func (o *Order) Total()`) while the shape
//! does not. That keeps methods that actually *do* something out of the
//! findings, which is what separates an anemic model from a model with
//! accessors.
//!
//! "Structurally" is meant literally: node kinds, child positions, and — where
//! a grammar hides an operator in an anonymous token — either the explicit node
//! it does carry (Rust's `mutable_specifier`) or the text *between* two operands
//! (`AstNode::text_between`). No rule here pattern-matches source text, so a
//! comment or string literal that happens to read like a field access cannot
//! produce a finding.

use std::collections::BTreeSet;

use yunq_ast::{AstNode, LanguageIdentifier, NodeKind};
use yunq_import_graph::{layer_of, HexLayer};
use yunq_symbols::{ClassInfo, MethodInfo};

/// Whether a method is the constructor of the type that declares it, whatever
/// its language calls one (`yunq_symbols::is_constructor_name`: `constructor`,
/// `__init__`, Rust's `new`, Go's `New<Type>`).
pub fn is_constructor(method: &MethodInfo<'_>, class: &ClassInfo<'_>) -> bool {
    yunq_symbols::is_constructor_name(&method.name, &class.name)
}

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

/// Whether an `Assignment` node uses a compound operator (`+=`, `|=`, …) rather
/// than plain `=`.
///
/// Read off the gap between the two operands (`AstNode::text_between`), because
/// the operator is an anonymous token the neutral AST does not carry and every
/// grammar here collapses `+=` and `=` onto one `NodeKind::Assignment`. A
/// substring search over the statement's text would also match an operator
/// inside a string literal on the right-hand side; the gap cannot.
fn is_compound_assignment(assignment: &AstNode) -> bool {
    let Some(target) = assignment.first_child() else { return false };
    let Some(value) = assignment.children().get(1) else { return false };
    let Some(operator) = assignment.text_between(target, value) else { return false };
    operator.trim() != "="
}

/// The expression a single-statement body evaluates to, with the wrappers that
/// do not change *what* is read peeled off structurally: `return`, Go's
/// `expression_list`, Rust's `reference_expression` (`&x`, `&mut x`).
///
/// Also reports whether a mutable borrow was taken on the way: a Rust
/// `reference_expression` carries an explicit `mutable_specifier` child for
/// `&mut`, so even that is a node rather than a token to match.
fn returned_expression(statement: &AstNode) -> (&AstNode, bool) {
    const TRANSPARENT: &[&str] = &["return_statement", "expression_statement", "expression_list"];
    let mut node = statement;
    let mut mutable = false;
    loop {
        if is_other(node, "reference_expression") {
            // `&mut self.items` is `[mutable_specifier, <operand>]`; `&self.items`
            // is `[<operand>]`. The operand is the last child either way.
            mutable = mutable || node.children().iter().any(|c| is_other(c, "mutable_specifier"));
            let Some(operand) = node.children().last() else { return (node, mutable) };
            node = operand;
            continue;
        }
        let transparent = matches!(node.kind(), NodeKind::Other(k) if TRANSPARENT.contains(&k.as_ref()));
        if !transparent {
            return (node, mutable);
        }
        let Some(inner) = node.first_child() else { return (node, mutable) };
        node = inner;
    }
}

/// A call that hands the same field out under a different owner — `.clone()`,
/// `.to_vec()`, `.iter()` — peeled off so the field read underneath is visible.
/// Structural: a `Call` whose callee is a `MemberAccess` naming one of these.
fn unwrap_pass_through_call(expression: &AstNode) -> &AstNode {
    const PASS_THROUGH: &[&str] =
        &["clone", "to_vec", "to_string", "as_str", "as_slice", "iter", "copied", "to_owned"];
    if *expression.kind() != NodeKind::Call {
        return expression;
    }
    let Some(callee) = expression.first_child() else { return expression };
    if *callee.kind() != NodeKind::MemberAccess {
        return expression;
    }
    let Some(method) = callee.children().get(1) else { return expression };
    if !PASS_THROUGH.contains(&method.text()) {
        return expression;
    }
    callee.first_child().unwrap_or(expression)
}

/// The field a `<instance>.<field>` access reads, where `<instance>` is whatever
/// this language calls the current object: `this`, `self`, or the declared name
/// of a Go receiver (`func (o *Order) ..` -> `o`).
fn accessed_field<'a>(expression: &'a AstNode, receiver: Option<&str>) -> Option<&'a str> {
    if *expression.kind() != NodeKind::MemberAccess {
        return None;
    }
    let base = expression.first_child()?;
    let field = expression.children().get(1)?;
    let is_own_instance = matches!(base.text(), "self" | "this")
        || receiver.is_some_and(|name| !name.is_empty() && base.text() == name);
    (is_own_instance && *field.kind() == NodeKind::Identifier).then(|| field.text())
}

/// Whether `method` is a getter or a setter for one of `fields`, and nothing
/// else. `None` for any method with real behavior — including one that reads a
/// field *and* does something with it.
///
/// Entirely structural: node kinds, child positions and the operator token read
/// from between two operands. Nothing here pattern-matches source text, so a
/// comment or a string literal that happens to look like a field read cannot
/// produce an accessor.
pub fn accessor_of(method: &MethodInfo<'_>, fields: &BTreeSet<String>) -> Option<Accessor> {
    let statements = body_statements(method.node);
    let [only] = statements.as_slice() else { return None };
    let receiver = method.receiver.as_deref();

    // An assignment is wrapped in an `expression_statement` in every grammar
    // here (the "declaration wrapper" shape
    // `core/rules-engine::structural_metrics` documents); unwrap one level.
    let assignment = if *only.kind() == NodeKind::Assignment {
        Some(*only)
    } else {
        only.first_child().filter(|child| *child.kind() == NodeKind::Assignment)
    };
    if let Some(assignment) = assignment {
        if is_compound_assignment(assignment) {
            return None; // `total += amount` accumulates; it does not replace
        }
        // Go wraps each side of an assignment in an `expression_list`.
        let (target, _) = returned_expression(assignment.first_child()?);
        let field = accessed_field(target, receiver)?;
        if !fields.contains(field) {
            return None;
        }
        let (value, _) = returned_expression(assignment.children().get(1)?);
        let assigns_a_parameter = *value.kind() == NodeKind::Identifier
            && method.params.iter().any(|param| param.name == value.text());
        return assigns_a_parameter.then(|| Accessor {
            field: field.to_string(),
            kind: AccessorKind::Setter,
            returns_mutable_reference: false,
        });
    }

    let (expression, mutable) = returned_expression(only);
    let field = accessed_field(unwrap_pass_through_call(expression), receiver)?;
    fields.contains(field).then(|| Accessor {
        field: field.to_string(),
        kind: AccessorKind::Getter,
        returns_mutable_reference: mutable,
    })
}

/// How one language spells "reachable from outside this type".
///
/// A table rather than a chain of language checks, and per-language predicates
/// rather than a `bool` flag threaded through call sites: adding a language is a
/// row here, and no caller has to know which languages exist. Same shape as
/// `yunq_ast::lookup_kind` and `core/symbols::classes::EXTRACTORS`.
const VISIBILITY: &[(&str, VisibilityPolicy)] = &[("rust", rust_is_public), ("go", go_is_public)];

/// Whether one language considers a method reachable from outside its type.
type VisibilityPolicy = fn(&MethodInfo<'_>) -> bool;

/// Rust: an explicit `pub` (the grammar carries it as a `visibility_modifier`
/// child, so this is a node check, not a text prefix).
fn rust_is_public(method: &MethodInfo<'_>) -> bool {
    method.node.children().iter().any(|c| is_other(c, "visibility_modifier"))
}

/// Go: exported means the identifier starts with an upper-case letter. There is
/// no keyword; the name *is* the visibility.
fn go_is_public(method: &MethodInfo<'_>) -> bool {
    method.name.starts_with(|c: char| c.is_uppercase())
}

/// TypeScript/Python (the default): no `private`/`protected` modifier, no
/// `#private` name, and — Python's convention in place of a keyword — no leading
/// underscore.
fn default_is_public(method: &MethodInfo<'_>) -> bool {
    if method.name.starts_with('#') || (method.name.starts_with('_') && !method.name.starts_with("__")) {
        return false;
    }
    !method
        .node
        .children()
        .iter()
        .any(|child| is_other(child, "accessibility_modifier") && child.text() != "public")
}

/// Whether a method is reachable from outside its own type — the only kind whose
/// existence says anything about the type's public design.
pub fn is_public(method: &MethodInfo<'_>, language: &LanguageIdentifier) -> bool {
    let policy = VISIBILITY
        .iter()
        .find(|(name, _)| *name == language.as_str())
        .map(|(_, policy)| *policy)
        .unwrap_or(default_is_public as VisibilityPolicy);
    policy(method)
}

/// The names of every type in `ast` that is a **wire DTO**: a type built to be
/// deserialized from outside the process.
///
/// This is the last piece of "is this the model?", and it is a fact in the code
/// rather than a guess about it. A type that deserializes from the outside world
/// *is* a boundary type by definition, and flat interchangeable primitives with
/// no behavior are precisely its job — so the rules that ask a model to be rich
/// have nothing to say about it. It is also the convention this very codebase
/// documents: domain types are validated newtypes with no `serde::Deserialize`,
/// and every edge owns its DTOs.
///
/// Signals, per language: a Rust `#[derive(..., Deserialize, ...)]` (an
/// `attribute_item` sibling immediately preceding the type), and a Python class
/// deriving Pydantic's `BaseModel` or `TypedDict`. TypeScript has no equivalent
/// marker — a plain `interface` is already outside `ClassRegistry` — so nothing
/// is inferred there.
pub fn wire_dto_names(ast: &AstNode) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    for parent in ast.descendants() {
        let children = parent.children();
        for (index, node) in children.iter().enumerate() {
            if is_other(node, "class_definition") {
                let pydantic = node
                    .children()
                    .iter()
                    .find(|c| is_other(c, "argument_list"))
                    .is_some_and(|bases| {
                        ["BaseModel", "TypedDict"].iter().any(|base| bases.text().contains(base))
                    });
                if pydantic {
                    if let Some(name) = node.children().iter().find(|c| *c.kind() == NodeKind::Identifier) {
                        names.insert(name.text().to_string());
                    }
                }
                continue;
            }
            if !is_other(node, "attribute_item") || !node.text().contains("Deserialize") {
                continue;
            }
            // The derive applies to the next item, skipping any further
            // attributes stacked on the same type.
            let declared = children[index + 1..]
                .iter()
                .find(|next| !is_other(next, "attribute_item"))
                .filter(|next| is_other(next, "struct_item") || is_other(next, "enum_item"));
            if let Some(declared) = declared {
                if let Some(name) = declared.children().iter().find(|c| is_other(c, "type_identifier")) {
                    names.insert(name.text().to_string());
                }
            }
        }
    }
    names
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
        .filter(|method| !is_constructor(method, class) && !method.is_trait_impl())
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
    fn an_accumulating_mutator_is_not_a_setter() {
        let found = accessors(
            "pub struct Metrics {\n    debt_minutes: usize,\n}\n\nimpl Metrics {\n    pub fn add_debt(&mut self, minutes: usize) {\n        self.debt_minutes += minutes;\n    }\n}\n",
            LanguageIdentifier::rust(),
            "Metrics",
        );
        assert!(found.is_empty(), "`+=` changes state relative to itself: {found:?}");
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
        assert!(is_public(order.method("total").unwrap(), &LanguageIdentifier::rust()));
        assert!(!is_public(order.method("internal").unwrap(), &LanguageIdentifier::rust()));

        let ts = parse(
            "t.ts",
            "class Order {\n  private hidden(): void {}\n  shown(): void {}\n}\n",
            LanguageIdentifier::typescript(),
        );
        let ts_registry = ClassRegistry::build(&ts);
        let ts_order = ts_registry.get("Order").unwrap();
        assert!(!is_public(ts_order.method("hidden").unwrap(), &LanguageIdentifier::typescript()));
        assert!(is_public(ts_order.method("shown").unwrap(), &LanguageIdentifier::typescript()));
    }

    #[test]
    fn a_rust_type_deriving_deserialize_is_a_wire_dto() {
        let ast = parse(
            "t.rs",
            "#[derive(Clone, Serialize, Deserialize)]\npub struct Handoff {\n    pub id: String,\n}\n\npub struct Order {\n    id: String,\n}\n",
            LanguageIdentifier::rust(),
        );
        let dtos = wire_dto_names(&ast);
        assert!(dtos.contains("Handoff"));
        assert!(!dtos.contains("Order"), "a type nobody deserializes is not a boundary type");
    }

    #[test]
    fn stacked_attributes_still_resolve_to_the_type_below_them() {
        let ast = parse(
            "t.rs",
            "#[derive(Deserialize)]\n#[serde(rename_all = \"camelCase\")]\npub struct Payload {\n    pub id: String,\n}\n",
            LanguageIdentifier::rust(),
        );
        assert!(wire_dto_names(&ast).contains("Payload"));
    }

    #[test]
    fn a_pydantic_model_is_a_wire_dto() {
        let ast = parse(
            "t.py",
            "class OrderRequest(BaseModel):\n    id: str\n\nclass Order:\n    pass\n",
            LanguageIdentifier::python(),
        );
        let dtos = wire_dto_names(&ast);
        assert!(dtos.contains("OrderRequest"));
        assert!(!dtos.contains("Order"));
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
