//! Rule: a public setter on a domain entity. Any caller can replace the field,
//! so the aggregate cannot enforce the rule that makes the change legal — and
//! the change itself carries no meaning. `order.setStatus("shipped")` says
//! nothing about whether the order was paid for; `order.ship()` can refuse.
//!
//! This is the encapsulation half of the anemic-model problem, reported
//! separately because it fires on the far more common intermediate case: a rich
//! entity, full of real behavior, with two leftover setters that let callers
//! route around all of it. `ddd:anemic-domain-model` only speaks when the whole
//! class is accessors.
//!
//! Only *public* setters count, per language convention (Rust `pub`, TypeScript
//! visibility modifiers, Python's leading underscore): a private setter used by
//! the entity's own behavior is an implementation detail, not a hole in the
//! aggregate boundary.

use vord_ast::{AstNode, SourceFile};
use vord_import_graph::LayerTaxonomy;
use vord_rules_engine::{CrossFileRule, Finding, IssueType, RuleId, RuleMetadata, Severity};
use vord_symbols::ClassRegistry;

use crate::common::{AccessorKind, accessor_of, declared_methods, field_names};

/// Whether a method *presents itself* as a setter: `setStatus`, `set_status`,
/// a TypeScript `set status(..)` accessor.
///
/// Body shape alone is not enough, and the difference is the whole point of the
/// rule. `order.review(status)` and `order.setStatus(status)` can compile to the
/// same single assignment, but the first names the thing that happened in the
/// language of the domain — which is exactly the refactoring this rule asks
/// for — while the second names the field it overwrites. Flagging both would
/// mean reporting the fix as the defect, so the name is part of the detection,
/// not decoration on it.
///
/// Matched on `set` followed by a word boundary, so `settle()` is a domain verb
/// rather than a setter for a field called `tle`.
fn is_setter_shaped(name: &str, node_text: &str) -> bool {
    if node_text.trim_start().starts_with("set ") {
        return true; // TypeScript `set status(value) { .. }` accessor
    }
    let Some(rest) = name
        .strip_prefix("set")
        .or_else(|| name.strip_prefix("Set"))
    else {
        return false;
    };
    rest.is_empty() || rest.starts_with('_') || rest.starts_with(|c: char| c.is_uppercase())
}

pub struct PublicEntitySetterRule {
    id: RuleId,
    taxonomy: LayerTaxonomy,
}

impl PublicEntitySetterRule {
    pub fn new() -> Self {
        Self::with_taxonomy(LayerTaxonomy::default())
    }

    /// Same rule, recognizing the domain layer through a project's declared
    /// `[[architecture.layer]]` taxonomy as well as the zero-config
    /// heuristic — see `HexagonalLayerRule::with_taxonomy` for why this is a
    /// strict extension of [`Self::new`].
    pub fn with_taxonomy(taxonomy: LayerTaxonomy) -> Self {
        Self {
            id: RuleId::new("ddd:public-entity-setter").expect("valid rule id"),
            taxonomy,
        }
    }
}

impl Default for PublicEntitySetterRule {
    fn default() -> Self {
        Self::new()
    }
}

impl CrossFileRule for PublicEntitySetterRule {
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
            description: "A domain entity exposes a public setter, letting callers replace its state without going through the rule that makes the change legal. Express the state change as a domain behavior instead.".into(),
            tags: vec!["ddd".into(), "encapsulation".into(), "invariants".into(), "cross-file".into()],
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
            let Some(index) = files.iter().position(|(file, _)| file.path() == class.file) else {
                continue;
            };
            let language = files[index].0.language().clone();
            let fields = field_names(class);
            for method in declared_methods(class) {
                let Some(accessor) = accessor_of(method, &fields) else {
                    continue;
                };
                if accessor.kind != AccessorKind::Setter
                    || !crate::common::is_public(method, &language)
                {
                    continue;
                }
                if !is_setter_shaped(&method.name, method.node.text()) {
                    continue;
                }
                findings.push((
                    index,
                    Finding::new(
                        format!(
                            "`{}::{}` lets any caller replace `{}` directly — the entity cannot enforce the rule that makes that change legal, and the call says nothing about why it happened; replace it with the domain behavior that performs the change",
                            class.name, method.name, accessor.field
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
        } else {
            vord_parser_rust::RustParser::new().parse(&file).unwrap()
        };
        PublicEntitySetterRule::new()
            .check(&[(file, ast)])
            .into_iter()
            .map(|(_, f)| f)
            .collect()
    }

    #[test]
    fn flags_a_public_setter_on_an_entity_that_has_behavior() {
        let code = "export class Order {\n  private status: string = 'draft';\n  setStatus(status: string): void {\n    this.status = status;\n  }\n  ship(): void {\n    if (this.status !== 'paid') {\n      throw new Error('unpaid');\n    }\n    this.status = 'shipped';\n  }\n}\n";
        let findings = check(
            "src/domain/order.ts",
            code,
            LanguageIdentifier::typescript(),
        );
        assert_eq!(findings.len(), 1);
        assert!(
            findings[0].message.contains("`Order::setStatus`"),
            "{}",
            findings[0].message
        );
        assert!(findings[0].message.contains("`status`"));
    }

    #[test]
    fn silent_on_a_private_setter() {
        let code = "export class Order {\n  private status: string = 'draft';\n  private setStatus(status: string): void {\n    this.status = status;\n  }\n}\n";
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
    fn silent_on_a_getter() {
        let code = "export class Order {\n  private status: string = 'draft';\n  getStatus(): string {\n    return this.status;\n  }\n}\n";
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
        let code = "export class OrderRow {\n  private status: string = '';\n  setStatus(status: string): void {\n    this.status = status;\n  }\n}\n";
        assert!(
            check(
                "src/infrastructure/order_row.ts",
                code,
                LanguageIdentifier::typescript()
            )
            .is_empty()
        );
    }

    #[test]
    fn flags_a_public_rust_setter_but_not_a_private_one() {
        let code = "pub struct Order {\n    status: String,\n}\n\nimpl Order {\n    pub fn set_status(&mut self, status: String) {\n        self.status = status;\n    }\n    fn set_status_unchecked(&mut self, status: String) {\n        self.status = status;\n    }\n}\n";
        let findings = check("src/domain/order.rs", code, LanguageIdentifier::rust());
        assert_eq!(findings.len(), 1);
        assert!(
            findings[0].message.contains("set_status`"),
            "{}",
            findings[0].message
        );
    }

    #[test]
    fn flags_a_python_setter_but_not_an_underscored_one() {
        let code = "class Order:\n    def __init__(self):\n        self.status = 'draft'\n\n    def set_status(self, status):\n        self.status = status\n\n    def _set_status(self, status):\n        self.status = status\n";
        let findings = check("src/domain/order.py", code, LanguageIdentifier::python());
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("`Order::set_status`"));
    }

    #[test]
    fn an_intent_named_mutator_is_the_fix_not_the_smell() {
        // `review(status)` compiles to the same assignment `setStatus(status)`
        // would, but it says what happened in the language of the domain.
        let code = "pub struct Hotspot {\n    status: HotspotStatus,\n}\n\nimpl Hotspot {\n    pub fn review(&mut self, status: HotspotStatus) {\n        self.status = status;\n    }\n}\n";
        assert!(check("src/domain/hotspot.rs", code, LanguageIdentifier::rust()).is_empty());
    }

    #[test]
    fn a_domain_verb_that_merely_starts_with_set_is_not_a_setter() {
        let code = "export class Invoice {\n  private state: string = 'open';\n  settle(state: string): void {\n    this.state = state;\n  }\n}\n";
        assert!(
            check(
                "src/domain/invoice.ts",
                code,
                LanguageIdentifier::typescript()
            )
            .is_empty()
        );
    }

    #[test]
    fn a_typescript_set_accessor_is_a_setter() {
        let code = "export class Order {\n  private status: string = 'draft';\n  set state(status: string) {\n    this.status = status;\n  }\n}\n";
        let findings = check(
            "src/domain/order.ts",
            code,
            LanguageIdentifier::typescript(),
        );
        assert_eq!(findings.len(), 1, "{findings:?}");
    }

    #[test]
    fn a_setter_that_enforces_something_is_not_a_setter() {
        let code = "export class Order {\n  private status: string = 'draft';\n  setStatus(status: string): void {\n    if (status === '') {\n      throw new Error('empty');\n    }\n    this.status = status;\n  }\n}\n";
        assert!(
            check(
                "src/domain/order.ts",
                code,
                LanguageIdentifier::typescript()
            )
            .is_empty()
        );
    }
}
