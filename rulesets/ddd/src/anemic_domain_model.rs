//! Rule: an entity in the domain layer whose every method is a getter or a
//! setter — the **anemic domain model**. The data lives in one place and the
//! rules that govern it live somewhere else (a "service"), so nothing can
//! enforce an invariant, and the object is a database row with extra steps.
//!
//! The detection is the classic "data class" shape CodeQL and every refactoring
//! catalog describe (all members are accessors, no behavior), scoped to the
//! domain layer — which is what turns a neutral observation into a finding. A
//! data-transfer object at the edge of the system *should* be anemic; an
//! aggregate root must not be.
//!
//! Two guards keep this honest:
//! - The class must actually expose accessors. A struct with three fields and no
//!   methods at all is a value object or an event, and calling that anemic would
//!   flag every well-designed record in the model.
//! - Trait implementations don't count as behavior (`Display`, `Serialize` and
//!   friends are shape dictated by the trait, not by the model) — the same
//!   exclusion `smells:low-cohesion` makes.
//!
//! Whole-program (`CrossFileRule`) because a Rust type's methods are commonly
//! split across `impl` blocks in other files, exactly the case
//! `ClassRegistry::build_cross_file` exists for.

use vord_ast::{AstNode, SourceFile};
use vord_rules_engine::{CrossFileRule, Finding, IssueType, RuleId, RuleMetadata, Severity};
use vord_symbols::ClassRegistry;

use crate::common::{accessor_of, declared_methods, field_names, is_domain_path, wire_dto_names};

pub struct AnemicDomainModelRule {
    id: RuleId,
    min_fields: usize,
    min_accessors: usize,
}

impl AnemicDomainModelRule {
    pub fn new(min_fields: usize, min_accessors: usize) -> Self {
        Self {
            id: RuleId::new("ddd:anemic-domain-model").expect("valid rule id"),
            min_fields,
            min_accessors,
        }
    }
}

impl Default for AnemicDomainModelRule {
    /// Three fields and two accessors is the smallest shape where "this is a
    /// data holder, not a model" is a claim worth making.
    fn default() -> Self {
        Self::new(3, 2)
    }
}

impl CrossFileRule for AnemicDomainModelRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn default_severity(&self) -> Severity {
        Severity::Major
    }

    fn remediation_effort_minutes(&self) -> u32 {
        90
    }

    fn issue_type(&self) -> IssueType {
        IssueType::CodeSmell
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "A domain class exposes only getters and setters, so the rules that govern its data live outside it — an anemic domain model that cannot enforce its own invariants.".into(),
            tags: vec!["ddd".into(), "domain-model".into(), "encapsulation".into(), "cross-file".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, files: &[(SourceFile, AstNode)]) -> Vec<(usize, Finding)> {
        let views: Vec<(&str, &AstNode)> = files
            .iter()
            .filter(|(file, _)| is_domain_path(file.path()))
            .filter(|(file, _)| !vord_rules_engine::is_test_only_path(file.path()))
            .map(|(file, ast)| (file.path(), ast))
            .collect();
        if views.is_empty() {
            return Vec::new();
        }
        let registry = ClassRegistry::build_cross_file(&views);
        let dtos: std::collections::BTreeSet<String> = views
            .iter()
            .flat_map(|(_, ast)| wire_dto_names(ast))
            .collect();
        let mut findings = Vec::new();
        for class in registry.iter() {
            if dtos.contains(&class.name) {
                continue; // a type deserialized from outside is meant to be flat
            }
            if class.fields.len() < self.min_fields {
                continue;
            }
            let methods = declared_methods(class);
            let fields = field_names(class);
            let accessors = methods
                .iter()
                .filter(|m| accessor_of(m, &fields).is_some())
                .count();
            if accessors < self.min_accessors || accessors != methods.len() {
                continue;
            }
            let Some(index) = files.iter().position(|(file, _)| file.path() == class.file) else {
                continue;
            };
            let Some(span) = class.span else { continue };
            findings.push((
                index,
                Finding::new(
                    format!(
                        "`{}` holds {} fields behind {} accessors and no behavior of its own — an anemic domain model: whatever service currently changes this data owns the rules that should live here; move them in and let the accessors go",
                        class.name,
                        class.fields.len(),
                        accessors
                    ),
                    span,
                ),
            ));
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
        AnemicDomainModelRule::default()
            .check(&[(file, ast)])
            .into_iter()
            .map(|(_, f)| f)
            .collect()
    }

    const ANEMIC_TS: &str = "export class Order {\n  private id: string = '';\n  private status: string = '';\n  private total: number = 0;\n  getId(): string {\n    return this.id;\n  }\n  getStatus(): string {\n    return this.status;\n  }\n  setStatus(status: string): void {\n    this.status = status;\n  }\n  getTotal(): number {\n    return this.total;\n  }\n}\n";

    #[test]
    fn flags_a_getter_setter_only_entity_in_the_domain_layer() {
        let findings = check(
            "src/domain/order.ts",
            ANEMIC_TS,
            LanguageIdentifier::typescript(),
        );
        assert_eq!(findings.len(), 1);
        assert!(
            findings[0]
                .message
                .contains("`Order` holds 3 fields behind 4 accessors"),
            "{}",
            findings[0].message
        );
    }

    #[test]
    fn silent_outside_the_domain_layer() {
        assert!(
            check(
                "src/adapters/order_dto.ts",
                ANEMIC_TS,
                LanguageIdentifier::typescript()
            )
            .is_empty()
        );
        assert!(
            check(
                "src/dto/order.ts",
                ANEMIC_TS,
                LanguageIdentifier::typescript()
            )
            .is_empty()
        );
    }

    #[test]
    fn silent_when_the_entity_has_real_behavior() {
        let code = "export class Order {\n  private id: string = '';\n  private status: string = '';\n  private total: number = 0;\n  getId(): string {\n    return this.id;\n  }\n  confirm(): void {\n    if (this.total <= 0) {\n      throw new Error('empty order');\n    }\n    this.status = 'confirmed';\n  }\n}\n";
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
    fn a_record_with_no_methods_is_a_value_object_not_an_anemic_model() {
        let code =
            "pub struct Money {\n    amount: i64,\n    currency: String,\n    scale: u8,\n}\n";
        assert!(check("src/domain/money.rs", code, LanguageIdentifier::rust()).is_empty());
    }

    #[test]
    fn flags_a_rust_struct_whose_only_methods_are_accessors() {
        let code = "pub struct Order {\n    id: String,\n    status: String,\n    total: i64,\n}\n\nimpl Order {\n    pub fn id(&self) -> &String {\n        &self.id\n    }\n    pub fn status(&self) -> &String {\n        &self.status\n    }\n    pub fn set_status(&mut self, status: String) {\n        self.status = status;\n    }\n}\n";
        let findings = check("src/domain/order.rs", code, LanguageIdentifier::rust());
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("3 accessors"));
    }

    #[test]
    fn a_trait_impl_does_not_count_as_domain_behavior() {
        let code = "pub struct Order {\n    id: String,\n    status: String,\n    total: i64,\n}\n\nimpl Order {\n    pub fn id(&self) -> &String {\n        &self.id\n    }\n    pub fn status(&self) -> &String {\n        &self.status\n    }\n}\n\nimpl Display for Order {\n    fn fmt(&self, f: &mut Formatter) -> Result {\n        write!(f, \"{}\", self.id)\n    }\n}\n";
        let findings = check("src/domain/order.rs", code, LanguageIdentifier::rust());
        assert_eq!(
            findings.len(),
            1,
            "a Display impl is not behavior the model chose: {findings:?}"
        );
    }

    #[test]
    fn flags_a_python_entity_of_properties_only() {
        let code = "class Order:\n    def __init__(self, id, status, total):\n        self.id = id\n        self.status = status\n        self.total = total\n\n    @property\n    def identifier(self):\n        return self.id\n\n    @property\n    def state(self):\n        return self.status\n";
        let findings = check("src/domain/order.py", code, LanguageIdentifier::python());
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("`Order`"));
    }

    #[test]
    fn silent_below_the_field_floor() {
        let code = "export class Flag {\n  private on: boolean = false;\n  isOn(): boolean {\n    return this.on;\n  }\n  setOn(on: boolean): void {\n    this.on = on;\n  }\n}\n";
        assert!(check("src/domain/flag.ts", code, LanguageIdentifier::typescript()).is_empty());
    }

    #[test]
    fn silent_in_test_only_paths() {
        assert!(
            check(
                "tests/domain/order.ts",
                ANEMIC_TS,
                LanguageIdentifier::typescript()
            )
            .is_empty()
        );
    }
}
