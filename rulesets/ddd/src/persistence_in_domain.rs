//! Rule: persistence mapping declared on a domain type — an ORM annotation, a
//! mapped base class, a `#[derive(Queryable)]`. The model now has two masters:
//! the business rule it exists to express, and the table it has to match. Every
//! schema migration becomes a domain change, and the aggregate's shape is
//! decided by what the database can store.
//!
//! The hexagonal answer is a separate persistence model in the adapter that
//! translates to and from the domain type, which is precisely the mapping work
//! an ORM annotation exists to avoid — so this rule is a genuine trade-off
//! called out loud, not a bug report. It is scoped to the *domain layer* only:
//! the same annotations on an `infrastructure/` row type are exactly right.
//!
//! Per-file (`Rule`): an annotation is a local fact.
//!
//! The annotation roster mirrors what Semgrep's per-framework packs recognize
//! for the same libraries (`semgrep-rules/python/{django,sqlalchemy}`,
//! `javascript/sequelize`, `typescript/nestjs`) — a fixed list of the mapping
//! markers each ORM actually uses.

use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use yunq_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

use crate::common::{is_domain_path, is_other};

/// TypeScript/JavaScript decorator markers: TypeORM, Sequelize (`sequelize-
/// typescript`), Nest/Mongoose schemas, MikroORM.
const TS_DECORATORS: &[&str] = &[
    "Entity",
    "Table",
    "Column",
    "PrimaryGeneratedColumn",
    "PrimaryColumn",
    "ManyToOne",
    "OneToMany",
    "ManyToMany",
    "OneToOne",
    "JoinColumn",
    "JoinTable",
    "Schema",
    "Prop",
    "Model",
    "ForeignKey",
    "BelongsTo",
    "HasMany",
    "Property",
];

/// Python mapped-base classes and mapping helpers: Django, SQLAlchemy (both the
/// declarative and the 2.0 style), SQLModel, MongoEngine, Beanie.
const PYTHON_BASES: &[&str] =
    &["models.Model", "DeclarativeBase", "SQLModel", "Document", "EmbeddedDocument", "Base"];
const PYTHON_MAPPERS: &[&str] =
    &["Column(", "mapped_column(", "relationship(", "declarative_base(", "ForeignKey("];

/// Rust derive/attribute markers: Diesel, SQLx, SeaORM.
const RUST_MARKERS: &[&str] = &[
    "Queryable",
    "Insertable",
    "AsChangeset",
    "Identifiable",
    "Selectable",
    "FromRow",
    "DeriveEntityModel",
    "DeriveActiveModel",
    "diesel(",
    "sqlx(",
    "table_name",
    "sea_orm(",
];

/// Every persistence marker in this file: (marker text, span).
fn markers(file: &SourceFile, ast: &AstNode) -> Vec<(String, yunq_ast::Span)> {
    let language = file.language();
    if *language == LanguageIdentifier::typescript() {
        return ast
            .descendants()
            .filter(|n| is_other(n, "decorator"))
            .filter_map(|node| {
                let name = node.text().trim_start_matches('@');
                let name = name.split(['(', '<', ' ']).next().unwrap_or(name).trim();
                TS_DECORATORS
                    .contains(&name)
                    .then(|| (format!("@{name}"), node.span()))
            })
            .collect();
    }
    if *language == LanguageIdentifier::python() {
        let mut found = Vec::new();
        for class in ast.descendants().filter(|n| is_other(n, "class_definition")) {
            let Some(bases) = class.children().iter().find(|c| is_other(c, "argument_list")) else { continue };
            if let Some(base) = PYTHON_BASES.iter().find(|base| bases.text().contains(*base)) {
                found.push((base.to_string(), class.span()));
            }
        }
        for call in ast.descendants().filter(|n| *n.kind() == NodeKind::Call) {
            let text = call.text();
            if let Some(mapper) = PYTHON_MAPPERS.iter().find(|mapper| text.starts_with(*mapper)) {
                found.push((mapper.trim_end_matches('(').to_string(), call.span()));
            }
        }
        return found;
    }
    if *language == LanguageIdentifier::rust() {
        return ast
            .descendants()
            .filter(|n| is_other(n, "attribute_item"))
            .filter_map(|node| {
                let text = node.text();
                RUST_MARKERS
                    .iter()
                    .find(|marker| text.contains(*marker))
                    .map(|marker| (marker.trim_end_matches('(').to_string(), node.span()))
            })
            .collect();
    }
    Vec::new()
}

pub struct PersistenceInDomainRule {
    id: RuleId,
}

impl PersistenceInDomainRule {
    pub fn new() -> Self {
        Self { id: RuleId::new("ddd:persistence-in-domain").expect("valid rule id") }
    }
}

impl Default for PersistenceInDomainRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for PersistenceInDomainRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, language: &LanguageIdentifier) -> bool {
        *language == LanguageIdentifier::typescript()
            || *language == LanguageIdentifier::python()
            || *language == LanguageIdentifier::rust()
    }

    fn default_severity(&self) -> Severity {
        Severity::Minor
    }

    fn remediation_effort_minutes(&self) -> u32 {
        60
    }

    fn issue_type(&self) -> IssueType {
        IssueType::CodeSmell
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "A domain type carries persistence mapping (ORM annotation, mapped base class, row-mapping derive), so its shape is decided by the database schema. Keep a separate persistence model in the adapter and translate.".into(),
            tags: vec!["ddd".into(), "hexagonal".into(), "persistence-ignorance".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        if !is_domain_path(file.path()) || yunq_rules_engine::is_test_only_path(file.path()) {
            return Vec::new();
        }
        markers(file, ast)
            .into_iter()
            .map(|(marker, span)| {
                Finding::new(
                    format!(
                        "`{marker}` maps this domain type to a database schema — the model now answers to the table as well as to the business rule; keep the mapping on a persistence model in the adapter and translate to the domain type"
                    ),
                    span,
                )
            })
            .collect()
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
        PersistenceInDomainRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_typeorm_decorators_on_a_domain_entity() {
        let code = "@Entity()\nexport class Order {\n  @PrimaryGeneratedColumn()\n  id: number;\n}\n";
        let findings = check("src/domain/order.ts", code, LanguageIdentifier::typescript());
        assert_eq!(findings.len(), 2);
        assert!(findings[0].message.contains("`@Entity`"), "{}", findings[0].message);
    }

    #[test]
    fn silent_on_the_same_decorators_in_the_infrastructure_layer() {
        let code = "@Entity()\nexport class OrderRow {\n  @Column()\n  id: number;\n}\n";
        assert!(check("src/infrastructure/order_row.ts", code, LanguageIdentifier::typescript()).is_empty());
    }

    #[test]
    fn silent_on_unrelated_decorators() {
        let code = "@Injectable()\nexport class OrderPolicy {}\n";
        assert!(check("src/domain/order_policy.ts", code, LanguageIdentifier::typescript()).is_empty());
    }

    #[test]
    fn flags_a_django_model_base_in_the_domain() {
        let code = "class Order(models.Model):\n    pass\n";
        let findings = check("src/domain/order.py", code, LanguageIdentifier::python());
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("models.Model"));
    }

    #[test]
    fn flags_a_sqlalchemy_column_mapping_in_the_domain() {
        let code = "class Order:\n    id = Column(Integer, primary_key=True)\n";
        let findings = check("src/domain/order.py", code, LanguageIdentifier::python());
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("Column"));
    }

    #[test]
    fn silent_on_a_plain_python_entity() {
        let code = "class Order:\n    def __init__(self, total):\n        self.total = total\n";
        assert!(check("src/domain/order.py", code, LanguageIdentifier::python()).is_empty());
    }

    #[test]
    fn flags_a_diesel_derive_on_a_domain_struct() {
        let code = "#[derive(Queryable, Insertable)]\npub struct Order {\n    pub id: i32,\n}\n";
        let findings = check("src/domain/order.rs", code, LanguageIdentifier::rust());
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("Queryable"));
    }

    #[test]
    fn silent_on_an_ordinary_rust_derive() {
        let code = "#[derive(Clone, Debug, PartialEq)]\npub struct Order {\n    pub id: i32,\n}\n";
        assert!(check("src/domain/order.rs", code, LanguageIdentifier::rust()).is_empty());
    }

    #[test]
    fn silent_in_test_only_paths() {
        let code = "@Entity()\nexport class Order {}\n";
        assert!(check("tests/domain/order.ts", code, LanguageIdentifier::typescript()).is_empty());
    }
}
