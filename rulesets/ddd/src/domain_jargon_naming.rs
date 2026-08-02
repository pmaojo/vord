//! Rule: a type declared in the domain layer named after the boundary it is
//! supposed to be insulated from — `UserDTO`, `CustomerDao`, `DbRecord`. Ubiquitous
//! language is a two-way contract: the business expert and the code must use the
//! *same* name for a concept, and a domain type spelling out "this crossed a
//! wire" or "this is a database row" in its own name has already broken that
//! contract, whether or not it actually carries a persistence annotation —
//! `ddd:persistence-in-domain` catches the annotation; this catches the name
//! alone, which is evidence on its own that whoever wrote the type was thinking
//! about the boundary, not the concept.
//!
//! Two independent, deliberately narrow signals, combined so as not to flag an
//! ordinary business noun that happens to share a syllable with one:
//! - A suffix that is *only* ever boundary jargon, never an English word on its
//!   own: `Dto`/`DTO`, `Dao`/`DAO`, `Pojo`/`POJO`.
//! - A prefix that spells out an implementation detail no business person
//!   would ever say out loud: `Db`, `Sql`, `Orm`. This is what catches
//!   `DbRecord` — bare `Record` is excluded on purpose, because `MedicalRecord`
//!   and `AttendanceRecord` are legitimate domain nouns in the domains that use
//!   them, and a suffix rule with no prefix requirement would flag both.

use vord_ast::{AstNode, LanguageIdentifier, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

use crate::common::declared_types;
use vord_import_graph::LayerTaxonomy;

const JARGON_SUFFIXES: &[&str] = &["Dto", "DTO", "Dao", "DAO", "Pojo", "POJO"];
const JARGON_PREFIXES: &[&str] = &["Db", "Sql", "Orm"];

/// The boundary-jargon marker a domain type's name carries, if any: the
/// specific prefix or suffix that gave it away, for a message that quotes the
/// evidence rather than just asserting the verdict.
fn jargon_marker(name: &str) -> Option<&'static str> {
    JARGON_SUFFIXES
        .iter()
        .find(|suffix| name.len() > suffix.len() && name.ends_with(*suffix))
        .or_else(|| {
            JARGON_PREFIXES
                .iter()
                .find(|prefix| name.len() > prefix.len() && name.starts_with(*prefix))
        })
        .copied()
}

pub struct DomainJargonNamingRule {
    id: RuleId,
    taxonomy: LayerTaxonomy,
}

impl DomainJargonNamingRule {
    pub fn new() -> Self {
        Self::with_taxonomy(LayerTaxonomy::default())
    }

    /// Same rule, recognizing the domain layer through a project's declared
    /// `[[architecture.layer]]` taxonomy as well as the zero-config
    /// heuristic — see `HexagonalLayerRule::with_taxonomy` for why this is a
    /// strict extension of [`Self::new`].
    pub fn with_taxonomy(taxonomy: LayerTaxonomy) -> Self {
        Self {
            id: RuleId::new("ddd:domain-jargon-naming").expect("valid rule id"),
            taxonomy,
        }
    }
}

impl Default for DomainJargonNamingRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for DomainJargonNamingRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, _language: &LanguageIdentifier) -> bool {
        true
    }

    fn default_severity(&self) -> Severity {
        Severity::Minor
    }

    fn remediation_effort_minutes(&self) -> u32 {
        15
    }

    fn issue_type(&self) -> IssueType {
        IssueType::CodeSmell
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "A type declared in the domain layer is named after the technical boundary it should be insulated from (a DTO/DAO suffix, or a Db/Sql/Orm prefix). Use the business's own name for the concept, and keep the technical name at the adapter that actually owns it.".into(),
            tags: vec!["ddd".into(), "ubiquitous-language".into(), "domain-model".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        if !self.taxonomy.is_domain(file.path())
            || vord_rules_engine::is_test_only_path(file.path())
        {
            return Vec::new();
        }
        declared_types(ast)
            .into_iter()
            .filter_map(|(name, span)| {
                let marker = jargon_marker(name)?;
                Some(Finding::new(
                    format!(
                        "`{name}` is declared in the domain layer but its name carries the `{marker}` marker of a boundary type — give it the business's own name for this concept instead"
                    ),
                    span,
                ))
            })
            .collect()
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
        DomainJargonNamingRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_a_dto_suffixed_typescript_interface_in_the_domain() {
        let code = "export interface UserDTO {\n  id: string;\n}\n";
        let findings = check("src/domain/user.ts", code, LanguageIdentifier::typescript());
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert!(
            findings[0].message.contains("`UserDTO`"),
            "{}",
            findings[0].message
        );
        assert!(findings[0].message.contains("`DTO`"));
    }

    #[test]
    fn flags_a_db_prefixed_rust_struct_in_the_domain() {
        let code = "pub struct DbRecord {\n    id: String,\n}\n";
        let findings = check("src/domain/record.rs", code, LanguageIdentifier::rust());
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert!(findings[0].message.contains("`DbRecord`"));
        assert!(findings[0].message.contains("`Db`"));
    }

    #[test]
    fn a_plain_record_with_no_technical_prefix_is_a_legitimate_domain_noun() {
        let code = "class MedicalRecord:\n    def __init__(self, patient_id):\n        self.patient_id = patient_id\n";
        assert!(
            check(
                "src/domain/medical_record.py",
                code,
                LanguageIdentifier::python()
            )
            .is_empty()
        );
    }

    #[test]
    fn flags_a_dao_suffixed_go_type() {
        let code = "package domain\n\ntype CustomerDao struct {\n\tID string\n}\n";
        let findings = check(
            "internal/domain/customer.go",
            code,
            LanguageIdentifier::go(),
        );
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert!(findings[0].message.contains("`CustomerDao`"));
    }

    #[test]
    fn an_ordinary_domain_class_is_silent() {
        let code = "export class Order {\n  private status: string = 'draft';\n}\n";
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
        // A DTO at the HTTP boundary is exactly what a DTO should be.
        let code = "export interface UserDTO {\n  id: string;\n}\n";
        assert!(
            check(
                "src/adapters/http/user_dto.ts",
                code,
                LanguageIdentifier::typescript()
            )
            .is_empty()
        );
    }

    #[test]
    fn a_bare_dto_with_nothing_before_the_suffix_is_not_flagged() {
        // No business concept has been abbreviated away here — there is no
        // name underneath the suffix to insulate.
        let code = "export interface DTO {\n  id: string;\n}\n";
        assert!(check("src/domain/dto.ts", code, LanguageIdentifier::typescript()).is_empty());
    }

    #[test]
    fn flags_a_rust_trait_class_registry_itself_would_have_skipped() {
        let code = "pub trait CustomerDao {\n    fn find(&self, id: &str);\n}\n";
        let findings = check("src/domain/customer.rs", code, LanguageIdentifier::rust());
        assert_eq!(findings.len(), 1, "{findings:?}");
    }
}
