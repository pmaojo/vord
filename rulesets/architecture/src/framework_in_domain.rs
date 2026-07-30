//! Rule: a file in an inner ring (domain, application, or a port
//! declaration) importing a framework or an I/O library directly — an HTTP
//! client, an ORM, a web framework, a cloud SDK, the filesystem.
//!
//! This is the *purity* half of hexagonal enforcement, and it catches what
//! the graph rules structurally cannot: `architecture:hexagonal-layer-violation`
//! only sees edges between two files in the analyzed set, so a domain entity
//! that skips the local `infrastructure/` package entirely and talks to
//! `sqlalchemy`/`axios`/`reqwest` itself produces no edge and no finding. The
//! dependency that hurts most is the one on code you don't even own.
//!
//! Per-file (`Rule`): a file's own import list and its own path are all this
//! needs.
//!
//! The module roster itself now lives in `yunq_import_graph::infra_roster` —
//! curated, not inferred, and shared with `ddd:bdd-step-reaches-infra`, which
//! needs the identical "does this code reach outside the process" vocabulary
//! at call sites inside a Gherkin step implementation rather than at a file's
//! own import list.

use yunq_ast::{AstNode, LanguageIdentifier, SourceFile};
use yunq_import_graph::{imported_modules, infra_roster, layer_of, matches_module, HexLayer};
use yunq_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

/// The rings that must stay pure. Adapters and infrastructure are *supposed*
/// to import frameworks — that is their entire job.
fn is_inner_ring(layer: HexLayer) -> bool {
    matches!(layer, HexLayer::Domain | HexLayer::Application | HexLayer::Port)
}

pub struct FrameworkInDomainRule {
    id: RuleId,
}

impl FrameworkInDomainRule {
    pub fn new() -> Self {
        Self { id: RuleId::new("architecture:framework-in-domain").expect("valid rule id") }
    }
}

impl Default for FrameworkInDomainRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for FrameworkInDomainRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, language: &LanguageIdentifier) -> bool {
        !infra_roster(language).is_empty()
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
            description: "Domain, application or port code imports a framework or I/O library directly (HTTP client, ORM, web framework, cloud SDK, filesystem), so the inside of the hexagon now depends on a technical detail. Move the call behind a port implemented by an adapter.".into(),
            tags: vec![
                "architecture".into(),
                "hexagonal".into(),
                "dependency-inversion".into(),
                "purity".into(),
            ],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        if yunq_rules_engine::is_test_only_path(file.path()) {
            return Vec::new();
        }
        let layer = layer_of(file.path());
        if !is_inner_ring(layer) {
            return Vec::new();
        }
        let roster = infra_roster(file.language());
        imported_modules(file, ast)
            .into_iter()
            .filter_map(|import| {
                let hit = roster.iter().find(|entry| matches_module(&import.specifier, entry.module))?;
                Some(Finding::new(
                    format!(
                        "{} code imports `{}` ({}) — the inside of the hexagon must not depend on a technical detail; declare a port here and put the {} call in an adapter",
                        layer.label(),
                        import.specifier,
                        hit.concern,
                        hit.module,
                    ),
                    import.span,
                ))
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
        let ast: AstNode = if language == LanguageIdentifier::typescript() {
            yunq_parser_typescript::TypeScriptParser::new().parse(&file).unwrap()
        } else if language == LanguageIdentifier::python() {
            yunq_parser_python::PythonParser::new().parse(&file).unwrap()
        } else {
            yunq_parser_rust::RustParser::new().parse(&file).unwrap()
        };
        FrameworkInDomainRule::new().check(&file, &ast)
    }

    fn ts(path: &str, code: &str) -> Vec<Finding> {
        check(path, code, LanguageIdentifier::typescript())
    }

    fn py(path: &str, code: &str) -> Vec<Finding> {
        check(path, code, LanguageIdentifier::python())
    }

    fn rs(path: &str, code: &str) -> Vec<Finding> {
        check(path, code, LanguageIdentifier::rust())
    }

    #[test]
    fn flags_an_orm_import_in_a_typescript_entity() {
        let findings = ts("src/domain/order.ts", "import { Entity } from 'typeorm';\nexport class Order {}\n");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("domain code imports `typeorm`"), "{}", findings[0].message);
        assert!(findings[0].message.contains("an ORM"));
    }

    #[test]
    fn flags_a_ui_framework_import_in_a_use_case() {
        let findings = ts(
            "src/application/place_order.ts",
            "import React from 'react';\nexport const place = React;\n",
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("application code"));
    }

    #[test]
    fn silent_in_an_adapter_where_frameworks_belong() {
        assert!(ts("src/adapters/http/order_controller.ts", "import axios from 'axios';\n").is_empty());
        assert!(ts("src/infrastructure/postgres.ts", "import { Pool } from 'pg';\n").is_empty());
    }

    #[test]
    fn silent_on_a_path_with_no_layer_vocabulary() {
        assert!(ts("src/lib/http.ts", "import axios from 'axios';\n").is_empty());
    }

    #[test]
    fn silent_on_a_domain_import_of_another_domain_module() {
        assert!(ts("src/domain/order.ts", "import { Money } from './money';\n").is_empty());
    }

    #[test]
    fn flags_requests_in_a_python_domain_module() {
        let findings = py("src/domain/order.py", "import requests\n");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("an HTTP client"));
    }

    #[test]
    fn flags_a_sqlalchemy_submodule_in_a_python_entity() {
        let findings = py("src/domain/order.py", "from sqlalchemy.orm import declarative_base\n");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("sqlalchemy.orm"));
    }

    #[test]
    fn flags_sqlx_in_a_rust_domain_module() {
        let findings = rs("svc/src/domain/order.rs", "use sqlx::PgPool;\n\npub struct Order;\n");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("a database driver"));
    }

    #[test]
    fn flags_std_fs_in_a_rust_port_declaration() {
        let findings = rs("svc/src/ports/orders.rs", "use std::fs::File;\n\npub trait Orders {}\n");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("the filesystem"));
    }

    #[test]
    fn silent_on_std_collections_in_a_rust_domain_module() {
        assert!(rs("svc/src/domain/order.rs", "use std::collections::BTreeMap;\n").is_empty());
    }

    #[test]
    fn silent_in_test_only_paths() {
        assert!(ts("tests/domain/order.test.ts", "import axios from 'axios';\n").is_empty());
    }

    #[test]
    fn applies_only_to_languages_with_a_curated_roster() {
        let rule = FrameworkInDomainRule::new();
        for language in [
            LanguageIdentifier::typescript(),
            LanguageIdentifier::python(),
            LanguageIdentifier::rust(),
            LanguageIdentifier::go(),
        ] {
            assert!(rule.applies_to(&language), "{language:?}");
        }
        assert!(!rule.applies_to(&LanguageIdentifier::php()));
    }

    #[test]
    fn flags_database_sql_in_a_go_domain_package() {
        let file = SourceFile::new(
            "internal/domain/order.go",
            "package domain\n\nimport \"database/sql\"\n",
            LanguageIdentifier::go(),
        )
        .unwrap();
        let ast = yunq_parser_go::GoParser::new().parse(&file).unwrap();
        let findings = FrameworkInDomainRule::new().check(&file, &ast);
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert!(findings[0].message.contains("a database driver"));
    }

    #[test]
    fn silent_on_a_pure_go_standard_library_import_in_the_domain() {
        let file = SourceFile::new(
            "internal/domain/order.go",
            "package domain\n\nimport (\n\t\"errors\"\n\t\"time\"\n)\n",
            LanguageIdentifier::go(),
        )
        .unwrap();
        let ast = yunq_parser_go::GoParser::new().parse(&file).unwrap();
        assert!(FrameworkInDomainRule::new().check(&file, &ast).is_empty());
    }
}
