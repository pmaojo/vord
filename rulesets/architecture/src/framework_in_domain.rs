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
//! The module roster below is curated, not inferred — the same shape as
//! `rulesets/secrets`' provider table, and the same posture Semgrep takes
//! with its per-framework rule packs (`semgrep-rules/python/{flask,django,
//! sqlalchemy,boto3,requests}`, `javascript/{express,sequelize}`,
//! `typescript/{angular,nestjs}`): a fixed list of the libraries that
//! actually mean "this code is doing I/O", each tagged with the concern it
//! drags into the hexagon, so the finding can name it.

use yunq_ast::{AstNode, LanguageIdentifier, SourceFile};
use yunq_import_graph::{layer_of, HexLayer};
use yunq_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

use crate::common::{imported_modules, matches_module};

/// One outside-the-hexagon module, and what it drags in.
struct InfraModule {
    module: &'static str,
    concern: &'static str,
}

const fn m(module: &'static str, concern: &'static str) -> InfraModule {
    InfraModule { module, concern }
}

const TS_MODULES: &[InfraModule] = &[
    m("fs", "the filesystem"),
    m("node:fs", "the filesystem"),
    m("fs/promises", "the filesystem"),
    m("node:fs/promises", "the filesystem"),
    m("http", "the network"),
    m("https", "the network"),
    m("node:http", "the network"),
    m("node:https", "the network"),
    m("net", "the network"),
    m("node:net", "the network"),
    m("child_process", "process execution"),
    m("node:child_process", "process execution"),
    m("axios", "an HTTP client"),
    m("node-fetch", "an HTTP client"),
    m("got", "an HTTP client"),
    m("undici", "an HTTP client"),
    m("superagent", "an HTTP client"),
    m("express", "a web framework"),
    m("koa", "a web framework"),
    m("fastify", "a web framework"),
    m("hapi", "a web framework"),
    m("@nestjs/common", "a web framework"),
    m("@nestjs/core", "a web framework"),
    m("next", "a web framework"),
    m("typeorm", "an ORM"),
    m("sequelize", "an ORM"),
    m("mongoose", "an ORM"),
    m("prisma", "an ORM"),
    m("@prisma/client", "an ORM"),
    m("knex", "an ORM"),
    m("@mikro-orm/core", "an ORM"),
    m("drizzle-orm", "an ORM"),
    m("pg", "a database driver"),
    m("mysql", "a database driver"),
    m("mysql2", "a database driver"),
    m("sqlite3", "a database driver"),
    m("better-sqlite3", "a database driver"),
    m("mongodb", "a database driver"),
    m("redis", "a database driver"),
    m("ioredis", "a database driver"),
    m("kafkajs", "a message broker"),
    m("amqplib", "a message broker"),
    m("bullmq", "a message broker"),
    m("nats", "a message broker"),
    m("aws-sdk", "a cloud SDK"),
    m("@aws-sdk/client-s3", "a cloud SDK"),
    m("@google-cloud/storage", "a cloud SDK"),
    m("firebase-admin", "a cloud SDK"),
    m("@azure/storage-blob", "a cloud SDK"),
    m("nodemailer", "an email transport"),
    m("react", "a UI framework"),
    m("react-dom", "a UI framework"),
    m("vue", "a UI framework"),
    m("@angular/core", "a UI framework"),
    m("svelte", "a UI framework"),
];

const PYTHON_MODULES: &[InfraModule] = &[
    m("requests", "an HTTP client"),
    m("httpx", "an HTTP client"),
    m("aiohttp", "an HTTP client"),
    m("urllib", "an HTTP client"),
    m("urllib3", "an HTTP client"),
    m("http.client", "an HTTP client"),
    m("flask", "a web framework"),
    m("fastapi", "a web framework"),
    m("django", "a web framework"),
    m("starlette", "a web framework"),
    m("pyramid", "a web framework"),
    m("tornado", "a web framework"),
    m("sanic", "a web framework"),
    m("bottle", "a web framework"),
    m("sqlalchemy", "an ORM"),
    m("sqlmodel", "an ORM"),
    m("peewee", "an ORM"),
    m("tortoise", "an ORM"),
    m("mongoengine", "an ORM"),
    m("psycopg2", "a database driver"),
    m("psycopg", "a database driver"),
    m("asyncpg", "a database driver"),
    m("pymongo", "a database driver"),
    m("motor", "a database driver"),
    m("sqlite3", "a database driver"),
    m("redis", "a database driver"),
    m("celery", "a message broker"),
    m("kombu", "a message broker"),
    m("pika", "a message broker"),
    m("confluent_kafka", "a message broker"),
    m("kafka", "a message broker"),
    m("boto3", "a cloud SDK"),
    m("botocore", "a cloud SDK"),
    m("google.cloud", "a cloud SDK"),
    m("azure", "a cloud SDK"),
    m("subprocess", "process execution"),
    m("socket", "the network"),
    m("smtplib", "an email transport"),
    m("ftplib", "the network"),
];

const RUST_MODULES: &[InfraModule] = &[
    m("std::fs", "the filesystem"),
    m("std::net", "the network"),
    m("std::process", "process execution"),
    m("tokio::fs", "the filesystem"),
    m("tokio::net", "the network"),
    m("tokio::process", "process execution"),
    m("reqwest", "an HTTP client"),
    m("hyper", "an HTTP client"),
    m("ureq", "an HTTP client"),
    m("isahc", "an HTTP client"),
    m("axum", "a web framework"),
    m("actix_web", "a web framework"),
    m("rocket", "a web framework"),
    m("warp", "a web framework"),
    m("tide", "a web framework"),
    m("poem", "a web framework"),
    m("tonic", "an RPC framework"),
    m("sqlx", "a database driver"),
    m("diesel", "an ORM"),
    m("sea_orm", "an ORM"),
    m("rusqlite", "a database driver"),
    m("tokio_postgres", "a database driver"),
    m("postgres", "a database driver"),
    m("mongodb", "a database driver"),
    m("redis", "a database driver"),
    m("lapin", "a message broker"),
    m("rdkafka", "a message broker"),
    m("aws_sdk_s3", "a cloud SDK"),
    m("aws_config", "a cloud SDK"),
    m("clap", "a CLI framework"),
];

fn roster(language: &LanguageIdentifier) -> &'static [InfraModule] {
    if *language == LanguageIdentifier::typescript() {
        return TS_MODULES;
    }
    if *language == LanguageIdentifier::python() {
        return PYTHON_MODULES;
    }
    if *language == LanguageIdentifier::rust() {
        return RUST_MODULES;
    }
    &[]
}

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
        !roster(language).is_empty()
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
        let roster = roster(file.language());
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
        assert!(rule.applies_to(&LanguageIdentifier::typescript()));
        assert!(rule.applies_to(&LanguageIdentifier::python()));
        assert!(rule.applies_to(&LanguageIdentifier::rust()));
        assert!(!rule.applies_to(&LanguageIdentifier::go()));
    }
}
