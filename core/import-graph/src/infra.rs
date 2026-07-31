//! Import extraction and the curated "this module means I/O" roster shared by
//! every rule that has to answer "does this code reach outside the process":
//! `architecture:framework-in-domain` (an inner-ring file importing a
//! framework directly) and `ddd:bdd-step-reaches-infra` (a Gherkin step
//! implementation calling one instead of the application layer).
//!
//! Import extraction here is deliberately different from this crate's own
//! `resolve` module, which only keeps edges it can resolve to another file in
//! the analyzed set — exactly the *opposite* of what "does this reach a
//! framework" needs, since a framework is by definition external and resolves
//! to nothing.
//!
//! The roster itself is curated, not inferred — the same shape as
//! `rulesets/secrets`' provider table, and the same posture Semgrep takes with
//! its per-framework rule packs: a fixed list of the libraries that actually
//! mean "this code is doing I/O", each tagged with the concern it drags in, so
//! a finding can name it.

use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile, Span};

fn is_other(node: &AstNode, kind: &str) -> bool {
    matches!(node.kind(), NodeKind::Other(k) if k.as_ref() == kind)
}

fn strip_quotes(text: &str) -> String {
    text.trim_matches(|c| c == '\'' || c == '"' || c == '`')
        .to_string()
}

/// One imported module specifier as the source writes it, with the span of
/// the statement that imports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportedModule {
    pub specifier: String,
    pub span: Span,
}

/// Every module `file` imports: TS/JS `import`/`export ... from`/`require()`,
/// Python `import x` / `from x import y` (absolute paths only — a relative
/// `from .x import y` names a sibling in the same layer, never a framework),
/// Rust `use` paths (the module prefix, `::`-joined, alias/list/wildcard tail
/// already cut off), and Go `import` specs.
pub fn imported_modules(file: &SourceFile, ast: &AstNode) -> Vec<ImportedModule> {
    let language = file.language();
    if *language == LanguageIdentifier::typescript() {
        return ts_imports(ast);
    }
    if *language == LanguageIdentifier::python() {
        return python_imports(ast);
    }
    if *language == LanguageIdentifier::rust() {
        return rust_imports(ast);
    }
    if *language == LanguageIdentifier::go() {
        return go_imports(ast);
    }
    Vec::new()
}

/// Go `import` specs: the quoted package path of every spec, single or grouped.
fn go_imports(ast: &AstNode) -> Vec<ImportedModule> {
    ast.descendants()
        .filter(|n| is_other(n, "import_declaration"))
        .flat_map(|node| {
            node.descendants()
                .filter(|n| *n.kind() == NodeKind::StringLiteral)
                .map(|spec| ImportedModule {
                    specifier: strip_quotes(spec.text()),
                    span: node.span(),
                })
                .collect::<Vec<_>>()
        })
        .collect()
}

fn ts_imports(ast: &AstNode) -> Vec<ImportedModule> {
    let mut modules = Vec::new();
    for node in ast.descendants() {
        if is_other(node, "import_statement") || is_other(node, "export_statement") {
            if let Some(spec) = node
                .descendants()
                .find(|n| *n.kind() == NodeKind::StringLiteral)
            {
                modules.push(ImportedModule {
                    specifier: strip_quotes(spec.text()),
                    span: node.span(),
                });
            }
        } else if *node.kind() == NodeKind::Call {
            // `require('x')` — the CommonJS half of the same dependency.
            let Some(callee) = node.first_child() else {
                continue;
            };
            if *callee.kind() != NodeKind::Identifier || callee.text() != "require" {
                continue;
            }
            if let Some(arg) = node
                .descendants()
                .find(|n| *n.kind() == NodeKind::StringLiteral)
            {
                modules.push(ImportedModule {
                    specifier: strip_quotes(arg.text()),
                    span: node.span(),
                });
            }
        }
    }
    modules
}

fn python_imports(ast: &AstNode) -> Vec<ImportedModule> {
    let mut modules = Vec::new();
    for node in ast.descendants() {
        if is_other(node, "import_statement") {
            for child in node.children() {
                let dotted = if is_other(child, "dotted_name") {
                    Some(child.text().to_string())
                } else if is_other(child, "aliased_import") {
                    child
                        .first_child()
                        .filter(|c| is_other(c, "dotted_name"))
                        .map(|c| c.text().to_string())
                } else {
                    None
                };
                if let Some(dotted) = dotted {
                    modules.push(ImportedModule {
                        specifier: dotted,
                        span: node.span(),
                    });
                }
            }
        } else if is_other(node, "import_from_statement") {
            if let Some(target) = node.first_child().filter(|c| is_other(c, "dotted_name")) {
                modules.push(ImportedModule {
                    specifier: target.text().to_string(),
                    span: node.span(),
                });
            }
        }
    }
    modules
}

fn rust_imports(ast: &AstNode) -> Vec<ImportedModule> {
    ast.descendants()
        .filter(|n| is_other(n, "use_declaration"))
        .filter_map(|node| {
            let path_node = node
                .children()
                .iter()
                .find(|c| !is_other(c, "visibility_modifier"))?;
            let text = path_node.text();
            let head = text.split('{').next().unwrap_or(text);
            let head = head.split(" as ").next().unwrap_or(head);
            let specifier = head
                .trim()
                .trim_end_matches(':')
                .trim_end_matches('*')
                .trim_end_matches(':')
                .trim()
                .to_string();
            (!specifier.is_empty()).then_some(ImportedModule {
                specifier,
                span: node.span(),
            })
        })
        .collect()
}

/// Whether `specifier` names `module` or something inside it, across all
/// three separator conventions: `axios`/`axios/lib` (TS),
/// `sqlalchemy`/`sqlalchemy.orm` (Python), `std::fs`/`std::fs::File` (Rust).
/// Prefix matching is segment-aware on purpose — `redisearch` must not match
/// `redis`, and `core::mem` must not match `core`.
pub fn matches_module(specifier: &str, module: &str) -> bool {
    if specifier == module {
        return true;
    }
    ["/", ".", "::"]
        .iter()
        .any(|sep| specifier.starts_with(&format!("{module}{sep}")))
}

/// One outside-the-hexagon module, and what it drags in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InfraModule {
    pub module: &'static str,
    pub concern: &'static str,
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

const GO_MODULES: &[InfraModule] = &[
    m("os", "the filesystem"),
    m("io/ioutil", "the filesystem"),
    m("path/filepath", "the filesystem"),
    m("net", "the network"),
    m("net/http", "the network"),
    m("os/exec", "process execution"),
    m("database/sql", "a database driver"),
    m("gorm.io/gorm", "an ORM"),
    m("github.com/jinzhu/gorm", "an ORM"),
    m("github.com/jmoiron/sqlx", "a database driver"),
    m("github.com/lib/pq", "a database driver"),
    m("github.com/jackc/pgx", "a database driver"),
    m("go.mongodb.org/mongo-driver", "a database driver"),
    m("github.com/redis/go-redis", "a database driver"),
    m("github.com/go-redis/redis", "a database driver"),
    m("github.com/gin-gonic/gin", "a web framework"),
    m("github.com/labstack/echo", "a web framework"),
    m("github.com/gofiber/fiber", "a web framework"),
    m("github.com/gorilla/mux", "a web framework"),
    m("google.golang.org/grpc", "an RPC framework"),
    m("github.com/aws/aws-sdk-go", "a cloud SDK"),
    m("cloud.google.com/go", "a cloud SDK"),
    m("github.com/segmentio/kafka-go", "a message broker"),
    m("github.com/streadway/amqp", "a message broker"),
    m("github.com/spf13/cobra", "a CLI framework"),
];

/// The curated infra/framework roster for one language — empty for a
/// language with none (nothing here is inferred for it).
pub fn infra_roster(language: &LanguageIdentifier) -> &'static [InfraModule] {
    if *language == LanguageIdentifier::typescript() {
        return TS_MODULES;
    }
    if *language == LanguageIdentifier::python() {
        return PYTHON_MODULES;
    }
    if *language == LanguageIdentifier::rust() {
        return RUST_MODULES;
    }
    if *language == LanguageIdentifier::go() {
        return GO_MODULES;
    }
    &[]
}

#[cfg(test)]
mod tests {
    use super::*;
    use yunq_rules_engine::AstParser;

    fn ts(code: &str) -> Vec<ImportedModule> {
        let file = SourceFile::new("t.ts", code, LanguageIdentifier::typescript()).unwrap();
        let ast = yunq_parser_typescript::TypeScriptParser::new()
            .parse(&file)
            .unwrap();
        imported_modules(&file, &ast)
    }

    fn py(code: &str) -> Vec<ImportedModule> {
        let file = SourceFile::new("t.py", code, LanguageIdentifier::python()).unwrap();
        let ast = yunq_parser_python::PythonParser::new()
            .parse(&file)
            .unwrap();
        imported_modules(&file, &ast)
    }

    fn rs(code: &str) -> Vec<ImportedModule> {
        let file = SourceFile::new("t.rs", code, LanguageIdentifier::rust()).unwrap();
        let ast = yunq_parser_rust::RustParser::new().parse(&file).unwrap();
        imported_modules(&file, &ast)
    }

    fn specifiers(modules: &[ImportedModule]) -> Vec<&str> {
        modules.iter().map(|m| m.specifier.as_str()).collect()
    }

    #[test]
    fn extracts_typescript_import_export_and_require_specifiers() {
        let modules = ts(
            "import axios from 'axios';\nexport { x } from './local';\nconst fs = require('node:fs');\n",
        );
        assert_eq!(specifiers(&modules), vec!["axios", "./local", "node:fs"]);
    }

    #[test]
    fn extracts_python_absolute_imports_only() {
        let modules =
            py("import sqlalchemy.orm\nfrom flask import Flask\nfrom .sibling import thing\n");
        assert_eq!(specifiers(&modules), vec!["sqlalchemy.orm", "flask"]);
    }

    #[test]
    fn extracts_python_aliased_imports() {
        let modules = py("import numpy as np\n");
        assert_eq!(specifiers(&modules), vec!["numpy"]);
    }

    #[test]
    fn extracts_rust_use_paths_without_list_alias_or_wildcard_tails() {
        let modules = rs(
            "use std::fs::File;\nuse sqlx::{PgPool, Row};\nuse reqwest::Client as Http;\nuse tokio::net::*;\n",
        );
        assert_eq!(
            specifiers(&modules),
            vec!["std::fs::File", "sqlx", "reqwest::Client", "tokio::net"]
        );
    }

    #[test]
    fn extracts_go_import_specs() {
        let file = SourceFile::new(
            "t.go",
            "package domain\n\nimport (\n\t\"database/sql\"\n\tgorm \"gorm.io/gorm\"\n)\n",
            LanguageIdentifier::go(),
        )
        .unwrap();
        let ast = yunq_parser_go::GoParser::new().parse(&file).unwrap();
        let modules = imported_modules(&file, &ast);
        assert_eq!(specifiers(&modules), vec!["database/sql", "gorm.io/gorm"]);
    }

    #[test]
    fn module_matching_is_segment_aware() {
        assert!(matches_module("axios", "axios"));
        assert!(matches_module("axios/lib/core", "axios"));
        assert!(matches_module("sqlalchemy.orm", "sqlalchemy"));
        assert!(matches_module("std::fs::File", "std::fs"));
        assert!(!matches_module("redisearch", "redis"));
        assert!(!matches_module("core::mem::swap", "core::fs"));
    }

    #[test]
    fn infra_roster_covers_all_four_languages_and_nothing_else() {
        for language in [
            LanguageIdentifier::typescript(),
            LanguageIdentifier::python(),
            LanguageIdentifier::rust(),
            LanguageIdentifier::go(),
        ] {
            assert!(!infra_roster(&language).is_empty(), "{language:?}");
        }
        assert!(infra_roster(&LanguageIdentifier::php()).is_empty());
    }
}
