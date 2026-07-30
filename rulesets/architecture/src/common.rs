//! Import extraction shared by this ruleset's per-file rules: what modules
//! does *this* file pull in, as written, without resolving them to anything.
//!
//! Deliberately different from `yunq_import_graph`, which only keeps edges it
//! can resolve to another file in the analyzed set — exactly the *opposite*
//! of what a "the inside must not know about frameworks" check needs, since a
//! framework is by definition external and resolves to nothing.

use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile, Span};

fn is_other(node: &AstNode, kind: &str) -> bool {
    matches!(node.kind(), NodeKind::Other(k) if k.as_ref() == kind)
}

fn strip_quotes(text: &str) -> String {
    text.trim_matches(|c| c == '\'' || c == '"' || c == '`').to_string()
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
                .map(|spec| ImportedModule { specifier: strip_quotes(spec.text()), span: node.span() })
                .collect::<Vec<_>>()
        })
        .collect()
}

fn ts_imports(ast: &AstNode) -> Vec<ImportedModule> {
    let mut modules = Vec::new();
    for node in ast.descendants() {
        if is_other(node, "import_statement") || is_other(node, "export_statement") {
            if let Some(spec) = node.descendants().find(|n| *n.kind() == NodeKind::StringLiteral) {
                modules.push(ImportedModule { specifier: strip_quotes(spec.text()), span: node.span() });
            }
        } else if *node.kind() == NodeKind::Call {
            // `require('x')` — the CommonJS half of the same dependency.
            let Some(callee) = node.first_child() else { continue };
            if *callee.kind() != NodeKind::Identifier || callee.text() != "require" {
                continue;
            }
            if let Some(arg) = node.descendants().find(|n| *n.kind() == NodeKind::StringLiteral) {
                modules.push(ImportedModule { specifier: strip_quotes(arg.text()), span: node.span() });
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
                    child.first_child().filter(|c| is_other(c, "dotted_name")).map(|c| c.text().to_string())
                } else {
                    None
                };
                if let Some(dotted) = dotted {
                    modules.push(ImportedModule { specifier: dotted, span: node.span() });
                }
            }
        } else if is_other(node, "import_from_statement") {
            if let Some(target) = node.first_child().filter(|c| is_other(c, "dotted_name")) {
                modules.push(ImportedModule { specifier: target.text().to_string(), span: node.span() });
            }
        }
    }
    modules
}

fn rust_imports(ast: &AstNode) -> Vec<ImportedModule> {
    ast.descendants()
        .filter(|n| is_other(n, "use_declaration"))
        .filter_map(|node| {
            let path_node = node.children().iter().find(|c| !is_other(c, "visibility_modifier"))?;
            let text = path_node.text();
            let head = text.split('{').next().unwrap_or(text);
            let head = head.split(" as ").next().unwrap_or(head);
            let specifier =
                head.trim().trim_end_matches(':').trim_end_matches('*').trim_end_matches(':').trim().to_string();
            (!specifier.is_empty()).then_some(ImportedModule { specifier, span: node.span() })
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
    ["/", ".", "::"].iter().any(|sep| specifier.starts_with(&format!("{module}{sep}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use yunq_rules_engine::AstParser;

    fn ts(code: &str) -> Vec<ImportedModule> {
        let file = SourceFile::new("t.ts", code, LanguageIdentifier::typescript()).unwrap();
        let ast = yunq_parser_typescript::TypeScriptParser::new().parse(&file).unwrap();
        imported_modules(&file, &ast)
    }

    fn py(code: &str) -> Vec<ImportedModule> {
        let file = SourceFile::new("t.py", code, LanguageIdentifier::python()).unwrap();
        let ast = yunq_parser_python::PythonParser::new().parse(&file).unwrap();
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
        let modules = py("import sqlalchemy.orm\nfrom flask import Flask\nfrom .sibling import thing\n");
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
        assert_eq!(specifiers(&modules), vec!["std::fs::File", "sqlx", "reqwest::Client", "tokio::net"]);
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
}
