//! Parses every import-graph-supported source file under a root and builds
//! `vord_import_graph::ImportGraph` from it. Shared by `vord arch` (the
//! interactive architecture viewer) and `vord_agent::runtime::Workspace`'s
//! `dependency_graph` — the parsing step both need, kept in one place so
//! neither walks the tree, resolves Rust crates and TS path aliases, or
//! selects a parser per language on its own.

use std::path::Path;

use vord_import_graph::ImportGraph;
use vord_rules_engine::AstParser;

use crate::SourceLoadError;

/// Every file this crate's parsers could make sense of, paired with the
/// import graph built from all of them.
pub struct ParsedImportGraph {
    pub graph: ImportGraph,
    pub files: Vec<(vord_ast::SourceFile, vord_ast::AstNode)>,
}

/// Parses every import-graph-supported file under `root` (TS/JS/TSX/JSX,
/// Python, Rust, Go — the four languages `ImportGraph` resolves) and builds
/// the graph from them. Files that fail to parse are skipped silently (a
/// parse error is an analysis signal, not a dependency-graph one).
pub fn build(root: &Path) -> Result<ParsedImportGraph, SourceLoadError> {
    let sources = crate::collect_sources_scoped(root, &[], &[], &[])?;
    let rust_crates = crate::discover_rust_crates(root);
    // Resolves TS/JS `@/`-style path-aliased imports (tsconfig.json/
    // jsconfig.json `compilerOptions.paths`) — without this, a project that
    // imports through such an alias shows almost no edges at all here, the
    // exact "128 files, 1 dependency" symptom this fixes.
    let ts_aliases = crate::discover_ts_path_aliases(root);

    let mut files: Vec<(vord_ast::SourceFile, vord_ast::AstNode)> = Vec::new();
    for file in &sources {
        let parser: Option<Box<dyn AstParser>> = match file.language().as_str() {
            "typescript" => Some(Box::new(vord_parser_typescript::TypeScriptParser::new())),
            "rust" => Some(Box::new(vord_parser_rust::RustParser::new())),
            "python" => Some(Box::new(vord_parser_python::PythonParser::new())),
            "go" => Some(Box::new(vord_parser_go::GoParser::new())),
            _ => None,
        };
        let Some(parser) = parser else { continue };
        let Ok(ast) = parser.parse(file) else {
            continue;
        };
        files.push((file.clone(), ast));
    }

    let views: Vec<(&str, &vord_ast::AstNode)> = files.iter().map(|(f, a)| (f.path(), a)).collect();
    let graph = ImportGraph::build_with_options(&views, &rust_crates, &ts_aliases);
    Ok(ParsedImportGraph { graph, files })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_root(name: &str) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!(
            "vord-dependency-graph-test-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("temp root");
        root
    }

    #[test]
    fn builds_a_real_edge_from_two_files_on_disk() {
        let root = temp_root("edge");
        std::fs::write(root.join("a.ts"), "import { b } from './b';\n").unwrap();
        std::fs::write(root.join("b.ts"), "export const b = 1;\n").unwrap();

        let built = build(&root).unwrap();

        assert_eq!(built.files.len(), 2);
        assert_eq!(built.graph.edges().len(), 1);
        assert_eq!(built.graph.edges()[0].from, "a.ts");
        assert_eq!(built.graph.edges()[0].to, "b.ts");
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn a_file_with_no_import_graph_support_contributes_no_edges() {
        let root = temp_root("unsupported");
        std::fs::write(root.join("README.md"), "# hello\n").unwrap();

        let built = build(&root).unwrap();

        assert!(built.graph.edges().is_empty());
        std::fs::remove_dir_all(&root).ok();
    }
}
