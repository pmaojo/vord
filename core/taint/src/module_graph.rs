//! Import/export module edge graph: given a file's AST and the paths of
//! every file in the same analysis run, resolves ES-module `import`
//! statements to the specific file and declared name they actually refer
//! to, instead of guessing project-wide by name alone.
//!
//! Public (not just crate-internal) because more than one cross-file
//! analysis needs "which file does this name actually come from" —
//! currently [`crate::CrossFileTaint`]'s function resolution, and (per
//! `ROADMAP.md`'s Phase 2 rule catalog work) import-cycle detection for
//! architecture smells. Kept dependency-free of taint concepts so it can be
//! reused without pulling in sources/sinks/sanitizers.

use std::collections::HashMap;

use yunq_ast::{AstNode, NodeKind};

/// A named thing's fully-qualified identity: the file it's declared/exported
/// in, plus its name there.
pub type FunctionKey = (String, String);

/// One file's resolved ES-module import edges.
pub struct ModuleImports {
    /// Local binding name → (target file, name exported/declared there).
    /// Only imports whose source specifier resolves to another file in this
    /// analysis run are kept — bare/package specifiers (`'child_process'`,
    /// `'react'`) have nothing local to point at and are dropped.
    pub bindings: HashMap<String, FunctionKey>,
    /// Whether this file has any recognized `import_statement` node at all —
    /// callers use this to gate a legacy by-name fallback for files with no
    /// ES-module import syntax at all (synthetic ASTs, non-ES-module
    /// languages).
    pub has_import_statements: bool,
}

/// Builds `file`'s import edges from its `import_statement` nodes. Only
/// relative specifiers (`'./lib'`, `'../utils/foo'`) that resolve to another
/// file in `all_paths` produce a binding; bare/package specifiers
/// (`'child_process'`, `'react'`) are external and dropped, though the
/// statement still counts toward `has_import_statements`.
pub fn collect_imports(file: &str, ast: &AstNode, all_paths: &[&str]) -> ModuleImports {
    let mut bindings = HashMap::new();
    let mut has_import_statements = false;
    for import in ast.descendants().filter(
        |n| matches!(n.kind(), NodeKind::Other(kind) if kind.as_ref() == "import_statement"),
    ) {
        has_import_statements = true;
        let Some(source) = import
            .children()
            .iter()
            .find(|c| *c.kind() == NodeKind::StringLiteral)
        else {
            continue;
        };
        let specifier = strip_quotes(source.text());
        let Some(target) = resolve_module_specifier(file, specifier, all_paths) else {
            continue;
        };
        let Some(clause) = import.children().iter().find(
            |c| matches!(c.kind(), NodeKind::Other(kind) if kind.as_ref() == "import_clause"),
        ) else {
            continue;
        };
        collect_clause_bindings(clause, &target, &mut bindings);
    }
    ModuleImports {
        bindings,
        has_import_statements,
    }
}

/// Reads one `import_clause`'s children — a bare default-import identifier,
/// and/or a `named_imports` block — into local-binding → target edges.
/// `namespace_import` (`* as ns`) is intentionally not covered: calls through
/// a namespace binding (`ns.helper()`) are member-access call sites, out of
/// scope for this same-name resolution.
fn collect_clause_bindings(
    clause: &AstNode,
    target: &str,
    bindings: &mut HashMap<String, FunctionKey>,
) {
    for child in clause.children() {
        match child.kind() {
            NodeKind::Identifier => {
                // Default import: no way to know the target's actual
                // exported name without deeper module analysis, so this
                // assumes (as is overwhelmingly the convention) the local
                // binding name mirrors the target function's own declared
                // name.
                let name = child.text().to_string();
                bindings.insert(name.clone(), (target.to_string(), name.clone()));
            }
            NodeKind::Other(kind) if kind.as_ref() == "named_imports" => {
                for spec in child.children().iter().filter(
                    |c| matches!(c.kind(), NodeKind::Other(k) if k.as_ref() == "import_specifier"),
                ) {
                    let idents: Vec<&AstNode> = spec
                        .children()
                        .iter()
                        .filter(|c| *c.kind() == NodeKind::Identifier)
                        .collect();
                    let Some(exported) = idents.first() else {
                        continue;
                    };
                    // `{ name as alias }`: two identifier children, exported
                    // name first, local alias second. `{ name }` alone: the
                    // single identifier is both.
                    let local = idents.last().unwrap_or(exported);
                    bindings.insert(
                        local.text().to_string(),
                        (target.to_string(), exported.text().to_string()),
                    );
                }
            }
            _ => {}
        }
    }
}

fn strip_quotes(text: &str) -> &str {
    text.trim_matches(|c| c == '\'' || c == '"' || c == '`')
}

/// Resolves a relative import `specifier` seen in `importer` to whichever of
/// `all_paths` it names, trying the specifier as-is, with common ES-module
/// extensions appended, and as a directory `index` file. Bare specifiers
/// (not starting with `.`) are always external and return `None`.
pub fn resolve_module_specifier(
    importer: &str,
    specifier: &str,
    all_paths: &[&str],
) -> Option<String> {
    if !specifier.starts_with('.') {
        return None;
    }
    let importer_dir = std::path::Path::new(importer)
        .parent()
        .unwrap_or_else(|| std::path::Path::new(""));
    let joined = normalize_path(&importer_dir.join(specifier));
    let joined_str = joined.to_string_lossy().replace('\\', "/");

    const EXTENSIONS: &[&str] = &["", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"];
    const INDEX_SUFFIXES: &[&str] = &["/index.ts", "/index.tsx", "/index.js", "/index.jsx"];

    EXTENSIONS
        .iter()
        .map(|ext| format!("{joined_str}{ext}"))
        .chain(
            INDEX_SUFFIXES
                .iter()
                .map(|suffix| format!("{joined_str}{suffix}")),
        )
        .find_map(|candidate| {
            all_paths
                .iter()
                .find(|p| **p == candidate)
                .map(|p| p.to_string())
        })
}

/// Collapses `.`/`..` components purely lexically (no filesystem access —
/// these are logical analysis-run paths, not necessarily real files on
/// disk).
fn normalize_path(path: &std::path::Path) -> std::path::PathBuf {
    let mut out = std::path::PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::ParentDir => {
                out.pop();
            }
            std::path::Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_package_specifier_is_external_and_never_resolves_locally() {
        // A same-named local function must not be picked up just because a
        // package import shares its name — non-relative specifiers are
        // rejected outright.
        assert_eq!(
            resolve_module_specifier("main.ts", "child_process", &["child_process.ts"]),
            None
        );
        assert_eq!(
            resolve_module_specifier("main.ts", "./lib", &["lib.ts", "other.ts"]),
            Some("lib.ts".to_string())
        );
    }

    #[test]
    fn relative_specifier_resolves_across_subdirectories() {
        assert_eq!(
            resolve_module_specifier("src/main.ts", "./lib/util", &["src/lib/util.ts"]),
            Some("src/lib/util.ts".to_string())
        );
    }

    #[test]
    fn parent_dir_traversal_is_normalized() {
        assert_eq!(
            resolve_module_specifier("src/sub/main.ts", "../lib", &["src/lib.ts"]),
            Some("src/lib.ts".to_string())
        );
    }

    #[test]
    fn unresolvable_relative_specifier_returns_none() {
        assert_eq!(
            resolve_module_specifier("main.ts", "./missing", &["lib.ts"]),
            None
        );
    }

    #[test]
    fn index_suffix_resolves_a_directory_import() {
        assert_eq!(
            resolve_module_specifier("main.ts", "./widgets", &["widgets/index.ts"]),
            Some("widgets/index.ts".to_string())
        );
    }
}
