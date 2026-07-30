//! Module-specifier resolution: turning what an `import` statement's source
//! text says ("./lib", "foo.bar", ".sibling") into one of the file paths in
//! a given candidate set — the same "resolve within this analysis run's
//! file set, nothing else" scoping every cross-file analysis in this
//! codebase uses (`core/taint::cross`'s function-name indexing is the same
//! idea applied to functions instead of files).
//!
//! TypeScript/JS: relative specifiers only (`./x`, `../x`) — bare
//! specifiers (`"react"`, path-aliased `"@/lib"`) resolve to a package or a
//! bundler config this analyzer doesn't have, so they're always treated as
//! external and produce no edge. A path alias never being followed is a
//! known false-negative, not a bug: better to miss a cycle than invent a
//! wrong edge.
//!
//! Python: both absolute (`import foo.bar`, `from foo.bar import baz`) and
//! relative (`from . import x`, `from .sibling import y`) module paths,
//! matched against candidates with or without a trailing `/__init__`.

const TS_EXTENSIONS: &[&str] = &[".tsx", ".ts", ".jsx", ".js"];
const PY_EXTENSION: &str = ".py";

fn split_segments(path: &str) -> Vec<&str> {
    path.split('/').filter(|s| !s.is_empty()).collect()
}

fn dirname_segments(path: &str) -> Vec<&str> {
    let mut segments = split_segments(path);
    segments.pop();
    segments
}

fn strip_known_extension<'a>(path: &'a str, extensions: &[&str]) -> &'a str {
    extensions.iter().find_map(|ext| path.strip_suffix(ext)).unwrap_or(path)
}

/// Joins `importer`'s directory with a `./`/`../`-relative specifier,
/// producing a normalized, extension-less path.
fn join_relative(importer: &str, specifier: &str) -> String {
    let mut segments: Vec<String> = dirname_segments(importer).into_iter().map(str::to_string).collect();
    for part in specifier.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                segments.pop();
            }
            other => segments.push(other.to_string()),
        }
    }
    segments.join("/")
}

/// Resolves a TypeScript/JS import specifier (as written, quotes already
/// stripped) against `candidates`, returning the matching candidate path.
/// Non-relative specifiers (no `./`/`../` prefix) are always external.
pub fn resolve_ts_specifier<'a>(importer: &str, specifier: &str, candidates: &[&'a str]) -> Option<&'a str> {
    if !specifier.starts_with('.') {
        return None;
    }
    let target = join_relative(importer, specifier);
    candidates.iter().copied().find(|candidate| {
        let stem = strip_known_extension(candidate, TS_EXTENSIONS);
        stem == target || stem == format!("{target}/index")
    })
}

/// A Python module path (dot-joined segments, e.g. `foo.bar`) turned into
/// path segments (`foo/bar`) the way its file would be laid out.
pub fn dotted_to_path(dotted: &str) -> String {
    dotted.replace('.', "/")
}

/// Resolves a Python absolute *dotted* module path (`foo.bar` from `import
/// foo.bar` or `from foo.bar import baz`, dots and all — this converts it)
/// against `candidates`.
pub fn resolve_py_absolute<'a>(dotted_module: &str, candidates: &[&'a str]) -> Option<&'a str> {
    resolve_py_module_path(&dotted_to_path(dotted_module), candidates)
}

/// Resolves a Python relative import (`from . import x` / `from .sibling
/// import y` / `from ..pkg import z`) against `candidates`. `dots` is the
/// number of leading dots (1 = current package, 2 = parent, ...);
/// `submodule` is the dotted path after the dots, if any (`sibling` in
/// `.sibling`); `imported_name` is the first name imported (`x`/`y`/`z`),
/// tried as a submodule file when `submodule` is absent — the common case
/// of `from . import sibling` naming a sibling *file*, not a symbol in the
/// package's `__init__.py`.
pub fn resolve_py_relative<'a>(
    importer: &str,
    dots: usize,
    submodule: Option<&str>,
    imported_name: Option<&str>,
    candidates: &[&'a str],
) -> Option<&'a str> {
    if dots == 0 {
        return None;
    }
    let mut segments: Vec<String> = dirname_segments(importer).into_iter().map(str::to_string).collect();
    for _ in 1..dots {
        segments.pop();
    }
    if let Some(submodule) = submodule {
        segments.push(dotted_to_path(submodule));
        let target = segments.join("/");
        return resolve_py_module_path(&target, candidates);
    }
    // No explicit submodule (`from . import x`): try `x` itself as a
    // sibling submodule file first (the common case), then fall back to
    // the bare package directory (an `__init__.py` re-export).
    if let Some(name) = imported_name {
        let mut with_name = segments.clone();
        with_name.push(name.to_string());
        if let Some(hit) = resolve_py_module_path(&with_name.join("/"), candidates) {
            return Some(hit);
        }
    }
    resolve_py_module_path(&segments.join("/"), candidates)
}

fn resolve_py_module_path<'a>(module_path: &str, candidates: &[&'a str]) -> Option<&'a str> {
    if module_path.is_empty() {
        return None;
    }
    candidates.iter().copied().find(|candidate| {
        let stem = strip_known_extension(candidate, &[PY_EXTENSION]);
        stem == module_path || stem == format!("{module_path}/__init__")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ts_relative_sibling_import_resolves() {
        let candidates = ["main.ts", "lib.ts"];
        assert_eq!(resolve_ts_specifier("main.ts", "./lib", &candidates), Some("lib.ts"));
    }

    #[test]
    fn ts_relative_parent_import_resolves() {
        let candidates = ["src/a.ts", "shared.ts"];
        assert_eq!(resolve_ts_specifier("src/a.ts", "../shared", &candidates), Some("shared.ts"));
    }

    #[test]
    fn ts_relative_index_import_resolves() {
        let candidates = ["main.ts", "utils/index.ts"];
        assert_eq!(resolve_ts_specifier("main.ts", "./utils", &candidates), Some("utils/index.ts"));
    }

    #[test]
    fn ts_bare_specifier_is_external() {
        let candidates = ["main.ts", "react.ts"];
        assert_eq!(resolve_ts_specifier("main.ts", "react", &candidates), None);
    }

    #[test]
    fn py_absolute_module_resolves() {
        let candidates = ["foo/bar.py", "main.py"];
        assert_eq!(resolve_py_absolute("foo.bar", &candidates), Some("foo/bar.py"));
    }

    #[test]
    fn py_absolute_package_init_resolves() {
        let candidates = ["foo/bar/__init__.py"];
        assert_eq!(resolve_py_absolute("foo.bar", &candidates), Some("foo/bar/__init__.py"));
    }

    #[test]
    fn py_relative_submodule_resolves() {
        let candidates = ["pkg/a.py", "pkg/sibling.py"];
        assert_eq!(resolve_py_relative("pkg/a.py", 1, Some("sibling"), None, &candidates), Some("pkg/sibling.py"));
    }

    #[test]
    fn py_relative_bare_import_resolves_named_sibling_file() {
        let candidates = ["pkg/a.py", "pkg/sibling.py"];
        assert_eq!(
            resolve_py_relative("pkg/a.py", 1, None, Some("sibling"), &candidates),
            Some("pkg/sibling.py")
        );
    }

    #[test]
    fn py_relative_parent_package_resolves() {
        let candidates = ["pkg/sub/a.py", "pkg/shared.py"];
        assert_eq!(
            resolve_py_relative("pkg/sub/a.py", 2, Some("shared"), None, &candidates),
            Some("pkg/shared.py")
        );
    }
}
