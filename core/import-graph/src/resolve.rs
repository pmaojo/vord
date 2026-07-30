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

const GO_EXTENSION: &str = ".go";

/// Resolves a Go import path (`example.com/app/internal/domain`) to a file in
/// `candidates`.
///
/// Go imports name a *package*, addressed by module path, and the module prefix
/// lives in `go.mod` — which this crate cannot read (it is I/O-free by design,
/// the same constraint that pushed Rust's crate index out to `infra/fs`). So
/// resolution matches on the *shared tail* of the import path and the candidate's
/// directory: `.../internal/infra` resolves to `internal/infra/pg.go` and to
/// `svc/internal/infra/pg.go` alike, because a scan rooted inside the module has
/// no reason to reproduce the module prefix in its paths.
///
/// Two segments of agreement are required (or the whole directory, if it is
/// shorter), so a third-party import cannot latch onto an unrelated local
/// directory that happens to end with the same word — `github.com/gin-gonic/gin`
/// does not resolve to `vendor/gin`. The longest agreement wins, and a package is
/// represented by its lexicographically first file: every file in a Go package
/// shares one directory, hence one component and one hexagonal layer.
pub fn resolve_go_import<'a>(import_path: &str, candidates: &[&'a str]) -> Option<&'a str> {
    let import_segments = split_segments(import_path.trim_matches('"'));
    let mut best: Option<(usize, &'a str)> = None;
    for candidate in candidates.iter().copied().filter(|c| c.ends_with(GO_EXTENSION)) {
        let dir_segments = dirname_segments(candidate);
        if dir_segments.is_empty() {
            continue;
        }
        let shared = dir_segments
            .iter()
            .rev()
            .zip(import_segments.iter().rev())
            .take_while(|(dir, import)| dir == import)
            .count();
        if shared == 0 || shared < dir_segments.len().min(2) {
            continue;
        }
        let better = match best {
            Some((best_shared, best_path)) => {
                shared > best_shared || (shared == best_shared && candidate < best_path)
            }
            None => true,
        };
        if better {
            best = Some((shared, candidate));
        }
    }
    best.map(|(_, candidate)| candidate)
}

const RS_EXTENSION: &str = ".rs";

/// A Rust file's *module directory*: where its child modules live. A module
/// root (`lib.rs`/`main.rs`/`mod.rs`) owns its own directory; any other
/// `foo.rs` owns `foo/` (the 2018-edition layout, where `foo::bar` lives in
/// `foo/bar.rs` next to `foo.rs`).
fn rust_module_dir(importer: &str) -> Vec<String> {
    let mut segments: Vec<String> = dirname_segments(importer).into_iter().map(str::to_string).collect();
    let stem = importer.rsplit('/').next().map(|f| strip_known_extension(f, &[RS_EXTENSION])).unwrap_or("");
    if !matches!(stem, "lib" | "main" | "mod" | "") {
        segments.push(stem.to_string());
    }
    segments
}

/// The crate source root a file belongs to: everything up to and including
/// its first `src/` segment (`core/ast/src/node.rs` -> `["core", "ast",
/// "src"]`). Files outside any `src/` directory (a single-file script, a
/// build script at a crate root) fall back to their own directory, which
/// makes `crate::` behave like `self::` for them rather than resolving
/// wrongly across the repo.
fn rust_crate_root(importer: &str) -> Vec<String> {
    let segments = split_segments(importer);
    match segments.iter().position(|s| *s == "src") {
        Some(index) => segments[..=index].iter().map(|s| s.to_string()).collect(),
        None => dirname_segments(importer).into_iter().map(str::to_string).collect(),
    }
}

/// Resolves an *intra-crate* Rust `use`/reference path — one rooted at
/// `crate`, `self` or `super` — to the file that declares that module,
/// within `candidates`.
///
/// `use_path` is the path as written, `::`-separated and already stripped of
/// its `{...}` list / `as` alias / `*` wildcard tail (see
/// `module_path_prefix` in `lib.rs`). Resolution tries the longest module
/// path first and drops trailing segments until a file matches, because a
/// path's tail names *items*, not modules, and nothing in the neutral AST
/// says where the module part stops: `crate::domain::order::Order` resolves
/// to `.../domain/order.rs` after one drop, and `crate::domain::Order` to
/// `.../domain.rs` (or `.../domain/mod.rs`) after one drop.
///
/// Cross-crate paths (a bare crate name) are *not* handled here — those need
/// the workspace crate index (`build_with_rust_crates`); this is the
/// within-crate module topology those edges never see.
pub fn resolve_rust_module<'a>(importer: &str, use_path: &str, candidates: &[&'a str]) -> Option<&'a str> {
    let mut segments = use_path.split("::").map(str::trim).filter(|s| !s.is_empty());
    let root = segments.next()?;
    let mut base = match root {
        "crate" => rust_crate_root(importer),
        "self" => rust_module_dir(importer),
        "super" => {
            let mut dir = rust_module_dir(importer);
            dir.pop();
            dir
        }
        _ => return None,
    };
    let mut rest: Vec<&str> = segments.collect();
    // Chained `super::super::x`: each extra `super` climbs one more module.
    while rest.first() == Some(&"super") {
        rest.remove(0);
        base.pop();
    }
    while !rest.is_empty() {
        let mut candidate_segments = base.clone();
        candidate_segments.extend(rest.iter().map(|s| s.to_string()));
        let target = candidate_segments.join("/");
        if let Some(hit) = candidates.iter().copied().find(|candidate| {
            let stem = strip_known_extension(candidate, &[RS_EXTENSION]);
            stem == target || stem == format!("{target}/mod")
        }) {
            if hit != importer {
                return Some(hit);
            }
            return None;
        }
        rest.pop();
    }
    None
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
    fn go_import_resolves_by_directory_suffix_without_a_go_mod() {
        let candidates = ["internal/domain/order.go", "internal/infra/postgres.go"];
        assert_eq!(
            resolve_go_import("example.com/app/internal/infra", &candidates),
            Some("internal/infra/postgres.go")
        );
    }

    #[test]
    fn the_longest_matching_go_package_directory_wins() {
        let candidates = ["internal/domain/order.go", "internal/domain/line/line.go"];
        assert_eq!(
            resolve_go_import("example.com/app/internal/domain/line", &candidates),
            Some("internal/domain/line/line.go")
        );
    }

    #[test]
    fn a_go_package_is_represented_by_its_first_file() {
        let candidates = ["internal/infra/zebra.go", "internal/infra/apple.go"];
        assert_eq!(resolve_go_import("app/internal/infra", &candidates), Some("internal/infra/apple.go"));
    }

    #[test]
    fn a_go_import_resolves_when_the_scan_root_is_inside_the_module() {
        // Scanned from a directory below `go.mod`, so the module prefix is not
        // part of the candidate paths at all.
        let candidates = ["hexagon/internal/infra/postgres.go", "hexagon/internal/domain/order.go"];
        assert_eq!(
            resolve_go_import("example.com/app/internal/infra", &candidates),
            Some("hexagon/internal/infra/postgres.go")
        );
    }

    #[test]
    fn a_single_shared_segment_is_not_enough_to_resolve() {
        let candidates = ["vendor/gin/gin.go"];
        assert_eq!(resolve_go_import("github.com/gin-gonic/gin", &candidates), None);
    }

    #[test]
    fn a_third_party_go_import_resolves_to_nothing() {
        let candidates = ["internal/domain/order.go"];
        assert_eq!(resolve_go_import("github.com/gin-gonic/gin", &candidates), None);
    }

    #[test]
    fn rust_crate_rooted_module_resolves_from_the_crate_src_root() {
        let candidates = ["svc/src/domain/order.rs", "svc/src/infrastructure/db.rs"];
        assert_eq!(
            resolve_rust_module("svc/src/domain/order.rs", "crate::infrastructure::db", &candidates),
            Some("svc/src/infrastructure/db.rs")
        );
    }

    #[test]
    fn rust_item_tail_is_dropped_until_a_module_file_matches() {
        let candidates = ["svc/src/domain/order.rs", "svc/src/infrastructure/db.rs"];
        assert_eq!(
            resolve_rust_module("svc/src/domain/order.rs", "crate::infrastructure::db::Pool", &candidates),
            Some("svc/src/infrastructure/db.rs")
        );
    }

    #[test]
    fn rust_mod_rs_layout_resolves() {
        let candidates = ["svc/src/app.rs", "svc/src/infrastructure/mod.rs"];
        assert_eq!(
            resolve_rust_module("svc/src/app.rs", "crate::infrastructure::Thing", &candidates),
            Some("svc/src/infrastructure/mod.rs")
        );
    }

    #[test]
    fn rust_super_climbs_one_module_level() {
        let candidates = ["svc/src/domain/order.rs", "svc/src/domain/money.rs"];
        assert_eq!(
            resolve_rust_module("svc/src/domain/order.rs", "super::money::Money", &candidates),
            Some("svc/src/domain/money.rs")
        );
    }

    #[test]
    fn rust_self_resolves_a_child_module_of_a_non_root_file() {
        let candidates = ["svc/src/domain.rs", "svc/src/domain/order.rs"];
        assert_eq!(
            resolve_rust_module("svc/src/domain.rs", "self::order::Order", &candidates),
            Some("svc/src/domain/order.rs")
        );
    }

    #[test]
    fn rust_external_crate_path_is_not_resolved_here() {
        let candidates = ["svc/src/domain/order.rs", "svc/src/infrastructure/db.rs"];
        assert_eq!(resolve_rust_module("svc/src/domain/order.rs", "sqlx::PgPool", &candidates), None);
    }

    #[test]
    fn rust_self_referential_path_produces_no_edge() {
        let candidates = ["svc/src/domain/order.rs"];
        assert_eq!(
            resolve_rust_module("svc/src/domain/order.rs", "crate::domain::order::Order", &candidates),
            None
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
