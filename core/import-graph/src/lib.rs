//! Import/export dependency graph over a file set, and cycle detection on
//! it — the enabler for `rulesets/architecture::DependencyCycleRule`. Pure:
//! no I/O, works purely off the neutral AST and a list of candidate file
//! paths (the same file set a `CrossFileRule` already receives).
//!
//! TypeScript/JS and Python resolve via relative specifiers against the
//! candidate file set (see `resolve` module docs for what's resolved and
//! what's deliberately left external); Go resolves `import` paths by
//! directory suffix (its module prefix lives in `go.mod`, which this crate
//! cannot read); Rust resolves `use` edges against a
//! crate-name index instead (`build_with_rust_crates`, see its own doc
//! comment — this crate stays I/O-free, so the index itself is built
//! elsewhere, `yunq_infra_fs::discover_rust_crates`). Every other language
//! contributes no edges (harmless, not an error).
//!
//! Also home to `component` (roadmap D1: components derived from path
//! topology), `boundary` (roadmap D2: declared boundaries between those
//! components), `layer` (the zero-config hexagonal reading of the same
//! topology: dependencies must point inward) and `metrics` (Martin's
//! component metrics — Ca/Ce/I/A/D) — all consumers of the same edge set
//! this module builds.

mod boundary;
mod component;
mod infra;
mod layer;
mod metrics;
mod resolve;

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use yunq_ast::{AstNode, NodeKind, Span};

pub use boundary::{ArchitectureConfig, BoundaryViolation, DependencyEdge, ViolationKind};
pub use component::component_of;
pub use infra::{imported_modules, infra_roster, matches_module, ImportedModule, InfraModule};
pub use layer::{inward_dependency_violations, layer_of, HexLayer, LayerViolation};
pub use metrics::{
    component_metrics, stability_violations, ComponentMetrics, StabilityViolation, TypeCensus,
};

/// One resolved dependency edge: `from` imports `to`, at `span` in `from`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportEdge {
    pub from: String,
    pub to: String,
    pub span: Span,
}

pub struct ImportGraph {
    edges: Vec<ImportEdge>,
}

fn is_ts_like(path: &str) -> bool {
    [".ts", ".tsx", ".js", ".jsx"].iter().any(|ext| path.ends_with(ext))
}

fn strip_quotes(text: &str) -> String {
    text.trim_matches(|c| c == '\'' || c == '"' || c == '`').to_string()
}

fn is_other(node: &AstNode, kind: &str) -> bool {
    matches!(node.kind(), NodeKind::Other(k) if k.as_ref() == kind)
}

fn extract_ts_edges(path: &str, ast: &AstNode, candidates: &[&str], edges: &mut Vec<ImportEdge>) {
    for node in
        ast.descendants().filter(|n| is_other(n, "import_statement") || is_other(n, "export_statement"))
    {
        let Some(spec_node) = node.descendants().find(|n| *n.kind() == NodeKind::StringLiteral) else {
            continue;
        };
        let specifier = strip_quotes(spec_node.text());
        if let Some(target) = resolve::resolve_ts_specifier(path, &specifier, candidates) {
            if target != path {
                edges.push(ImportEdge { from: path.to_string(), to: target.to_string(), span: node.span() });
            }
        }
    }
}

/// A `dotted_name` module path from a plain `import_statement` entry — also
/// unwraps `import foo.bar as baz`'s `aliased_import` wrapper.
fn dotted_module_text(node: &AstNode) -> Option<String> {
    if is_other(node, "dotted_name") {
        return Some(node.text().to_string());
    }
    if is_other(node, "aliased_import") {
        return node.first_child().filter(|c| is_other(c, "dotted_name")).map(|c| c.text().to_string());
    }
    None
}

fn extract_py_edges(path: &str, ast: &AstNode, candidates: &[&str], edges: &mut Vec<ImportEdge>) {
    for node in ast.descendants() {
        if is_other(node, "import_statement") {
            for child in node.children() {
                let Some(module) = dotted_module_text(child) else { continue };
                if let Some(target) = resolve::resolve_py_absolute(&module, candidates) {
                    if target != path {
                        edges.push(ImportEdge { from: path.to_string(), to: target.to_string(), span: node.span() });
                    }
                }
            }
        } else if is_other(node, "import_from_statement") {
            let Some(target_node) = node.first_child() else { continue };
            let imported_name = node.children().get(1).map(|n| n.text());
            let resolved = if is_other(target_node, "dotted_name") {
                resolve::resolve_py_absolute(target_node.text(), candidates)
            } else if is_other(target_node, "relative_import") {
                let dots = target_node
                    .children()
                    .iter()
                    .find(|c| is_other(c, "import_prefix"))
                    .map(|c| c.text().len())
                    .unwrap_or(0);
                let submodule =
                    target_node.children().iter().find(|c| is_other(c, "dotted_name")).map(|c| c.text());
                resolve::resolve_py_relative(path, dots, submodule, imported_name, candidates)
            } else {
                None
            };
            if let Some(target) = resolved {
                if target != path {
                    edges.push(ImportEdge { from: path.to_string(), to: target.to_string(), span: node.span() });
                }
            }
        }
    }
}

/// Go `import` edges: every `import_spec`'s quoted package path, resolved by
/// directory suffix (`resolve::resolve_go_import` — Go's module prefix lives in
/// `go.mod`, which this I/O-free crate cannot read).
fn extract_go_edges(path: &str, ast: &AstNode, candidates: &[&str], edges: &mut Vec<ImportEdge>) {
    for node in ast.descendants().filter(|n| is_other(n, "import_declaration")) {
        for spec in node.descendants().filter(|n| *n.kind() == NodeKind::StringLiteral) {
            let specifier = strip_quotes(spec.text());
            if let Some(target) = resolve::resolve_go_import(&specifier, candidates) {
                if target != path {
                    edges.push(ImportEdge { from: path.to_string(), to: target.to_string(), span: node.span() });
                }
            }
        }
    }
}

/// The leftmost identifier of a Rust path expression — the crate name (or
/// `crate`/`self`/`super`) every shape this walks ultimately roots at: a
/// bare `Identifier`, a nested `scoped_identifier` (`a::b::c`, the general
/// path form — a `use` path, a call target, a bare reference with no `use`
/// at all), a `scoped_type_identifier` (the same thing in type position —
/// `x: a::b::Type`, `-> a::b::Type`), a `scoped_use_list` (`a::b::{C, D}` —
/// its own first child is already the shared prefix, no need to look inside
/// the list), a `use_as_clause` (`a::b as c` — first child is the aliased
/// path, second is the new name, ignored here), or a `use_wildcard`
/// (`a::b::*`).
fn rust_path_root(node: &AstNode) -> Option<String> {
    match node.kind() {
        NodeKind::Identifier => Some(node.text().to_string()),
        NodeKind::Other(kind) => match kind.as_ref() {
            "crate" | "self" | "super" => Some(node.text().to_string()),
            "scoped_identifier" | "scoped_type_identifier" | "scoped_use_list" | "use_as_clause"
            | "use_wildcard" => node.first_child().and_then(rust_path_root),
            _ => None,
        },
        _ => None,
    }
}

/// Resolves `path_node`'s leftmost segment against `crate_index` and, if it
/// names a distinct workspace crate not already recorded for this file,
/// pushes one `ImportEdge`. `seen` dedupes by target: a single fully-
/// qualified reference nests several matching path nodes (`a::b::c::new()`
/// visits `a::b::c::new`, `a::b::c` and `a::b` in turn, all resolving to the
/// same crate `a`), and a crate can legitimately be referenced dozens of
/// times in one file — one edge per (file, crate) pair is the useful unit,
/// not one per AST node or per call site.
fn push_rust_edge(
    path: &str,
    path_node: &AstNode,
    span: Span,
    crate_index: &HashMap<String, String>,
    seen: &mut HashSet<String>,
    edges: &mut Vec<ImportEdge>,
) {
    let Some(segment) = rust_path_root(path_node) else { return };
    if matches!(segment.as_str(), "crate" | "self" | "super" | "std" | "core" | "alloc") {
        return;
    }
    let Some(crate_dir) = crate_index.get(&segment) else { return };
    let target = format!("{crate_dir}/Cargo.toml");
    if component_of(&target) == component_of(path) {
        return;
    }
    if seen.insert(target.clone()) {
        edges.push(ImportEdge { from: path.to_string(), to: target, span });
    }
}

/// Rust cross-crate references: only cross-*crate* references resolve, via
/// `crate_index` (crate identifier -> directory,
/// `yunq_infra_fs::discover_rust_crates`'s output). `crate`/`self`/`super`
/// paths are always intra-crate and `std`/`core`/`alloc` are always the
/// implicit-prelude crates, so both are skipped before ever consulting the
/// index — anything else not found in it is an external (non-workspace)
/// dependency, left unresolved like an external TS/Python specifier.
///
/// Two passes, because Rust has two distinct ways to reach another crate's
/// items: `use_declaration` (handling the shapes `rust_path_root` docs —
/// plain, list, aliased, wildcard), and — unlike TypeScript/Python, where a
/// module's names don't exist in scope without an `import`/`from ...
/// import` first — a bare fully-qualified path with no `use` anywhere in
/// the file at all (`yunq_infra_fs::Thing::new()`, or a
/// `scoped_type_identifier` in a signature). Both passes walk the same
/// `rust_path_root`/`push_rust_edge` resolution; the second one is strictly
/// additive; a `use`'d reference is already caught by the first pass and
/// `push_rust_edge`'s dedup makes the overlap harmless.
///
/// Test code is excluded the same way `core/duplication` already excludes
/// it (`yunq_rules_engine::test_code`): a standalone integration-test file
/// (`tests/*.rs`) contributes no edges at all, and a `#[cfg(test)] mod
/// tests { ... }` block inside an ordinary source file is excluded only for
/// the references inside it — a dev-dependency reachable solely from a
/// crate's own tests (exercising a port against a real adapter, a
/// legitimate, Cargo-sanctioned pattern) must not read as a production
/// boundary violation just because the crate graph technically allows it.
///
/// Deliberately not extended to `DependencyCycleRule`: Cargo's own
/// dependency graph already forbids a real crate-level cycle from existing
/// at all (a workspace with one fails to build), so there is no signal a
/// cycle check could add there that isn't already a build failure — unlike
/// the boundary-violation check, which catches something Cargo doesn't
/// enforce at all (an edge's *direction*, not just its declaredness).
fn extract_rust_edges(path: &str, ast: &AstNode, crate_index: &HashMap<String, String>, edges: &mut Vec<ImportEdge>) {
    if yunq_rules_engine::is_test_only_path(path) {
        return;
    }
    let test_ranges = yunq_rules_engine::rust_test_module_ranges(ast.text());
    let mut seen = HashSet::new();

    for node in ast.descendants().filter(|n| is_other(n, "use_declaration")) {
        if yunq_rules_engine::in_ranges(&test_ranges, node.span().start_line) {
            continue;
        }
        let Some(path_node) = node.children().iter().find(|c| !is_other(c, "visibility_modifier")) else {
            continue;
        };
        push_rust_edge(path, path_node, node.span(), crate_index, &mut seen, edges);
    }

    for node in
        ast.descendants().filter(|n| is_other(n, "scoped_identifier") || is_other(n, "scoped_type_identifier"))
    {
        if yunq_rules_engine::in_ranges(&test_ranges, node.span().start_line) {
            continue;
        }
        push_rust_edge(path, node, node.span(), crate_index, &mut seen, edges);
    }
}

/// A Rust path node's *module path prefix*: the `::`-separated text with the
/// shapes that aren't module segments cut off — a `{A, B}` use list, an `as`
/// alias, a `*` wildcard tail. (`use crate::a::b::{C, D};` -> `crate::a::b`.)
fn module_path_prefix(node: &AstNode) -> String {
    let text = node.text();
    let head = text.split('{').next().unwrap_or(text);
    let head = head.split(" as ").next().unwrap_or(head);
    head.trim().trim_end_matches(':').trim_end_matches('*').trim_end_matches(':').trim().to_string()
}

/// Rust *intra-crate* module edges: `use crate::infrastructure::db`,
/// `super::money`, `self::order` resolved to the file declaring that module
/// (`resolve::resolve_rust_module`).
///
/// Deliberately not part of [`ImportGraph::build`], which is what
/// `DependencyCycleRule` and `BoundaryViolationRule` use. Rust module cycles
/// are legal and idiomatic — a parent module names its children and children
/// reach back with `super::` — so folding these edges into the default graph
/// would turn the cycle rule into a firehose on every Rust codebase. The
/// layering rules ([`layer`]) want them, because "which ring is this file
/// in" is a *path* question that a single-crate `src/domain` /
/// `src/infrastructure` layout answers perfectly well without any crate
/// index at all.
fn extract_rust_module_edges(path: &str, ast: &AstNode, candidates: &[&str], edges: &mut Vec<ImportEdge>) {
    if yunq_rules_engine::is_test_only_path(path) {
        return;
    }
    let test_ranges = yunq_rules_engine::rust_test_module_ranges(ast.text());
    let mut seen = HashSet::new();
    for node in ast.descendants().filter(|n| is_other(n, "use_declaration")) {
        if yunq_rules_engine::in_ranges(&test_ranges, node.span().start_line) {
            continue;
        }
        let Some(path_node) = node.children().iter().find(|c| !is_other(c, "visibility_modifier")) else {
            continue;
        };
        let prefix = module_path_prefix(path_node);
        let Some(target) = resolve::resolve_rust_module(path, &prefix, candidates) else { continue };
        if seen.insert(target.to_string()) {
            edges.push(ImportEdge { from: path.to_string(), to: target.to_string(), span: node.span() });
        }
    }
}

impl ImportGraph {
    /// Builds the graph from a file set — the same `&[(path, ast)]` shape
    /// `core/taint::CrossFileTaint::find_flows` takes. Rust files contribute
    /// no edges this way (no crate index to resolve `use` paths against);
    /// see [`Self::build_with_rust_crates`].
    pub fn build(files: &[(&str, &AstNode)]) -> Self {
        Self::build_with_rust_crates(files, &HashMap::new())
    }

    /// Same as [`Self::build`], plus Rust `use` edges resolved against
    /// `rust_crates` (crate identifier, hyphens replaced with underscores,
    /// e.g. `"yunq_infra_fs"` -> that crate's directory —
    /// `yunq_infra_fs::discover_rust_crates`'s shape exactly). An empty map
    /// behaves exactly like [`Self::build`]: every `use` path is left
    /// unresolved, harmless rather than an error, the same convention every
    /// unmatched specifier in `resolve` already follows.
    pub fn build_with_rust_crates(files: &[(&str, &AstNode)], rust_crates: &HashMap<String, String>) -> Self {
        let candidates: Vec<&str> = files.iter().map(|(path, _)| *path).collect();
        let mut edges = Vec::new();
        for (path, ast) in files {
            if is_ts_like(path) {
                extract_ts_edges(path, ast, &candidates, &mut edges);
            } else if path.ends_with(".py") {
                extract_py_edges(path, ast, &candidates, &mut edges);
            } else if path.ends_with(".rs") {
                extract_rust_edges(path, ast, rust_crates, &mut edges);
            } else if path.ends_with(".go") {
                extract_go_edges(path, ast, &candidates, &mut edges);
            }
        }
        Self { edges }
    }

    /// Same as [`Self::build`], plus Rust *intra-crate* module edges
    /// (`crate::`/`self::`/`super::` paths resolved to the file declaring
    /// that module — see `extract_rust_module_edges` for why this is opt-in
    /// rather than the default). This is what the layering rules build on:
    /// a single-crate `src/domain` / `src/infrastructure` layout is a
    /// hexagon whether or not the workspace has more than one crate in it.
    pub fn build_with_rust_modules(files: &[(&str, &AstNode)]) -> Self {
        let mut graph = Self::build(files);
        let candidates: Vec<&str> = files.iter().map(|(path, _)| *path).collect();
        for (path, ast) in files {
            if path.ends_with(".rs") {
                extract_rust_module_edges(path, ast, &candidates, &mut graph.edges);
            }
        }
        graph
    }

    pub fn edges(&self) -> &[ImportEdge] {
        &self.edges
    }

    /// File-level edges collapsed to component-level edges
    /// (`component::component_of`), deduplicated and with same-component
    /// edges dropped — the input `boundary::ArchitectureConfig::violations`
    /// checks declared boundaries against.
    pub fn component_edges(&self) -> BTreeSet<(String, String)> {
        self.edges
            .iter()
            .map(|e| (component_of(&e.from), component_of(&e.to)))
            .filter(|(from, to)| from != to)
            .collect()
    }

    /// The span of the import statement responsible for the `from -> to`
    /// edge, if one exists — used to point a cycle finding at the actual
    /// import line rather than the top of the file.
    pub fn edge_span(&self, from: &str, to: &str) -> Option<Span> {
        self.edges.iter().find(|e| e.from == from && e.to == to).map(|e| e.span)
    }

    /// Every import cycle in the graph, each as an ordered path
    /// `[a, b, c, a]` (`a` imports `b` imports `c` imports `a`). One entry
    /// per strongly-connected component of size > 1 — a file that merely
    /// imports itself (a size-1 SCC with a self-loop) is not reported: that
    /// pattern is a barrel/re-export idiom in practice, not the "modules
    /// depend on each other" smell this rule targets.
    pub fn cycles(&self) -> Vec<Vec<String>> {
        let mut adjacency: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for edge in &self.edges {
            adjacency.entry(edge.from.clone()).or_default().push(edge.to.clone());
            adjacency.entry(edge.to.clone()).or_default();
        }
        Tarjan::new(&adjacency)
            .run()
            .into_iter()
            .filter(|scc| scc.len() > 1)
            .map(|scc| order_cycle(&scc, &adjacency))
            .collect()
    }
}

/// Walks one strongly-connected component to produce a human-readable cycle
/// path `[start, ..., start]`, greedily preferring unvisited members and
/// closing back to a deterministic (lexicographically smallest) start node.
/// An SCC is strongly connected by definition, so this always terminates
/// with a closed path; the `None` arm is an unreachable defensive fallback.
fn order_cycle(scc: &[String], adjacency: &BTreeMap<String, Vec<String>>) -> Vec<String> {
    let members: BTreeSet<&String> = scc.iter().collect();
    let start = scc.iter().min().cloned().unwrap_or_default();
    let mut path = vec![start.clone()];
    let mut visited: BTreeSet<String> = BTreeSet::from([start.clone()]);
    let mut current = start.clone();
    loop {
        let next = adjacency
            .get(&current)
            .into_iter()
            .flatten()
            .find(|n| members.contains(*n) && (**n == start || !visited.contains(*n)))
            .cloned();
        match next {
            Some(n) if n == start => {
                path.push(n);
                break;
            }
            Some(n) => {
                visited.insert(n.clone());
                path.push(n.clone());
                current = n;
            }
            None => break,
        }
    }
    path
}

/// Tarjan's strongly-connected-components algorithm — standard textbook
/// form, recursive (fine at lint scale: a project's module graph is small
/// enough not to risk stack depth in practice).
struct Tarjan<'g> {
    adjacency: &'g BTreeMap<String, Vec<String>>,
    index: usize,
    indices: HashMap<String, usize>,
    lowlink: HashMap<String, usize>,
    on_stack: HashSet<String>,
    stack: Vec<String>,
    sccs: Vec<Vec<String>>,
}

impl<'g> Tarjan<'g> {
    fn new(adjacency: &'g BTreeMap<String, Vec<String>>) -> Self {
        Self {
            adjacency,
            index: 0,
            indices: HashMap::new(),
            lowlink: HashMap::new(),
            on_stack: HashSet::new(),
            stack: Vec::new(),
            sccs: Vec::new(),
        }
    }

    fn run(mut self) -> Vec<Vec<String>> {
        let nodes: Vec<String> = self.adjacency.keys().cloned().collect();
        for node in nodes {
            if !self.indices.contains_key(&node) {
                self.strongconnect(node);
            }
        }
        self.sccs
    }

    fn strongconnect(&mut self, v: String) {
        self.indices.insert(v.clone(), self.index);
        self.lowlink.insert(v.clone(), self.index);
        self.index += 1;
        self.stack.push(v.clone());
        self.on_stack.insert(v.clone());

        let neighbors = self.adjacency.get(&v).cloned().unwrap_or_default();
        for w in neighbors {
            if !self.indices.contains_key(&w) {
                self.strongconnect(w.clone());
                let merged = self.lowlink[&v].min(self.lowlink[&w]);
                self.lowlink.insert(v.clone(), merged);
            } else if self.on_stack.contains(&w) {
                let merged = self.lowlink[&v].min(self.indices[&w]);
                self.lowlink.insert(v.clone(), merged);
            }
        }

        if self.lowlink[&v] == self.indices[&v] {
            let mut component = Vec::new();
            loop {
                let w = self.stack.pop().expect("component root is always on the stack");
                self.on_stack.remove(&w);
                let done = w == v;
                component.push(w);
                if done {
                    break;
                }
            }
            self.sccs.push(component);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use yunq_ast::{LanguageIdentifier, SourceFile};
    use yunq_rules_engine::AstParser;

    fn parse_ts(path: &str, code: &str) -> (SourceFile, AstNode) {
        let file = SourceFile::new(path, code, LanguageIdentifier::typescript()).unwrap();
        let ast = yunq_parser_typescript::TypeScriptParser::new().parse(&file).unwrap();
        (file, ast)
    }

    fn parse_py(path: &str, code: &str) -> (SourceFile, AstNode) {
        let file = SourceFile::new(path, code, LanguageIdentifier::python()).unwrap();
        let ast = yunq_parser_python::PythonParser::new().parse(&file).unwrap();
        (file, ast)
    }

    fn parse_rust(path: &str, code: &str) -> (SourceFile, AstNode) {
        let file = SourceFile::new(path, code, LanguageIdentifier::rust()).unwrap();
        let ast = yunq_parser_rust::RustParser::new().parse(&file).unwrap();
        (file, ast)
    }

    #[test]
    fn detects_a_two_file_ts_cycle() {
        let a = parse_ts("a.ts", "import { b } from './b';\nexport const a = 1;\n");
        let b = parse_ts("b.ts", "import { a } from './a';\nexport const b = 1;\n");
        let files: Vec<(&str, &AstNode)> = vec![(a.0.path(), &a.1), (b.0.path(), &b.1)];
        let graph = ImportGraph::build(&files);
        let cycles = graph.cycles();
        assert_eq!(cycles.len(), 1);
        assert_eq!(cycles[0], vec!["a.ts".to_string(), "b.ts".to_string(), "a.ts".to_string()]);
    }

    #[test]
    fn no_cycle_in_a_linear_ts_chain() {
        let a = parse_ts("a.ts", "import { b } from './b';\n");
        let b = parse_ts("b.ts", "import { c } from './c';\n");
        let c = parse_ts("c.ts", "export const c = 1;\n");
        let files: Vec<(&str, &AstNode)> = vec![(a.0.path(), &a.1), (b.0.path(), &b.1), (c.0.path(), &c.1)];
        assert!(ImportGraph::build(&files).cycles().is_empty());
    }

    #[test]
    fn detects_a_three_file_ts_cycle() {
        let a = parse_ts("a.ts", "import { b } from './b';\n");
        let b = parse_ts("b.ts", "import { c } from './c';\n");
        let c = parse_ts("c.ts", "import { a } from './a';\n");
        let files: Vec<(&str, &AstNode)> = vec![(a.0.path(), &a.1), (b.0.path(), &b.1), (c.0.path(), &c.1)];
        let cycles = ImportGraph::build(&files).cycles();
        assert_eq!(cycles.len(), 1);
        assert_eq!(cycles[0].first(), cycles[0].last());
        assert_eq!(cycles[0].len(), 4);
    }

    #[test]
    fn external_bare_specifiers_produce_no_edges() {
        let a = parse_ts("a.ts", "import React from 'react';\nimport { b } from './b';\n");
        let b = parse_ts("b.ts", "export const b = 1;\n");
        let files: Vec<(&str, &AstNode)> = vec![(a.0.path(), &a.1), (b.0.path(), &b.1)];
        let graph = ImportGraph::build(&files);
        assert_eq!(graph.edges().len(), 1);
        assert!(graph.cycles().is_empty());
    }

    #[test]
    fn detects_a_two_file_python_cycle() {
        let a = parse_py("pkg/a.py", "from .b import thing\n");
        let b = parse_py("pkg/b.py", "from .a import other\n");
        let files: Vec<(&str, &AstNode)> = vec![(a.0.path(), &a.1), (b.0.path(), &b.1)];
        let cycles = ImportGraph::build(&files).cycles();
        assert_eq!(cycles.len(), 1);
        assert_eq!(cycles[0], vec!["pkg/a.py".to_string(), "pkg/b.py".to_string(), "pkg/a.py".to_string()]);
    }

    #[test]
    fn python_absolute_module_cycle_detected() {
        let a = parse_py("pkg/a.py", "from pkg.b import thing\n");
        let b = parse_py("pkg/b.py", "from pkg.a import other\n");
        let files: Vec<(&str, &AstNode)> = vec![(a.0.path(), &a.1), (b.0.path(), &b.1)];
        assert_eq!(ImportGraph::build(&files).cycles().len(), 1);
    }

    #[test]
    fn self_import_is_not_reported_as_a_cycle() {
        // Degenerate/self-referential — deliberately not flagged (see
        // ImportGraph::cycles doc comment).
        let a = parse_ts("a.ts", "export * from './a';\n");
        let files: Vec<(&str, &AstNode)> = vec![(a.0.path(), &a.1)];
        assert!(ImportGraph::build(&files).cycles().is_empty());
    }

    #[test]
    fn edge_span_points_at_the_import_statement() {
        let a = parse_ts("a.ts", "// comment\nimport { b } from './b';\n");
        let b = parse_ts("b.ts", "export const b = 1;\n");
        let files: Vec<(&str, &AstNode)> = vec![(a.0.path(), &a.1), (b.0.path(), &b.1)];
        let graph = ImportGraph::build(&files);
        let span = graph.edge_span("a.ts", "b.ts").unwrap();
        assert_eq!(span.start_line, 2);
    }

    fn rust_crate_index(entries: &[(&str, &str)]) -> HashMap<String, String> {
        entries.iter().map(|(name, dir)| (name.to_string(), dir.to_string())).collect()
    }

    #[test]
    fn plain_build_leaves_rust_use_paths_unresolved() {
        let a = parse_rust("core/a/src/lib.rs", "use yunq_infra_fs::Thing;\n");
        let files: Vec<(&str, &AstNode)> = vec![(a.0.path(), &a.1)];
        assert!(ImportGraph::build(&files).edges().is_empty());
    }

    #[test]
    fn resolves_a_plain_cross_crate_use_against_the_crate_index() {
        let a = parse_rust("core/a/src/lib.rs", "use yunq_infra_fs::Thing;\n");
        let files: Vec<(&str, &AstNode)> = vec![(a.0.path(), &a.1)];
        let index = rust_crate_index(&[("yunq_infra_fs", "infra/fs")]);
        let graph = ImportGraph::build_with_rust_crates(&files, &index);
        assert_eq!(graph.edges().len(), 1);
        assert_eq!(graph.edges()[0].to, "infra/fs/Cargo.toml");
    }

    fn resolves_single_rust_statement(code: &str) -> ImportGraph {
        let a = parse_rust("core/a/src/lib.rs", code);
        let files: Vec<(&str, &AstNode)> = vec![(a.0.path(), &a.1)];
        let index = rust_crate_index(&[("yunq_infra_fs", "infra/fs")]);
        ImportGraph::build_with_rust_crates(&files, &index)
    }

    #[test]
    fn resolves_a_use_list_shape() {
        let graph = resolves_single_rust_statement("use yunq_infra_fs::{FileAnalysisCache, YunqConfig};\n");
        assert_eq!(graph.edges().len(), 1);
        assert_eq!(graph.edges()[0].to, "infra/fs/Cargo.toml");
    }

    #[test]
    fn resolves_a_use_as_clause_renaming_the_crate() {
        let graph = resolves_single_rust_statement("use yunq_infra_fs as fs;\n");
        assert_eq!(graph.edges().len(), 1);
        assert_eq!(graph.edges()[0].to, "infra/fs/Cargo.toml");
    }

    #[test]
    fn resolves_a_use_as_clause_renaming_an_item() {
        let graph = resolves_single_rust_statement("use yunq_infra_fs::Thing as Renamed;\n");
        assert_eq!(graph.edges().len(), 1);
        assert_eq!(graph.edges()[0].to, "infra/fs/Cargo.toml");
    }

    #[test]
    fn resolves_a_use_wildcard_shape() {
        let graph = resolves_single_rust_statement("use yunq_infra_fs::*;\n");
        assert_eq!(graph.edges().len(), 1);
        assert_eq!(graph.edges()[0].to, "infra/fs/Cargo.toml");
    }

    #[test]
    fn repeated_references_to_the_same_crate_dedupe_to_one_edge() {
        let graph = resolves_single_rust_statement(
            "use yunq_infra_fs::{FileAnalysisCache, YunqConfig};\nuse yunq_infra_fs as fs;\nuse yunq_infra_fs::Thing as Renamed;\nuse yunq_infra_fs::*;\n",
        );
        assert_eq!(graph.edges().len(), 1);
        assert_eq!(graph.edges()[0].to, "infra/fs/Cargo.toml");
    }

    #[test]
    fn a_bare_fully_qualified_call_with_no_use_statement_is_still_an_edge() {
        // Rust needs no `use` at all — any crate's items are reachable by
        // full path from anywhere, unlike TS/Python where a name doesn't
        // exist in scope without an import first.
        let graph = resolves_single_rust_statement(
            "pub fn open() -> yunq_infra_fs::Thing {\n    yunq_infra_fs::Thing::new()\n}\n",
        );
        assert_eq!(graph.edges().len(), 1);
        assert_eq!(graph.edges()[0].to, "infra/fs/Cargo.toml");
    }

    #[test]
    fn a_bare_reference_inside_a_cfg_test_module_is_still_excluded() {
        let code = "\
#[cfg(test)]
mod tests {
    #[test]
    fn uses_it() {
        let _ = yunq_infra_fs::Thing::new();
    }
}
";
        let graph = resolves_single_rust_statement(code);
        assert!(graph.edges().is_empty());
    }

    #[test]
    fn crate_self_and_super_paths_produce_no_edge() {
        let a = parse_rust(
            "core/a/src/lib.rs",
            "use crate::foo::Bar;\nuse self::sibling;\nuse super::baz::Qux;\nuse std::collections::HashMap;\n",
        );
        let files: Vec<(&str, &AstNode)> = vec![(a.0.path(), &a.1)];
        // Even an index that (implausibly) had entries named "crate"/"std"
        // must never be consulted for these — they're skipped up front.
        let index = rust_crate_index(&[("crate", "should/never/resolve"), ("std", "should/never/resolve")]);
        let graph = ImportGraph::build_with_rust_crates(&files, &index);
        assert!(graph.edges().is_empty());
    }

    #[test]
    fn a_crate_importing_its_own_external_name_is_not_an_edge() {
        // `core/rules-engine` referring to itself as `yunq_rules_engine`
        // (an unusual but legal absolute self-reference) resolves to the
        // same component as the importer and must not count as crossing a
        // boundary.
        let a = parse_rust("core/rules-engine/src/lib.rs", "use yunq_rules_engine::Other;\n");
        let files: Vec<(&str, &AstNode)> = vec![(a.0.path(), &a.1)];
        let index = rust_crate_index(&[("yunq_rules_engine", "core/rules-engine")]);
        assert!(ImportGraph::build_with_rust_crates(&files, &index).edges().is_empty());
    }

    #[test]
    fn an_external_non_workspace_crate_produces_no_edge() {
        let a = parse_rust("core/a/src/lib.rs", "use serde::Serialize;\n");
        let files: Vec<(&str, &AstNode)> = vec![(a.0.path(), &a.1)];
        let index = rust_crate_index(&[("yunq_infra_fs", "infra/fs")]);
        assert!(ImportGraph::build_with_rust_crates(&files, &index).edges().is_empty());
    }

    #[test]
    fn rust_component_edges_report_a_cross_tier_dependency() {
        let a = parse_rust("core/a/src/lib.rs", "use yunq_infra_fs::Thing;\n");
        let files: Vec<(&str, &AstNode)> = vec![(a.0.path(), &a.1)];
        let index = rust_crate_index(&[("yunq_infra_fs", "infra/fs")]);
        let graph = ImportGraph::build_with_rust_crates(&files, &index);
        assert_eq!(graph.component_edges(), BTreeSet::from([("core/a".to_string(), "infra/fs".to_string())]));
    }

    #[test]
    fn a_standalone_integration_test_file_contributes_no_rust_edges() {
        let a = parse_rust("core/a/tests/it.rs", "use yunq_infra_fs::Thing;\n");
        let files: Vec<(&str, &AstNode)> = vec![(a.0.path(), &a.1)];
        let index = rust_crate_index(&[("yunq_infra_fs", "infra/fs")]);
        assert!(ImportGraph::build_with_rust_crates(&files, &index).edges().is_empty());
    }

    #[test]
    fn a_use_inside_a_cfg_test_module_contributes_no_edge_but_production_code_still_does() {
        let code = "\
use yunq_infra_fs::Production;

#[cfg(test)]
mod tests {
    use yunq_infra_fs::TestOnlyDevDep;

    #[test]
    fn uses_it() {
        let _ = TestOnlyDevDep;
    }
}
";
        let a = parse_rust("core/a/src/lib.rs", code);
        let files: Vec<(&str, &AstNode)> = vec![(a.0.path(), &a.1)];
        let index = rust_crate_index(&[("yunq_infra_fs", "infra/fs")]);
        let graph = ImportGraph::build_with_rust_crates(&files, &index);
        assert_eq!(graph.edges().len(), 1);
        assert!(graph.edges()[0].span.start_line < 3);
    }
}
