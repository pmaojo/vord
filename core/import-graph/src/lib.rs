//! Import/export dependency graph over a file set, and cycle detection on
//! it — the enabler for `rulesets/architecture::DependencyCycleRule`. Pure:
//! no I/O, works purely off the neutral AST and a list of candidate file
//! paths (the same file set a `CrossFileRule` already receives).
//!
//! TypeScript/JS and Python only for now (see `resolve` module docs for
//! what's resolved and what's deliberately left external); other languages
//! contribute no edges (harmless, not an error).

mod resolve;

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use yunq_ast::{AstNode, NodeKind, Span};

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

impl ImportGraph {
    /// Builds the graph from a file set — the same `&[(path, ast)]` shape
    /// `core/taint::CrossFileTaint::find_flows` takes.
    pub fn build(files: &[(&str, &AstNode)]) -> Self {
        let candidates: Vec<&str> = files.iter().map(|(path, _)| *path).collect();
        let mut edges = Vec::new();
        for (path, ast) in files {
            if is_ts_like(path) {
                extract_ts_edges(path, ast, &candidates, &mut edges);
            } else if path.ends_with(".py") {
                extract_py_edges(path, ast, &candidates, &mut edges);
            }
        }
        Self { edges }
    }

    pub fn edges(&self) -> &[ImportEdge] {
        &self.edges
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
}
