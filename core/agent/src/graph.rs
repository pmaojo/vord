//! The `graph` tool's data and pure queries over it (roadmap: agent graph
//! tools).
//!
//! Building the graph — walking the tree, parsing every source file,
//! resolving imports — is I/O and lives on [`crate::runtime::Workspace`];
//! everything here is pure data over what that produces, so the four query
//! shapes below (`dependents`, `dependencies`, `cycles`, `components`) are
//! unit-testable without a filesystem, the same split `completion` already
//! draws between "the analyzer's raw findings" and "the verdict over them".

/// One resolved import: `from` imports `to`. File-level, matching
/// `vord_import_graph::ImportEdge` minus the span the agent has no use for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GraphEdge {
    pub from: String,
    pub to: String,
}

/// A snapshot of the repository's import/dependency graph at the moment it
/// was built. Rebuilt on every `graph` tool call, the same way `Analyzer`
/// rescans on every `scan` call — the agent may have just written the file
/// whose dependents it is asking about.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GraphSnapshot {
    /// File-level import edges, for `dependents`/`dependencies`/`cycles`.
    pub edges: Vec<GraphEdge>,
    /// The same edges collapsed to component level (path-topology
    /// components — see `vord_import_graph::component_of`), for `components`.
    pub component_edges: Vec<(String, String)>,
    /// Every import cycle, each an ordered path `[a, b, c, a]` — see
    /// `vord_import_graph::ImportGraph::cycles` for the exact shape.
    pub cycles: Vec<Vec<String>>,
}

/// Which view of the graph a `graph` tool call asked for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GraphQueryKind {
    /// Files that import the given `path` — "who breaks if I change this".
    Dependents,
    /// Files the given `path` imports — "what does this file pull in".
    Dependencies,
    /// Import cycles, optionally narrowed to the ones a given `path` sits
    /// in; every cycle when no `path` is given.
    Cycles,
    /// Component-level coupling across the whole repository. `path` is
    /// ignored — this view is never scoped to one file.
    Components,
}

impl GraphQueryKind {
    pub const ALL: [GraphQueryKind; 4] = [
        Self::Dependents,
        Self::Dependencies,
        Self::Cycles,
        Self::Components,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Dependents => "dependents",
            Self::Dependencies => "dependencies",
            Self::Cycles => "cycles",
            Self::Components => "components",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.as_str() == raw)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum GraphQueryError {
    #[error("`graph` query `{0}` requires a `path`")]
    MissingPath(&'static str),
}

/// Most lines one `graph` answer renders before it is cut off, matching
/// `RepoWorkspace::search`'s own cap (`MAX_SEARCH_HITS`) for the same
/// reason: an unbounded answer on a large repository — every cycle, every
/// component edge — would spend a whole tool call's worth of the model's
/// context on one response, and that cost falls hardest on exactly the
/// smaller-context local models (Qwen and friends over Ollama/vLLM) this
/// tool is meant to work well with, not just on frontier ones with room to
/// spare.
const MAX_GRAPH_ITEMS: usize = 200;

/// Renders `total` items through `line`, stopping at [`MAX_GRAPH_ITEMS`] and
/// saying so rather than silently dropping the rest.
fn render_capped<T>(
    heading: String,
    total: usize,
    items: impl Iterator<Item = T>,
    line: impl Fn(T) -> String,
) -> String {
    let mut out = format!("{heading}:\n");
    for (shown, item) in items.enumerate() {
        if shown >= MAX_GRAPH_ITEMS {
            out.push_str(&format!("  … truncated at {MAX_GRAPH_ITEMS} of {total}\n"));
            break;
        }
        out.push_str(&format!("  - {}\n", line(item)));
    }
    out
}

fn render_paths(heading: &str, paths: &[String]) -> String {
    if paths.is_empty() {
        return format!("no {heading}");
    }
    render_capped(heading.to_string(), paths.len(), paths.iter(), |path| {
        path.clone()
    })
}

fn render_cycles(cycles: &[Vec<String>]) -> String {
    if cycles.is_empty() {
        return "no import cycles".to_string();
    }
    render_capped(
        format!("{} import cycle(s)", cycles.len()),
        cycles.len(),
        cycles.iter(),
        |cycle| cycle.join(" -> "),
    )
}

fn render_component_edges(edges: &[(String, String)]) -> String {
    if edges.is_empty() {
        return "no component-level dependency edges".to_string();
    }
    render_capped(
        format!("{} component-level edge(s)", edges.len()),
        edges.len(),
        edges.iter(),
        |(from, to)| format!("{from} -> {to}"),
    )
}

impl GraphSnapshot {
    /// Files with an edge landing on `path` — sorted and deduplicated, since
    /// several import statements in the same file all resolving to `path`
    /// is one dependent, not several.
    pub fn dependents_of(&self, path: &str) -> Vec<String> {
        let mut out: Vec<String> = self
            .edges
            .iter()
            .filter(|edge| edge.to == path)
            .map(|edge| edge.from.clone())
            .collect();
        out.sort();
        out.dedup();
        out
    }

    /// Files `path` has an edge to — sorted and deduplicated for the same
    /// reason as [`Self::dependents_of`].
    pub fn dependencies_of(&self, path: &str) -> Vec<String> {
        let mut out: Vec<String> = self
            .edges
            .iter()
            .filter(|edge| edge.from == path)
            .map(|edge| edge.to.clone())
            .collect();
        out.sort();
        out.dedup();
        out
    }

    /// Every cycle, or only the ones `path` is a member of when one is
    /// given.
    pub fn cycles_touching(&self, path: Option<&str>) -> Vec<Vec<String>> {
        match path {
            None => self.cycles.clone(),
            Some(path) => self
                .cycles
                .iter()
                .filter(|cycle| cycle.iter().any(|node| node == path))
                .cloned()
                .collect(),
        }
    }

    /// Renders the answer to one `graph` tool call — the text a
    /// `ToolResult` carries back to the model.
    pub fn answer(
        &self,
        kind: GraphQueryKind,
        path: Option<&str>,
    ) -> Result<String, GraphQueryError> {
        match kind {
            GraphQueryKind::Dependents => {
                let path = path.ok_or(GraphQueryError::MissingPath(kind.as_str()))?;
                Ok(render_paths(
                    &format!("file(s) that import `{path}`"),
                    &self.dependents_of(path),
                ))
            }
            GraphQueryKind::Dependencies => {
                let path = path.ok_or(GraphQueryError::MissingPath(kind.as_str()))?;
                Ok(render_paths(
                    &format!("file(s) `{path}` imports"),
                    &self.dependencies_of(path),
                ))
            }
            GraphQueryKind::Cycles => Ok(render_cycles(&self.cycles_touching(path))),
            GraphQueryKind::Components => Ok(render_component_edges(&self.component_edges)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn edge(from: &str, to: &str) -> GraphEdge {
        GraphEdge {
            from: from.to_string(),
            to: to.to_string(),
        }
    }

    fn snapshot() -> GraphSnapshot {
        GraphSnapshot {
            edges: vec![
                edge("src/a.rs", "src/b.rs"),
                edge("src/c.rs", "src/b.rs"),
                edge("src/b.rs", "src/d.rs"),
            ],
            component_edges: vec![("core/a".to_string(), "infra/fs".to_string())],
            cycles: vec![vec![
                "src/x.rs".to_string(),
                "src/y.rs".to_string(),
                "src/x.rs".to_string(),
            ]],
        }
    }

    #[test]
    fn query_kinds_round_trip_through_their_wire_string() {
        for kind in GraphQueryKind::ALL {
            assert_eq!(GraphQueryKind::parse(kind.as_str()), Some(kind));
        }
        assert_eq!(GraphQueryKind::parse("neighbors"), None);
    }

    #[test]
    fn dependents_of_finds_every_importer_sorted_and_deduped() {
        let snapshot = snapshot();
        assert_eq!(
            snapshot.dependents_of("src/b.rs"),
            vec!["src/a.rs".to_string(), "src/c.rs".to_string()]
        );
        assert!(snapshot.dependents_of("src/a.rs").is_empty());
    }

    #[test]
    fn dependencies_of_finds_what_a_file_imports() {
        let snapshot = snapshot();
        assert_eq!(
            snapshot.dependencies_of("src/a.rs"),
            vec!["src/b.rs".to_string()]
        );
        assert!(snapshot.dependencies_of("src/d.rs").is_empty());
    }

    #[test]
    fn cycles_touching_narrows_to_the_given_path() {
        let snapshot = snapshot();
        assert_eq!(snapshot.cycles_touching(None).len(), 1);
        assert_eq!(snapshot.cycles_touching(Some("src/x.rs")).len(), 1);
        assert!(snapshot.cycles_touching(Some("src/a.rs")).is_empty());
    }

    #[test]
    fn dependents_without_a_path_is_a_missing_path_error() {
        let error = snapshot()
            .answer(GraphQueryKind::Dependents, None)
            .unwrap_err();
        assert_eq!(error, GraphQueryError::MissingPath("dependents"));
    }

    #[test]
    fn dependencies_without_a_path_is_a_missing_path_error() {
        let error = snapshot()
            .answer(GraphQueryKind::Dependencies, None)
            .unwrap_err();
        assert_eq!(error, GraphQueryError::MissingPath("dependencies"));
    }

    #[test]
    fn dependents_answer_names_the_importers() {
        let text = snapshot()
            .answer(GraphQueryKind::Dependents, Some("src/b.rs"))
            .unwrap();
        assert!(text.contains("src/a.rs"));
        assert!(text.contains("src/c.rs"));
    }

    #[test]
    fn an_empty_result_says_so_rather_than_returning_nothing() {
        let text = snapshot()
            .answer(
                GraphQueryKind::Dependents,
                Some("src/nobody-imports-this.rs"),
            )
            .unwrap();
        assert!(text.starts_with("no "), "{text}");
    }

    #[test]
    fn cycles_answer_ignores_a_path_that_matches_nothing() {
        let text = snapshot().answer(GraphQueryKind::Cycles, None).unwrap();
        assert!(text.contains("src/x.rs -> src/y.rs -> src/x.rs"));
    }

    #[test]
    fn components_answer_ignores_path_entirely() {
        let with_path = snapshot()
            .answer(GraphQueryKind::Components, Some("src/a.rs"))
            .unwrap();
        let without_path = snapshot().answer(GraphQueryKind::Components, None).unwrap();
        assert_eq!(with_path, without_path);
        assert!(with_path.contains("core/a -> infra/fs"));
    }

    #[test]
    fn an_empty_graph_answers_every_kind_without_a_path() {
        let empty = GraphSnapshot::default();
        assert!(
            empty
                .answer(GraphQueryKind::Cycles, None)
                .unwrap()
                .contains("no")
        );
        assert!(
            empty
                .answer(GraphQueryKind::Components, None)
                .unwrap()
                .contains("no")
        );
    }

    /// A large repository's dependents list must not spend a whole tool
    /// call's context on one answer — the exact cost that falls hardest on
    /// a smaller-context local model.
    #[test]
    fn a_dependents_answer_is_capped_rather_than_unbounded() {
        let edges: Vec<GraphEdge> = (0..(MAX_GRAPH_ITEMS + 50))
            .map(|i| edge(&format!("src/importer_{i}.rs"), "src/target.rs"))
            .collect();
        let snapshot = GraphSnapshot {
            edges,
            ..Default::default()
        };

        let text = snapshot
            .answer(GraphQueryKind::Dependents, Some("src/target.rs"))
            .unwrap();

        assert_eq!(text.matches("  - ").count(), MAX_GRAPH_ITEMS);
        assert!(
            text.contains(&format!(
                "truncated at {MAX_GRAPH_ITEMS} of {}",
                MAX_GRAPH_ITEMS + 50
            )),
            "{text}"
        );
    }
}
