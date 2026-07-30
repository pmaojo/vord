//! Declared architecture boundaries (roadmap D2): `allowed_dependencies`
//! and `forbidden_dependencies` between components (see
//! `component::component_of`), with `exceptions` as the escape hatch for a
//! specific edge that would otherwise be caught by either.
//!
//! Kept in this crate, not `rulesets/architecture`, because it is pure
//! graph-and-config logic with no `Rule`/`Finding` vocabulary of its own —
//! `rulesets/architecture::BoundaryViolationRule` is the thin adapter that
//! turns a `Vec<BoundaryViolation>` into findings, same split as
//! `ImportGraph::cycles()` versus `DependencyCycleRule`.

use std::collections::BTreeSet;

use crate::ImportGraph;

/// One declared dependency edge between components. The `yunq.toml`-facing
/// shape (`yunq_infra_fs::DependencyEdgeConfig`) mirrors this 1:1; kept as a
/// separate type here so this crate has no dependency on `infra/fs`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct DependencyEdge {
    pub from: String,
    pub to: String,
}

impl DependencyEdge {
    pub fn new(from: impl Into<String>, to: impl Into<String>) -> Self {
        Self { from: from.into(), to: to.into() }
    }

    fn matches(&self, from: &str, to: &str) -> bool {
        matches_component(&self.from, from) && matches_component(&self.to, to)
    }
}

/// A pattern with no component-name segment (e.g. `"core"`, matching the
/// tier a `component_of` two-segment id's first half names) matches every
/// component in that tier, not only a component literally named `"core"` —
/// the tier-wide case (`"core -> infra"` in the roadmap's own example) is
/// the common one; an exact `"core/rules-engine"` still matches only itself.
fn matches_component(pattern: &str, component: &str) -> bool {
    component == pattern || component.starts_with(&format!("{pattern}/"))
}

/// `[architecture]` in `yunq.toml`, engine-facing. Empty (the default,
/// `is_empty()` true) means no boundaries declared — `violations` then
/// never fires, the same fail-open convention every other optional
/// `yunq.toml` table follows (see `DuplicationSettings`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ArchitectureConfig {
    pub allowed_dependencies: Vec<DependencyEdge>,
    pub forbidden_dependencies: Vec<DependencyEdge>,
    pub exceptions: Vec<DependencyEdge>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ViolationKind {
    /// Matched an explicit `forbidden_dependencies` entry.
    Forbidden,
    /// `allowed_dependencies` is non-empty (whitelist mode) and this edge
    /// matched none of its entries.
    Undeclared,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BoundaryViolation {
    pub from: String,
    pub to: String,
    pub kind: ViolationKind,
}

impl ArchitectureConfig {
    /// No boundaries declared at all — the state a project with no
    /// `[architecture]` table (or an empty one) is in.
    pub fn is_empty(&self) -> bool {
        self.allowed_dependencies.is_empty() && self.forbidden_dependencies.is_empty()
    }

    /// Every declared-boundary violation among `graph`'s component-level
    /// edges. `forbidden_dependencies` is checked first (an edge can't be
    /// both explicitly forbidden and merely undeclared); `exceptions`
    /// overrides either outcome for the specific edges it lists.
    pub fn violations(&self, graph: &ImportGraph) -> Vec<BoundaryViolation> {
        if self.is_empty() {
            return Vec::new();
        }
        let edges: BTreeSet<(String, String)> = graph.component_edges();
        edges
            .into_iter()
            .filter(|(from, to)| !self.exceptions.iter().any(|e| e.matches(from, to)))
            .filter_map(|(from, to)| {
                if self.forbidden_dependencies.iter().any(|e| e.matches(&from, &to)) {
                    return Some(BoundaryViolation { from, to, kind: ViolationKind::Forbidden });
                }
                if !self.allowed_dependencies.is_empty()
                    && !self.allowed_dependencies.iter().any(|e| e.matches(&from, &to))
                {
                    return Some(BoundaryViolation { from, to, kind: ViolationKind::Undeclared });
                }
                None
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use yunq_ast::{LanguageIdentifier, SourceFile};
    use yunq_rules_engine::AstParser;

    fn graph_of(files: &[(&str, &str)]) -> ImportGraph {
        let parser = yunq_parser_typescript::TypeScriptParser::new();
        let parsed: Vec<(SourceFile, yunq_ast::AstNode)> = files
            .iter()
            .map(|(path, code)| {
                let file = SourceFile::new(*path, *code, LanguageIdentifier::typescript()).unwrap();
                let ast = parser.parse(&file).unwrap();
                (file, ast)
            })
            .collect();
        let views: Vec<(&str, &yunq_ast::AstNode)> = parsed.iter().map(|(f, a)| (f.path(), a)).collect();
        ImportGraph::build(&views)
    }

    #[test]
    fn no_config_means_no_violations() {
        let graph = graph_of(&[("core/a.ts", "import { b } from '../infra/b';\n"), ("infra/b.ts", "export const b = 1;\n")]);
        assert!(ArchitectureConfig::default().violations(&graph).is_empty());
    }

    #[test]
    fn forbidden_tier_edge_flags_a_crate_level_import() {
        let graph = graph_of(&[
            ("core/a.ts", "import { b } from '../infra/b';\n"),
            ("infra/b.ts", "export const b = 1;\n"),
        ]);
        let config = ArchitectureConfig {
            forbidden_dependencies: vec![DependencyEdge::new("core", "infra")],
            ..Default::default()
        };
        let violations = config.violations(&graph);
        assert_eq!(violations, vec![BoundaryViolation { from: "core".into(), to: "infra".into(), kind: ViolationKind::Forbidden }]);
    }

    #[test]
    fn allow_listing_makes_every_other_edge_a_violation() {
        let graph = graph_of(&[
            ("bin/a.ts", "import { b } from '../core/b';\nimport { c } from '../infra/c';\n"),
            ("core/b.ts", "export const b = 1;\n"),
            ("infra/c.ts", "export const c = 1;\n"),
        ]);
        let config = ArchitectureConfig {
            allowed_dependencies: vec![DependencyEdge::new("bin", "core")],
            ..Default::default()
        };
        let violations = config.violations(&graph);
        assert_eq!(violations, vec![BoundaryViolation { from: "bin".into(), to: "infra".into(), kind: ViolationKind::Undeclared }]);
    }

    #[test]
    fn exception_overrides_a_forbidden_edge() {
        let graph = graph_of(&[
            ("core/legacy/a.ts", "import { b } from '../../infra/b';\n"),
            ("infra/b.ts", "export const b = 1;\n"),
        ]);
        let config = ArchitectureConfig {
            forbidden_dependencies: vec![DependencyEdge::new("core", "infra")],
            exceptions: vec![DependencyEdge::new("core/legacy", "infra")],
            ..Default::default()
        };
        assert!(config.violations(&graph).is_empty());
    }

    #[test]
    fn within_component_edges_never_violate() {
        let graph = graph_of(&[
            ("core/rules-engine/a.ts", "import { b } from './b';\n"),
            ("core/rules-engine/b.ts", "export const b = 1;\n"),
        ]);
        let config = ArchitectureConfig {
            forbidden_dependencies: vec![DependencyEdge::new("core", "core")],
            ..Default::default()
        };
        assert!(config.violations(&graph).is_empty());
    }
}
