//! Hexagonal layer classification from path topology, and the one rule that
//! makes a hexagon a hexagon: **dependencies point inward**.
//!
//! Same conviction as `component`: the directory structure already says
//! which ring a file lives in, so no new config is needed to find out —
//! `domain/order.ts` is the inside, `infrastructure/postgres_orders.ts` is
//! the outside, and an import from the first to the second inverts the
//! dependency the whole architecture is built on. This is the zero-config
//! counterpart to `boundary`'s declared `[architecture]` edges: that one
//! enforces *your* named components, this one enforces the layering
//! vocabulary Ports & Adapters / Clean Architecture / Onion already share.
//!
//! Kept in this crate, not `rulesets/architecture`, for the same reason
//! `boundary` is: pure graph-and-path logic with no `Rule`/`Finding`
//! vocabulary — `architecture::HexagonalLayerRule` is the thin adapter that
//! turns a `Vec<LayerViolation>` into findings.

use vord_ast::Span;

use crate::ImportGraph;

/// One ring of the hexagon, as inferred from a path segment.
///
/// [`HexLayer::Adapter`] and [`HexLayer::Infrastructure`] are distinct names
/// for the *same* ring (depth 2): in Ports & Adapters everything outside the
/// application is an adapter, and the two words are used interchangeably
/// depending on which book a codebase was named after. They share a depth so
/// an `adapters/http` handler calling into `infrastructure/postgres` is not
/// reported — that edge is inside one ring, not a violation of anything.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum HexLayer {
    /// Entities, aggregates, value objects — the inside. Knows nothing.
    Domain,
    /// Use cases / application services orchestrating the domain.
    Application,
    /// The interfaces (ports) the inside declares for the outside to satisfy.
    Port,
    /// Inbound/outbound adapters: controllers, handlers, CLI, UI, gateways.
    Adapter,
    /// Technical detail: persistence, HTTP clients, brokers, frameworks.
    Infrastructure,
    /// No layering vocabulary in the path — deliberately not guessed at.
    Unknown,
}

impl HexLayer {
    /// How far out from the domain this ring sits. `None` for
    /// [`HexLayer::Unknown`], which is never compared against anything.
    ///
    /// `Port` shares `Application`'s depth: a port is declared by the inside
    /// for the outside to implement, so an application service depending on
    /// a port it defines is the intended direction, not a violation.
    pub fn depth(&self) -> Option<u8> {
        match self {
            HexLayer::Domain => Some(0),
            HexLayer::Application | HexLayer::Port => Some(1),
            HexLayer::Adapter | HexLayer::Infrastructure => Some(2),
            HexLayer::Unknown => None,
        }
    }

    /// The word used in finding messages.
    pub fn label(&self) -> &'static str {
        match self {
            HexLayer::Domain => "domain",
            HexLayer::Application => "application",
            HexLayer::Port => "port",
            HexLayer::Adapter => "adapter",
            HexLayer::Infrastructure => "infrastructure",
            HexLayer::Unknown => "unclassified",
        }
    }

    /// Parses one of the five named rings from a `vord.toml`-facing string
    /// (case-insensitive) — the vocabulary a declared [`CustomLayerSpec`] may
    /// subsume into. [`HexLayer::Unknown`] is deliberately not parseable
    /// here: it is the "no vocabulary matched" outcome, never something a
    /// project declares a custom layer *as*.
    fn parse(raw: &str) -> Option<Self> {
        match raw.to_ascii_lowercase().as_str() {
            "domain" => Some(HexLayer::Domain),
            "application" => Some(HexLayer::Application),
            "port" => Some(HexLayer::Port),
            "adapter" => Some(HexLayer::Adapter),
            "infrastructure" => Some(HexLayer::Infrastructure),
            _ => None,
        }
    }
}

/// `core` is included: it is the most common name for "the pure inside" in
/// codebases that don't literally spell `domain` (vord's own workspace is
/// one — `core/` is documented as "PURE LOGIC — no I/O").
const DOMAIN_SEGMENTS: &[&str] = &[
    "domain",
    "domains",
    "entities",
    "entity",
    "aggregate",
    "aggregates",
    "value_objects",
    "value-objects",
    "valueobjects",
    "core",
];

/// `app` is deliberately absent: in a Next.js/Nuxt tree `app/` is the UI
/// router directory, not the application layer, and misreading a whole
/// frontend as "the inside" would invert every finding this module makes.
const APPLICATION_SEGMENTS: &[&str] = &[
    "application",
    "applications",
    "usecase",
    "usecases",
    "use_case",
    "use_cases",
    "use-cases",
    "interactor",
    "interactors",
];

const PORT_SEGMENTS: &[&str] = &["port", "ports"];

const ADAPTER_SEGMENTS: &[&str] = &[
    "adapter",
    "adapters",
    "controller",
    "controllers",
    "handler",
    "handlers",
    "presenter",
    "presenters",
    "presentation",
    "delivery",
    "transport",
    "web",
    "http",
    "rest",
    "graphql",
    "routes",
    "views",
    "cli",
];

const INFRASTRUCTURE_SEGMENTS: &[&str] = &[
    "infrastructure",
    "infra",
    "persistence",
    "database",
    "gateway",
    "gateways",
    "driven",
    "driving",
];

/// The layer a file belongs to, derived purely from its path.
///
/// **Innermost match wins.** A path can name more than one ring
/// (`apps/api/src/domain/order.ts` says both `api` and `domain`), and the
/// inner name is the one that describes the file: that file *is* domain code
/// that happens to live inside a deployable named `api`. Taking the first
/// (outermost) match instead would classify every domain file of an
/// `apps/api`-style monorepo as an adapter and then report the inversion
/// backwards, which is worse than saying nothing.
///
/// A path with no layering vocabulary at all is [`HexLayer::Unknown`] — this
/// module never guesses, and every consumer skips unknowns rather than
/// inventing a ring for them.
pub fn layer_of(path: &str) -> HexLayer {
    let mut best = HexLayer::Unknown;
    for segment in path.split('/') {
        let layer = classify_segment(segment);
        match (layer.depth(), best.depth()) {
            (Some(_), None) => best = layer,
            (Some(depth), Some(best_depth)) if depth < best_depth => best = layer,
            _ => {}
        }
    }
    best
}

fn classify_segment(segment: &str) -> HexLayer {
    let lower = segment.to_ascii_lowercase();
    let table = [
        (DOMAIN_SEGMENTS, HexLayer::Domain),
        (APPLICATION_SEGMENTS, HexLayer::Application),
        (PORT_SEGMENTS, HexLayer::Port),
        (ADAPTER_SEGMENTS, HexLayer::Adapter),
        (INFRASTRUCTURE_SEGMENTS, HexLayer::Infrastructure),
    ];
    table
        .iter()
        .find(|(segments, _)| segments.contains(&lower.as_str()))
        .map(|(_, layer)| *layer)
        .unwrap_or(HexLayer::Unknown)
}

/// One `[[architecture.layer]]` entry, `vord.toml`-facing: a project-specific
/// layer name (`"checkout-domain"`) that plays the role of one of the five
/// built-in rings (`is_a`), matched by glob against a file's path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CustomLayerSpec {
    pub name: String,
    pub is_a: String,
    pub patterns: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum LayerTaxonomyError {
    #[error(
        "layer {name:?} declares unknown parent ring {is_a:?} (expected domain|application|port|adapter|infrastructure)"
    )]
    UnknownParent { name: String, is_a: String },
    #[error("layer {name:?} has an invalid pattern {pattern:?}: {source}")]
    InvalidPattern {
        name: String,
        pattern: String,
        #[source]
        source: globset::Error,
    },
}

#[derive(Clone, Debug)]
struct CustomLayer {
    parent: HexLayer,
    matcher: globset::GlobSet,
}

/// A project's declared extension of the zero-config hexagonal-layer
/// vocabulary: a directory named `checkout/` gets to mean "domain" without
/// renaming it to `domain/`.
///
/// This is single-hop subsumption only — every custom layer's parent must be
/// one of the five built-in rings, never another custom layer — deliberately
/// short of a general ontology. [`LayerTaxonomy::default`] declares no custom
/// layers, so [`LayerTaxonomy::classify`] always falls through to
/// [`layer_of`]: the zero-config behavior every existing caller and test
/// relies on is unchanged when no `[[architecture.layer]]` is configured.
#[derive(Clone, Debug, Default)]
pub struct LayerTaxonomy {
    custom: Vec<CustomLayer>,
}

impl LayerTaxonomy {
    /// Validates and compiles every declared layer. Rejects an `is_a` that
    /// isn't one of the five ring names, and any pattern `globset` itself
    /// rejects — a malformed declaration must fail the scan, not silently
    /// classify nothing.
    pub fn new(entries: Vec<CustomLayerSpec>) -> Result<Self, LayerTaxonomyError> {
        let mut custom = Vec::with_capacity(entries.len());
        for entry in entries {
            let parent =
                HexLayer::parse(&entry.is_a).ok_or_else(|| LayerTaxonomyError::UnknownParent {
                    name: entry.name.clone(),
                    is_a: entry.is_a.clone(),
                })?;
            let mut builder = globset::GlobSetBuilder::new();
            for pattern in &entry.patterns {
                let glob = globset::Glob::new(pattern).map_err(|source| {
                    LayerTaxonomyError::InvalidPattern {
                        name: entry.name.clone(),
                        pattern: pattern.clone(),
                        source,
                    }
                })?;
                builder.add(glob);
            }
            let matcher = builder
                .build()
                .map_err(|source| LayerTaxonomyError::InvalidPattern {
                    name: entry.name.clone(),
                    pattern: "<set>".to_string(),
                    source,
                })?;
            custom.push(CustomLayer { parent, matcher });
        }
        Ok(Self { custom })
    }

    /// The ring `path` belongs to: the parent ring of the first declared
    /// custom layer (declaration order) whose pattern matches, or — for a
    /// project with no matching custom layer, and for every project with
    /// none declared at all — [`layer_of`]'s path-segment heuristic.
    pub fn classify(&self, path: &str) -> HexLayer {
        self.custom
            .iter()
            .find(|layer| layer.matcher.is_match(path))
            .map(|layer| layer.parent)
            .unwrap_or_else(|| layer_of(path))
    }

    pub fn is_domain(&self, path: &str) -> bool {
        self.classify(path) == HexLayer::Domain
    }

    pub fn is_application(&self, path: &str) -> bool {
        self.classify(path) == HexLayer::Application
    }
}

/// One import that points outward: an inner-ring file depending on an
/// outer-ring one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LayerViolation {
    pub from: String,
    pub to: String,
    pub from_layer: HexLayer,
    pub to_layer: HexLayer,
    /// The offending import statement's span in `from`.
    pub span: Span,
}

/// Every outward-pointing import in `graph`.
///
/// Reported per import statement, not per file pair, so a finding lands on
/// the actual line that has to change (same choice
/// `BoundaryViolationRule` makes). Edges where either side is
/// [`HexLayer::Unknown`], and edges inside one ring, are not violations.
pub fn inward_dependency_violations(graph: &ImportGraph) -> Vec<LayerViolation> {
    inward_dependency_violations_with(graph, layer_of)
}

/// Same as [`inward_dependency_violations`], classifying each edge's
/// endpoints through a declared [`LayerTaxonomy`] instead of the hardcoded
/// segment heuristic alone — identical output when `taxonomy` declares no
/// custom layers.
pub fn inward_dependency_violations_with_taxonomy(
    graph: &ImportGraph,
    taxonomy: &LayerTaxonomy,
) -> Vec<LayerViolation> {
    inward_dependency_violations_with(graph, |path| taxonomy.classify(path))
}

fn inward_dependency_violations_with(
    graph: &ImportGraph,
    classify: impl Fn(&str) -> HexLayer,
) -> Vec<LayerViolation> {
    graph
        .edges()
        .iter()
        .filter_map(|edge| {
            let from_layer = classify(&edge.from);
            let to_layer = classify(&edge.to);
            let (from_depth, to_depth) = (from_layer.depth()?, to_layer.depth()?);
            (from_depth < to_depth).then(|| LayerViolation {
                from: edge.from.clone(),
                to: edge.to.clone(),
                from_layer,
                to_layer,
                span: edge.span,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use vord_ast::{AstNode, LanguageIdentifier, SourceFile};
    use vord_rules_engine::AstParser;

    fn graph_of(files: &[(&str, &str)]) -> ImportGraph {
        let parser = vord_parser_typescript::TypeScriptParser::new();
        let parsed: Vec<(SourceFile, AstNode)> = files
            .iter()
            .map(|(path, code)| {
                let file = SourceFile::new(*path, *code, LanguageIdentifier::typescript()).unwrap();
                let ast = parser.parse(&file).unwrap();
                (file, ast)
            })
            .collect();
        let views: Vec<(&str, &AstNode)> = parsed.iter().map(|(f, a)| (f.path(), a)).collect();
        ImportGraph::build(&views)
    }

    #[test]
    fn classifies_each_ring_from_its_conventional_directory_name() {
        assert_eq!(layer_of("src/domain/order.ts"), HexLayer::Domain);
        assert_eq!(
            layer_of("src/application/place_order.ts"),
            HexLayer::Application
        );
        assert_eq!(layer_of("src/ports/order_repository.ts"), HexLayer::Port);
        assert_eq!(
            layer_of("src/adapters/http/order_controller.ts"),
            HexLayer::Adapter
        );
        assert_eq!(
            layer_of("src/infrastructure/postgres_orders.ts"),
            HexLayer::Infrastructure
        );
    }

    #[test]
    fn a_path_with_no_layering_vocabulary_is_unknown() {
        assert_eq!(layer_of("src/utils/format.ts"), HexLayer::Unknown);
        assert_eq!(layer_of("index.ts"), HexLayer::Unknown);
        assert!(HexLayer::Unknown.depth().is_none());
    }

    #[test]
    fn innermost_segment_wins_when_a_path_names_two_rings() {
        // The file is domain code that happens to live inside a deployable
        // called `api` — not an adapter.
        assert_eq!(layer_of("apps/api/src/domain/order.ts"), HexLayer::Domain);
        assert_eq!(
            layer_of("services/web/application/place_order.py"),
            HexLayer::Application
        );
    }

    #[test]
    fn adapter_and_infrastructure_share_a_depth_so_neither_can_violate_the_other() {
        assert_eq!(HexLayer::Adapter.depth(), HexLayer::Infrastructure.depth());
        let graph = graph_of(&[
            (
                "src/adapters/api.ts",
                "import { db } from '../infrastructure/db';\n",
            ),
            ("src/infrastructure/db.ts", "export const db = 1;\n"),
        ]);
        assert!(inward_dependency_violations(&graph).is_empty());
    }

    #[test]
    fn flags_domain_importing_infrastructure() {
        let graph = graph_of(&[
            (
                "src/domain/order.ts",
                "import { db } from '../infrastructure/db';\n",
            ),
            ("src/infrastructure/db.ts", "export const db = 1;\n"),
        ]);
        let violations = inward_dependency_violations(&graph);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].from_layer, HexLayer::Domain);
        assert_eq!(violations[0].to_layer, HexLayer::Infrastructure);
        assert_eq!(violations[0].from, "src/domain/order.ts");
    }

    #[test]
    fn flags_domain_importing_the_application_layer_above_it() {
        let graph = graph_of(&[
            (
                "src/domain/order.ts",
                "import { place } from '../application/place_order';\n",
            ),
            (
                "src/application/place_order.ts",
                "export const place = 1;\n",
            ),
        ]);
        let violations = inward_dependency_violations(&graph);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].to_layer, HexLayer::Application);
    }

    #[test]
    fn silent_on_the_intended_inward_direction() {
        let graph = graph_of(&[
            (
                "src/adapters/order_controller.ts",
                "import { place } from '../application/place_order';\n",
            ),
            (
                "src/application/place_order.ts",
                "import { Order } from '../domain/order';\nexport const place = 1;\n",
            ),
            ("src/domain/order.ts", "export class Order {}\n"),
        ]);
        assert!(inward_dependency_violations(&graph).is_empty());
    }

    #[test]
    fn silent_when_the_application_layer_depends_on_a_port_it_declares() {
        let graph = graph_of(&[
            (
                "src/application/place_order.ts",
                "import { OrderRepository } from '../ports/order_repository';\n",
            ),
            (
                "src/ports/order_repository.ts",
                "export interface OrderRepository {}\n",
            ),
        ]);
        assert!(inward_dependency_violations(&graph).is_empty());
    }

    #[test]
    fn silent_when_either_side_is_unclassified() {
        let graph = graph_of(&[
            (
                "src/domain/order.ts",
                "import { fmt } from '../utils/format';\n",
            ),
            ("src/utils/format.ts", "export const fmt = 1;\n"),
        ]);
        assert!(inward_dependency_violations(&graph).is_empty());
    }

    #[test]
    fn flags_a_python_domain_package_importing_infrastructure() {
        let parser = vord_parser_python::PythonParser::new();
        let files = [
            (
                "src/domain/order.py",
                "from src.infrastructure.db import session\n",
            ),
            ("src/infrastructure/db.py", "session = 1\n"),
        ];
        let parsed: Vec<(SourceFile, AstNode)> = files
            .iter()
            .map(|(path, code)| {
                let file = SourceFile::new(*path, *code, LanguageIdentifier::python()).unwrap();
                let ast = parser.parse(&file).unwrap();
                (file, ast)
            })
            .collect();
        let views: Vec<(&str, &AstNode)> = parsed.iter().map(|(f, a)| (f.path(), a)).collect();
        let graph = ImportGraph::build(&views);
        let violations = inward_dependency_violations(&graph);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].to_layer, HexLayer::Infrastructure);
    }

    fn custom_layer(name: &str, is_a: &str, patterns: &[&str]) -> CustomLayerSpec {
        CustomLayerSpec {
            name: name.to_string(),
            is_a: is_a.to_string(),
            patterns: patterns.iter().map(|p| p.to_string()).collect(),
        }
    }

    #[test]
    fn default_taxonomy_behaves_exactly_like_layer_of() {
        let taxonomy = LayerTaxonomy::default();
        assert_eq!(
            taxonomy.classify("src/domain/order.ts"),
            layer_of("src/domain/order.ts")
        );
        assert_eq!(
            taxonomy.classify("src/checkout/order.ts"),
            layer_of("src/checkout/order.ts")
        );
    }

    #[test]
    fn a_custom_layer_maps_to_its_declared_parent_ring() {
        let taxonomy = LayerTaxonomy::new(vec![custom_layer(
            "checkout-domain",
            "domain",
            &["src/checkout/**"],
        )])
        .unwrap();
        assert_eq!(taxonomy.classify("src/checkout/order.ts"), HexLayer::Domain);
        assert!(taxonomy.is_domain("src/checkout/order.ts"));
        assert!(!taxonomy.is_domain("src/adapters/http.ts"));
    }

    #[test]
    fn an_unmatched_path_still_falls_back_to_the_hardcoded_heuristic() {
        let taxonomy = LayerTaxonomy::new(vec![custom_layer(
            "checkout-domain",
            "domain",
            &["src/checkout/**"],
        )])
        .unwrap();
        assert_eq!(
            taxonomy.classify("src/infrastructure/db.ts"),
            HexLayer::Infrastructure
        );
    }

    #[test]
    fn an_unknown_parent_ring_is_rejected() {
        let err = LayerTaxonomy::new(vec![custom_layer(
            "checkout-domain",
            "not-a-ring",
            &["src/checkout/**"],
        )])
        .unwrap_err();
        assert!(matches!(err, LayerTaxonomyError::UnknownParent { .. }));
    }

    #[test]
    fn a_custom_layer_with_no_patterns_never_matches() {
        let taxonomy =
            LayerTaxonomy::new(vec![custom_layer("empty-layer", "domain", &[])]).unwrap();
        // An empty GlobSet must reject every path, not accept everything by
        // default — a mutation flipping that fallback would make every
        // unclassified path in the project silently "domain".
        assert_eq!(
            taxonomy.classify("src/anything/at/all.ts"),
            HexLayer::Unknown
        );
    }

    #[test]
    fn an_invalid_glob_pattern_is_rejected() {
        let err = LayerTaxonomy::new(vec![custom_layer("checkout-domain", "domain", &["["])])
            .unwrap_err();
        assert!(matches!(err, LayerTaxonomyError::InvalidPattern { .. }));
    }

    #[test]
    fn a_custom_pattern_wins_over_the_default_segment_heuristic() {
        // `src/checkout/adapters/stripe.ts` would classify as Adapter under
        // the innermost-segment heuristic; the declared taxonomy says the
        // whole `checkout/` tree is domain code instead.
        let taxonomy = LayerTaxonomy::new(vec![custom_layer(
            "checkout-domain",
            "domain",
            &["src/checkout/**"],
        )])
        .unwrap();
        assert_eq!(
            layer_of("src/checkout/adapters/stripe.ts"),
            HexLayer::Adapter
        );
        assert_eq!(
            taxonomy.classify("src/checkout/adapters/stripe.ts"),
            HexLayer::Domain
        );
    }

    #[test]
    fn declaration_order_decides_between_overlapping_custom_patterns() {
        let taxonomy = LayerTaxonomy::new(vec![
            custom_layer("checkout-domain", "domain", &["src/checkout/**"]),
            custom_layer(
                "checkout-adapters",
                "adapter",
                &["src/checkout/adapters/**"],
            ),
        ])
        .unwrap();
        assert_eq!(
            taxonomy.classify("src/checkout/adapters/stripe.ts"),
            HexLayer::Domain,
            "first declared match wins, same convention as ArchitectureConfig"
        );
    }

    #[test]
    fn taxonomy_aware_violations_use_the_custom_layer_for_both_endpoints() {
        let graph = graph_of(&[
            (
                "src/checkout/order.ts",
                "import { pool } from '../infrastructure/db';\n",
            ),
            ("src/infrastructure/db.ts", "export const pool = 1;\n"),
        ]);
        let taxonomy = LayerTaxonomy::new(vec![custom_layer(
            "checkout-domain",
            "domain",
            &["src/checkout/**"],
        )])
        .unwrap();
        // Without the taxonomy, `checkout` names no ring at all and the edge
        // is silently skipped.
        assert!(inward_dependency_violations(&graph).is_empty());
        let violations = inward_dependency_violations_with_taxonomy(&graph, &taxonomy);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].from_layer, HexLayer::Domain);
        assert_eq!(violations[0].to_layer, HexLayer::Infrastructure);
    }
}
