//! Component-level architecture metrics — Robert C. Martin's package
//! metrics, computed over the same component graph `boundary` checks
//! declared edges against:
//!
//! - **Ca** (afferent coupling): how many components depend on this one.
//! - **Ce** (efferent coupling): how many components this one depends on.
//! - **I** (instability) = `Ce / (Ca + Ce)`: 0 = nothing depends outward, so
//!   changing it is hard and nobody forces it to change; 1 = depends on
//!   everything and nothing depends on it, so it is free to change.
//! - **A** (abstractness) = abstract types / all types: how much of what the
//!   component exposes is an interface/trait/abstract class rather than a
//!   concrete implementation.
//! - **D** (distance from the main sequence) = `|A + I - 1|`: how far the
//!   component sits from the `A + I = 1` line where abstractness and
//!   instability are in balance. High D means either the *zone of pain*
//!   (concrete and stable — everyone depends on it and it cannot change) or
//!   the *zone of uselessness* (abstract and unstable — abstractions nobody
//!   uses).
//!
//! The Ca/Ce half is what CodeQL exposes per type as
//! `TAfferentCoupling.ql`/`TEfferentCoupling.ql` and combines in
//! `java/hub-class`; the A/I/D half is what SonarQube's package-tangle and
//! design pages historically reported. Neither ships it as a *gate*: this
//! crate computes the numbers so `rulesets/architecture` can fail a build on
//! them.
//!
//! Abstractness cannot be derived from the import graph alone (it needs each
//! file's declarations), so [`component_metrics`] takes the per-component
//! type census as an argument — the rule that has the ASTs counts them, this
//! module stays pure graph arithmetic.

use std::collections::{BTreeMap, BTreeSet};

use crate::ImportGraph;

/// One component's type census: how many types it declares, and how many of
/// those are abstractions (TS `interface`/`abstract class`, Rust `trait`,
/// Python `Protocol`/ABC subclass).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TypeCensus {
    pub total: usize,
    pub abstractions: usize,
}

impl TypeCensus {
    pub fn new(total: usize, abstractions: usize) -> Self {
        Self { total, abstractions }
    }

    /// Accumulates another file's counts into this component's census.
    pub fn add(&mut self, other: TypeCensus) {
        self.total += other.total;
        self.abstractions += other.abstractions;
    }
}

/// Martin's package metrics for one component.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComponentMetrics {
    pub component: String,
    pub afferent: usize,
    pub efferent: usize,
    pub census: TypeCensus,
}

impl ComponentMetrics {
    /// `I = Ce / (Ca + Ce)`. A component with no coupling at all is defined
    /// as maximally stable (0.0) rather than undefined: nothing depends on
    /// it and it depends on nothing, so no change pressure reaches it.
    pub fn instability(&self) -> f64 {
        let total = self.afferent + self.efferent;
        if total == 0 {
            return 0.0;
        }
        self.efferent as f64 / total as f64
    }

    /// `A = abstractions / types`. A component declaring no types at all is
    /// 0.0 (nothing abstract to find), never a division by zero.
    pub fn abstractness(&self) -> f64 {
        if self.census.total == 0 {
            return 0.0;
        }
        self.census.abstractions as f64 / self.census.total as f64
    }

    /// `D = |A + I - 1|`, normalized to `0.0..=1.0`.
    pub fn distance_from_main_sequence(&self) -> f64 {
        (self.abstractness() + self.instability() - 1.0).abs()
    }

    /// True when high `D` comes from being concrete *and* heavily depended
    /// upon — the zone of pain, where a change breaks every caller and no
    /// abstraction exists to absorb it. The other high-`D` corner (the zone
    /// of uselessness) reads very differently in a finding message, so
    /// callers distinguish them.
    pub fn in_zone_of_pain(&self) -> bool {
        self.abstractness() + self.instability() < 1.0
    }
}

/// Martin's metrics for every component that appears in `graph`'s
/// component-level edges or in `census`, keyed by component name.
///
/// `census` is keyed by component (see [`component_of`]); components missing
/// from it get an empty census (`A = 0`), which is the honest reading for a
/// component whose files declare no types.
pub fn component_metrics(
    graph: &ImportGraph,
    census: &BTreeMap<String, TypeCensus>,
) -> BTreeMap<String, ComponentMetrics> {
    let edges: BTreeSet<(String, String)> = graph.component_edges();
    let mut components: BTreeSet<String> = census.keys().cloned().collect();
    for (from, to) in &edges {
        components.insert(from.clone());
        components.insert(to.clone());
    }
    components
        .into_iter()
        .map(|component| {
            let efferent = edges.iter().filter(|(from, _)| *from == component).count();
            let afferent = edges.iter().filter(|(_, to)| *to == component).count();
            let metrics = ComponentMetrics {
                component: component.clone(),
                afferent,
                efferent,
                census: census.get(&component).copied().unwrap_or_default(),
            };
            (component, metrics)
        })
        .collect()
}

/// One component edge that points from a more stable component to a less
/// stable one — a violation of the **Stable Dependencies Principle**:
/// "depend in the direction of stability". A stable component (low `I`,
/// widely depended upon, hard to change) that reaches out to a volatile one
/// inherits that volatility: every change to the unstable component can
/// force a change in the stable one, and through it in everything that
/// depends on it.
#[derive(Clone, Debug, PartialEq)]
pub struct StabilityViolation {
    pub from: String,
    pub to: String,
    pub from_instability: f64,
    pub to_instability: f64,
}

/// Every SDP violation among `metrics`' components, i.e. every edge whose
/// target is less stable than its source by more than `margin`.
///
/// `margin` exists because `I` is a ratio over small integers: with two or
/// three couplings on either side, a difference of 0.1 is one import, not a
/// design decision. Callers pass the tolerance they are willing to defend in
/// a build failure.
pub fn stability_violations(
    graph: &ImportGraph,
    metrics: &BTreeMap<String, ComponentMetrics>,
    margin: f64,
) -> Vec<StabilityViolation> {
    graph
        .component_edges()
        .into_iter()
        .filter_map(|(from, to)| {
            let from_instability = metrics.get(&from)?.instability();
            let to_instability = metrics.get(&to)?.instability();
            (to_instability - from_instability > margin).then_some(StabilityViolation {
                from,
                to,
                from_instability,
                to_instability,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::component_of;
    use yunq_ast::{AstNode, LanguageIdentifier, SourceFile};
    use yunq_rules_engine::AstParser;

    fn graph_of(files: &[(&str, &str)]) -> ImportGraph {
        let parser = yunq_parser_typescript::TypeScriptParser::new();
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

    /// `pkg-a` and `pkg-b` both import `pkg-core`; nothing imports them.
    fn fan_in_graph() -> ImportGraph {
        graph_of(&[
            ("pkg-a/src/a.ts", "import { c } from '../../pkg-core/src/c';\n"),
            ("pkg-b/src/b.ts", "import { c } from '../../pkg-core/src/c';\n"),
            ("pkg-core/src/c.ts", "export const c = 1;\n"),
        ])
    }

    #[test]
    fn afferent_and_efferent_coupling_count_distinct_components() {
        let metrics = component_metrics(&fan_in_graph(), &BTreeMap::new());
        let core = &metrics["pkg-core/src"];
        assert_eq!(core.afferent, 2);
        assert_eq!(core.efferent, 0);
        let a = &metrics["pkg-a/src"];
        assert_eq!(a.afferent, 0);
        assert_eq!(a.efferent, 1);
    }

    #[test]
    fn instability_is_zero_for_a_pure_dependee_and_one_for_a_pure_dependent() {
        let metrics = component_metrics(&fan_in_graph(), &BTreeMap::new());
        assert_eq!(metrics["pkg-core/src"].instability(), 0.0);
        assert_eq!(metrics["pkg-a/src"].instability(), 1.0);
    }

    #[test]
    fn an_uncoupled_component_is_stable_rather_than_undefined() {
        let census = BTreeMap::from([("solo".to_string(), TypeCensus::new(3, 0))]);
        let metrics = component_metrics(&graph_of(&[]), &census);
        assert_eq!(metrics["solo"].instability(), 0.0);
        assert_eq!(metrics["solo"].abstractness(), 0.0);
    }

    #[test]
    fn abstractness_is_the_share_of_declared_types_that_are_abstractions() {
        let census = BTreeMap::from([("pkg-core/src".to_string(), TypeCensus::new(4, 3))]);
        let metrics = component_metrics(&fan_in_graph(), &census);
        assert_eq!(metrics["pkg-core/src"].abstractness(), 0.75);
        // A = 0.75, I = 0.0 -> D = 0.25: near the main sequence.
        assert_eq!(metrics["pkg-core/src"].distance_from_main_sequence(), 0.25);
    }

    #[test]
    fn a_concrete_widely_depended_on_component_lands_in_the_zone_of_pain() {
        let census = BTreeMap::from([("pkg-core/src".to_string(), TypeCensus::new(10, 0))]);
        let metrics = component_metrics(&fan_in_graph(), &census);
        let core = &metrics["pkg-core/src"];
        // A = 0, I = 0 -> D = 1.
        assert_eq!(core.distance_from_main_sequence(), 1.0);
        assert!(core.in_zone_of_pain());
    }

    #[test]
    fn an_abstract_component_nobody_depends_on_is_useless_not_painful() {
        let census = BTreeMap::from([("pkg-a/src".to_string(), TypeCensus::new(4, 4))]);
        let metrics = component_metrics(&fan_in_graph(), &census);
        let a = &metrics["pkg-a/src"];
        // A = 1, I = 1 -> D = 1, but on the other side of the line.
        assert_eq!(a.distance_from_main_sequence(), 1.0);
        assert!(!a.in_zone_of_pain());
    }

    #[test]
    fn flags_a_stable_component_depending_on_a_less_stable_one() {
        // `pkg-core` is depended on by two components *and* reaches out to
        // `pkg-volatile`, which depends on everything and is depended on by
        // nothing.
        let graph = graph_of(&[
            ("pkg-a/src/a.ts", "import { c } from '../../pkg-core/src/c';\n"),
            ("pkg-b/src/b.ts", "import { c } from '../../pkg-core/src/c';\n"),
            (
                "pkg-core/src/c.ts",
                "import { v } from '../../pkg-volatile/src/v';\nexport const c = v;\n",
            ),
            (
                "pkg-volatile/src/v.ts",
                "import { a } from '../../pkg-a/src/a';\nimport { b } from '../../pkg-b/src/b';\nexport const v = a + b;\n",
            ),
        ]);
        let metrics = component_metrics(&graph, &BTreeMap::new());
        let violations = stability_violations(&graph, &metrics, 0.2);
        assert!(
            violations.iter().any(|v| v.from == "pkg-core/src" && v.to == "pkg-volatile/src"),
            "expected pkg-core -> pkg-volatile, got {violations:?}"
        );
    }

    #[test]
    fn silent_when_dependencies_point_toward_stability() {
        let graph = fan_in_graph();
        let metrics = component_metrics(&graph, &BTreeMap::new());
        assert!(stability_violations(&graph, &metrics, 0.2).is_empty());
    }

    #[test]
    fn margin_suppresses_a_difference_of_one_import() {
        let graph = fan_in_graph();
        let metrics = component_metrics(&graph, &BTreeMap::new());
        // pkg-a (I = 1.0) -> pkg-core (I = 0.0) is the good direction; the
        // reverse edge doesn't exist, so nothing fires at any margin.
        assert!(stability_violations(&graph, &metrics, 0.0).is_empty());
    }

    #[test]
    fn census_add_accumulates_per_file_counts() {
        let mut census = TypeCensus::default();
        census.add(TypeCensus::new(2, 1));
        census.add(TypeCensus::new(3, 0));
        assert_eq!(census, TypeCensus::new(5, 1));
    }

    #[test]
    fn component_of_keys_are_what_the_census_must_use() {
        // Guards the contract between this module and its callers: the
        // census must be keyed the same way the graph collapses paths.
        assert_eq!(component_of("pkg-core/src/c.ts"), "pkg-core/src");
    }
}
