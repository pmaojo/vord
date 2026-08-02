//! Rule: a component far from the *main sequence* — Robert C. Martin's
//! `D = |A + I - 1|` metric over the component graph
//! (`vord_import_graph::metrics`).
//!
//! Two failure modes, one number:
//!
//! - **Zone of pain** (`A + I < 1`): concrete *and* widely depended upon.
//!   Everything imports it, nothing abstracts it, so every change to it is a
//!   change to its callers — the practical definition of a codebase that is
//!   hard to change. This is the Dependency Inversion Principle stated at
//!   component scale: heavily-used components should be depended upon through
//!   abstractions.
//! - **Zone of uselessness** (`A + I > 1`): abstract and unstable —
//!   interfaces and traits nobody depends on. Abstraction that buys nothing,
//!   which is the Interface Segregation Principle's failure mode at component
//!   scale.
//!
//! Where this comes from: the Ca/Ce half of the arithmetic is what CodeQL
//! reports per type (`TAfferentCoupling.ql`, `TEfferentCoupling.ql`) and
//! thresholds in `java/hub-class`; the A/I/D half is Martin's package-metric
//! suite, which SonarQube historically surfaced on its design pages. Both
//! present it as a *number to look at*. Here it is a rule that can fail a
//! build, which is the only form a gatekeeper can use.
//!
//! Thresholds are deliberately conservative: `D` is a ratio over small
//! integers, so a component with three types and two imports can hit `D = 1`
//! without meaning anything. A component must declare `min_types` types and
//! carry `min_couplings` component-level dependencies before it is judged.

use vord_ast::{AstNode, SourceFile, Span};
use vord_import_graph::{ComponentMetrics, ImportGraph, component_metrics, component_of};
use vord_rules_engine::{CrossFileRule, Finding, IssueType, RuleId, RuleMetadata, Severity};

use crate::census::component_census;

pub struct MainSequenceRule {
    id: RuleId,
    max_distance: f64,
    min_types: usize,
    min_couplings: usize,
}

impl MainSequenceRule {
    pub fn new(max_distance: f64, min_types: usize, min_couplings: usize) -> Self {
        Self {
            id: RuleId::new("architecture:main-sequence-deviation").expect("valid rule id"),
            max_distance,
            min_types,
            min_couplings,
        }
    }
}

impl Default for MainSequenceRule {
    /// `D > 0.7` is the "clearly in a zone, not merely off-centre" band; 5
    /// types and 3 component couplings are the floor at which the ratios stop
    /// being noise.
    fn default() -> Self {
        Self::new(0.7, 5, 3)
    }
}

/// The message body for one out-of-band component — which zone, and what to
/// do about it.
fn diagnosis(metrics: &ComponentMetrics) -> String {
    let (a, i, d) = (
        metrics.abstractness(),
        metrics.instability(),
        metrics.distance_from_main_sequence(),
    );
    let numbers = format!(
        "abstractness {a:.2}, instability {i:.2}, distance from the main sequence {d:.2} (Ca={}, Ce={}, {} types, {} abstractions)",
        metrics.afferent, metrics.efferent, metrics.census.total, metrics.census.abstractions
    );
    if metrics.in_zone_of_pain() {
        format!(
            "component `{}` is in the zone of pain — concrete and heavily depended upon, so every change to it forces a change in its callers: {numbers}. Extract the interfaces/traits its dependents should be coupled to instead",
            metrics.component
        )
    } else {
        format!(
            "component `{}` is in the zone of uselessness — abstract but barely depended upon, so its abstractions are paying no rent: {numbers}. Collapse them into their single implementation, or delete them",
            metrics.component
        )
    }
}

impl CrossFileRule for MainSequenceRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn default_severity(&self) -> Severity {
        Severity::Major
    }

    fn remediation_effort_minutes(&self) -> u32 {
        120
    }

    fn issue_type(&self) -> IssueType {
        IssueType::CodeSmell
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "A component sits far from Martin's main sequence (D = |A + I - 1|): either concrete and heavily depended upon (the zone of pain — nothing can change) or abstract and depended upon by nobody (the zone of uselessness — abstraction with no payoff).".into(),
            tags: vec![
                "architecture".into(),
                "coupling".into(),
                "dependency-inversion".into(),
                "metrics".into(),
                "cross-file".into(),
            ],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, files: &[(SourceFile, AstNode)]) -> Vec<(usize, Finding)> {
        let views: Vec<(&str, &AstNode)> =
            files.iter().map(|(file, ast)| (file.path(), ast)).collect();
        let graph = ImportGraph::build_with_rust_modules(&views);
        let census = component_census(files);
        let metrics = component_metrics(&graph, &census);
        metrics
            .values()
            .filter(|m| m.census.total >= self.min_types)
            .filter(|m| m.afferent + m.efferent >= self.min_couplings)
            .filter(|m| m.distance_from_main_sequence() > self.max_distance)
            .filter_map(|m| {
                // One finding per component, anchored on its first file in
                // path order so the report is stable across runs.
                let index = files
                    .iter()
                    .enumerate()
                    .filter(|(_, (file, _))| component_of(file.path()) == m.component)
                    .min_by_key(|(_, (file, _))| file.path())
                    .map(|(index, _)| index)?;
                Some((index, Finding::new(diagnosis(m), Span::new(1, 1, 1, 1))))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vord_ast::LanguageIdentifier;
    use vord_rules_engine::AstParser;

    fn parsed_ts(files: &[(&str, &str)]) -> Vec<(SourceFile, AstNode)> {
        let parser = vord_parser_typescript::TypeScriptParser::new();
        files
            .iter()
            .map(|(path, code)| {
                let file = SourceFile::new(*path, *code, LanguageIdentifier::typescript()).unwrap();
                let ast = parser.parse(&file).unwrap();
                (file, ast)
            })
            .collect()
    }

    /// Five concrete classes in `kernel`, imported by three other components
    /// and importing nothing: A = 0, I = 0, D = 1.
    fn painful_kernel() -> Vec<(SourceFile, AstNode)> {
        parsed_ts(&[
            (
                "kernel/src/model.ts",
                "export class A {}\nexport class B {}\nexport class C {}\nexport class D {}\nexport class E {}\n",
            ),
            (
                "one/src/a.ts",
                "import { A } from '../../kernel/src/model';\nexport const a = A;\n",
            ),
            (
                "two/src/b.ts",
                "import { B } from '../../kernel/src/model';\nexport const b = B;\n",
            ),
            (
                "three/src/c.ts",
                "import { C } from '../../kernel/src/model';\nexport const c = C;\n",
            ),
        ])
    }

    #[test]
    fn flags_a_concrete_heavily_depended_on_component_as_the_zone_of_pain() {
        let findings = MainSequenceRule::default().check(&painful_kernel());
        let kernel: Vec<_> = findings
            .iter()
            .filter(|(_, f)| f.message.contains("`kernel/src`"))
            .collect();
        assert_eq!(
            kernel.len(),
            1,
            "expected exactly one kernel finding, got {findings:?}"
        );
        assert!(kernel[0].1.message.contains("zone of pain"));
        assert!(kernel[0].1.message.contains("Ca=3"));
    }

    #[test]
    fn abstractions_move_the_same_component_back_onto_the_main_sequence() {
        let files = parsed_ts(&[
            (
                "kernel/src/model.ts",
                "export interface A {}\nexport interface B {}\nexport interface C {}\nexport interface D {}\nexport class E {}\n",
            ),
            (
                "one/src/a.ts",
                "import { A } from '../../kernel/src/model';\nexport const a: A = {} as A;\n",
            ),
            (
                "two/src/b.ts",
                "import { B } from '../../kernel/src/model';\nexport const b: B = {} as B;\n",
            ),
            (
                "three/src/c.ts",
                "import { C } from '../../kernel/src/model';\nexport const c: C = {} as C;\n",
            ),
        ]);
        let findings = MainSequenceRule::default().check(&files);
        assert!(
            !findings
                .iter()
                .any(|(_, f)| f.message.contains("`kernel/src`")),
            "A = 0.8 with I = 0 is D = 0.2, well inside the band: {findings:?}"
        );
    }

    #[test]
    fn a_component_below_the_type_floor_is_never_judged() {
        let files = parsed_ts(&[
            ("kernel/src/model.ts", "export class A {}\n"),
            (
                "one/src/a.ts",
                "import { A } from '../../kernel/src/model';\nexport const a = A;\n",
            ),
            (
                "two/src/b.ts",
                "import { A } from '../../kernel/src/model';\nexport const b = A;\n",
            ),
            (
                "three/src/c.ts",
                "import { A } from '../../kernel/src/model';\nexport const c = A;\n",
            ),
        ]);
        assert!(MainSequenceRule::default().check(&files).is_empty());
    }

    #[test]
    fn a_component_below_the_coupling_floor_is_never_judged() {
        let files = parsed_ts(&[(
            "kernel/src/model.ts",
            "export class A {}\nexport class B {}\nexport class C {}\nexport class D {}\nexport class E {}\n",
        )]);
        assert!(MainSequenceRule::default().check(&files).is_empty());
    }

    #[test]
    fn the_finding_is_anchored_on_the_components_first_file() {
        let files = painful_kernel();
        let findings = MainSequenceRule::default().check(&files);
        let (index, _) = findings
            .iter()
            .find(|(_, f)| f.message.contains("`kernel/src`"))
            .unwrap();
        assert_eq!(files[*index].0.path(), "kernel/src/model.ts");
    }

    #[test]
    fn thresholds_are_configurable() {
        // A stricter band flags what the default tolerates.
        let files = parsed_ts(&[
            (
                "kernel/src/model.ts",
                "export interface A {}\nexport interface B {}\nexport interface C {}\nexport interface D {}\nexport class E {}\n",
            ),
            (
                "one/src/a.ts",
                "import { A } from '../../kernel/src/model';\nexport const a: A = {} as A;\n",
            ),
            (
                "two/src/b.ts",
                "import { B } from '../../kernel/src/model';\nexport const b: B = {} as B;\n",
            ),
            (
                "three/src/c.ts",
                "import { C } from '../../kernel/src/model';\nexport const c: C = {} as C;\n",
            ),
        ]);
        let strict = MainSequenceRule::new(0.1, 5, 3);
        assert!(
            strict
                .check(&files)
                .iter()
                .any(|(_, f)| f.message.contains("`kernel/src`"))
        );
    }
}
