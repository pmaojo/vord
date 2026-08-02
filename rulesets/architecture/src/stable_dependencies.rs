//! Rule: the **Stable Dependencies Principle** — "depend in the direction of
//! stability". A component that many others depend on (low instability
//! `I = Ce / (Ca + Ce)`) must not reach out to a volatile one: it inherits
//! that volatility, and through it so does everything that depends on it. One
//! churn-heavy adapter can then force a change in a component nobody can
//! afford to change.
//!
//! Computed over the component graph in `vord_import_graph::metrics`, which
//! is the same Ca/Ce arithmetic CodeQL exposes per type
//! (`TAfferentCoupling.ql`/`TEfferentCoupling.ql`) — the difference is that
//! this is a *direction* check between two components rather than a size
//! metric on one, and it fails a build rather than drawing a treemap.
//!
//! Guards against reading noise as design: the depended-on component must
//! already be a real dependency hub (`min_afferent` dependents), and the
//! instability gap must exceed `margin`, because `I` is a ratio over small
//! integers where one import can move it 0.1.

use vord_ast::{AstNode, SourceFile};
use vord_import_graph::{ImportGraph, component_metrics, component_of, stability_violations};
use vord_rules_engine::{CrossFileRule, Finding, IssueType, RuleId, RuleMetadata, Severity};

use crate::census::component_census;

pub struct StableDependencyRule {
    id: RuleId,
    margin: f64,
    min_afferent: usize,
}

impl StableDependencyRule {
    pub fn new(margin: f64, min_afferent: usize) -> Self {
        Self {
            id: RuleId::new("architecture:stable-dependency-violation").expect("valid rule id"),
            margin,
            min_afferent,
        }
    }
}

impl Default for StableDependencyRule {
    /// A 0.25 instability gap is more than one import can explain at any
    /// realistic coupling count, and requiring two dependents means the
    /// "stable" side is actually load-bearing rather than merely quiet.
    fn default() -> Self {
        Self::new(0.25, 2)
    }
}

impl CrossFileRule for StableDependencyRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn default_severity(&self) -> Severity {
        Severity::Major
    }

    fn remediation_effort_minutes(&self) -> u32 {
        90
    }

    fn issue_type(&self) -> IssueType {
        IssueType::CodeSmell
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "A stable component (many dependents, low instability) depends on a less stable one, inheriting its churn — a violation of the Stable Dependencies Principle. Invert the edge behind an abstraction owned by the stable side.".into(),
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
        let metrics = component_metrics(&graph, &component_census(files));
        let mut findings = Vec::new();
        for violation in stability_violations(&graph, &metrics, self.margin) {
            let Some(from_metrics) = metrics.get(&violation.from) else {
                continue;
            };
            if from_metrics.afferent < self.min_afferent {
                continue;
            }
            // Anchored on every import line that realizes this component
            // edge, so the finding points at code that can be changed —
            // the same choice `architecture:boundary-violation` makes.
            for edge in graph.edges() {
                if vord_rules_engine::is_test_only_path(&edge.from) {
                    continue;
                }
                if component_of(&edge.from) != violation.from
                    || component_of(&edge.to) != violation.to
                {
                    continue;
                }
                let Some(index) = files.iter().position(|(file, _)| file.path() == edge.from)
                else {
                    continue;
                };
                findings.push((
                    index,
                    Finding::new(
                        format!(
                            "stable dependencies violation: `{}` (instability {:.2}, {} dependents) depends on the less stable `{}` (instability {:.2}) — depend in the direction of stability, or invert this edge behind an abstraction `{}` owns",
                            violation.from,
                            violation.from_instability,
                            from_metrics.afferent,
                            violation.to,
                            violation.to_instability,
                            violation.from,
                        ),
                        edge.span,
                    ),
                ));
            }
        }
        findings
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

    /// `kernel` has two dependents (`one`, `two`) and reaches out to
    /// `volatile`, which itself depends on both of them: I(kernel) = 1/3,
    /// I(volatile) = 2/3.
    fn inverted_stability() -> Vec<(SourceFile, AstNode)> {
        parsed_ts(&[
            (
                "kernel/src/model.ts",
                "import { v } from '../../volatile/src/v';\nexport const k = v;\n",
            ),
            (
                "one/src/a.ts",
                "import { k } from '../../kernel/src/model';\nexport const a = k;\n",
            ),
            (
                "two/src/b.ts",
                "import { k } from '../../kernel/src/model';\nexport const b = k;\n",
            ),
            (
                "volatile/src/v.ts",
                "import { a } from '../../one/src/a';\nimport { b } from '../../two/src/b';\nexport const v = [a, b];\n",
            ),
        ])
    }

    #[test]
    fn flags_a_hub_component_depending_on_a_volatile_one() {
        let files = inverted_stability();
        let findings = StableDependencyRule::default().check(&files);
        assert_eq!(findings.len(), 1, "{findings:?}");
        let (index, finding) = &findings[0];
        assert_eq!(files[*index].0.path(), "kernel/src/model.ts");
        assert!(
            finding.message.contains("`kernel/src`"),
            "{}",
            finding.message
        );
        assert!(
            finding.message.contains("`volatile/src`"),
            "{}",
            finding.message
        );
        assert!(
            finding.message.contains("2 dependents"),
            "{}",
            finding.message
        );
    }

    #[test]
    fn the_finding_points_at_the_offending_import_line() {
        let files = inverted_stability();
        let findings = StableDependencyRule::default().check(&files);
        assert_eq!(findings[0].1.span.start_line, 1);
    }

    #[test]
    fn silent_when_dependencies_point_toward_stability() {
        let files = parsed_ts(&[
            ("kernel/src/model.ts", "export class K {}\n"),
            (
                "one/src/a.ts",
                "import { K } from '../../kernel/src/model';\nexport const a = K;\n",
            ),
            (
                "two/src/b.ts",
                "import { K } from '../../kernel/src/model';\nexport const b = K;\n",
            ),
        ]);
        assert!(StableDependencyRule::default().check(&files).is_empty());
    }

    #[test]
    fn silent_when_the_stable_side_has_too_few_dependents_to_judge() {
        let files = parsed_ts(&[
            (
                "kernel/src/model.ts",
                "import { v } from '../../volatile/src/v';\nexport const k = v;\n",
            ),
            (
                "one/src/a.ts",
                "import { k } from '../../kernel/src/model';\nexport const a = k;\n",
            ),
            (
                "volatile/src/v.ts",
                "import { a } from '../../one/src/a';\nexport const v = a;\n",
            ),
        ]);
        assert!(StableDependencyRule::new(0.25, 2).check(&files).is_empty());
    }

    #[test]
    fn margin_is_configurable() {
        let files = inverted_stability();
        // A gap of 1/3 clears 0.25 but not 0.5.
        assert!(StableDependencyRule::new(0.5, 2).check(&files).is_empty());
    }
}
