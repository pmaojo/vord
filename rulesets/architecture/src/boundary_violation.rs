//! Rule: an import edge that crosses a declared architecture boundary
//! (`[architecture]` in `yunq.toml`, parsed into
//! `yunq_import_graph::ArchitectureConfig`). Unlike `DependencyCycleRule`,
//! this rule carries config — it isn't part of `all_cross_rules()`'s
//! zero-config chain, and the composition root constructs and registers it
//! once `yunq.toml` is in scope (mirroring how
//! `AnalyzerService::with_duplication_config` is applied after
//! `default_service` builds the zero-config rule set, not baked into the
//! registry itself).

use yunq_ast::{AstNode, SourceFile};
use yunq_import_graph::{component_of, ArchitectureConfig, ImportGraph, ViolationKind};
use yunq_rules_engine::{CrossFileRule, Finding, IssueType, RuleId, RuleMetadata, Severity};

pub struct BoundaryViolationRule {
    id: RuleId,
    config: ArchitectureConfig,
}

impl BoundaryViolationRule {
    pub fn new(config: ArchitectureConfig) -> Self {
        Self { id: RuleId::new("architecture:boundary-violation").expect("valid rule id"), config }
    }
}

impl CrossFileRule for BoundaryViolationRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn default_severity(&self) -> Severity {
        Severity::Major
    }

    fn remediation_effort_minutes(&self) -> u32 {
        30
    }

    fn issue_type(&self) -> IssueType {
        IssueType::CodeSmell
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "An import crosses a dependency edge this project has declared out of bounds in `[architecture]` (yunq.toml) — either explicitly forbidden, or, once `allowed_dependencies` is declared, simply never allow-listed.".into(),
            tags: vec!["architecture".into(), "coupling".into(), "cross-file".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, files: &[(SourceFile, AstNode)]) -> Vec<(usize, Finding)> {
        if self.config.is_empty() {
            return Vec::new();
        }
        let views: Vec<(&str, &AstNode)> = files.iter().map(|(file, ast)| (file.path(), ast)).collect();
        let graph = ImportGraph::build(&views);
        let mut findings = Vec::new();
        for violation in self.config.violations(&graph) {
            let reason = match violation.kind {
                ViolationKind::Forbidden => "forbidden by `[architecture] forbidden_dependencies`",
                ViolationKind::Undeclared => "not declared in `[architecture] allowed_dependencies`",
            };
            // Attach the finding to every file that is itself the source of
            // an edge landing in this violation's component pair, so a
            // developer sees the actual import line(s) responsible, not
            // just the component-level verdict.
            for edge in graph.edges() {
                if component_of(&edge.from) != violation.from || component_of(&edge.to) != violation.to {
                    continue;
                }
                let Some(index) = files.iter().position(|(file, _)| file.path() == edge.from) else { continue };
                findings.push((
                    index,
                    Finding::new(
                        format!(
                            "architecture boundary violation: `{}` depends on `{}` ({reason})",
                            violation.from, violation.to
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
    use yunq_ast::LanguageIdentifier;
    use yunq_import_graph::DependencyEdge;
    use yunq_rules_engine::AstParser;

    fn parsed(files: &[(&str, &str)]) -> Vec<(SourceFile, AstNode)> {
        let parser = yunq_parser_typescript::TypeScriptParser::new();
        files
            .iter()
            .map(|(path, code)| {
                let file = SourceFile::new(*path, *code, LanguageIdentifier::typescript()).unwrap();
                let ast = parser.parse(&file).unwrap();
                (file, ast)
            })
            .collect()
    }

    #[test]
    fn silent_with_no_architecture_config() {
        let files = parsed(&[("core/a.ts", "import { b } from '../infra/b';\n"), ("infra/b.ts", "export const b = 1;\n")]);
        let rule = BoundaryViolationRule::new(ArchitectureConfig::default());
        assert!(rule.check(&files).is_empty());
    }

    #[test]
    fn flags_a_forbidden_tier_import_at_the_importing_file() {
        let files = parsed(&[("core/a.ts", "import { b } from '../infra/b';\n"), ("infra/b.ts", "export const b = 1;\n")]);
        let config = ArchitectureConfig {
            forbidden_dependencies: vec![DependencyEdge::new("core", "infra")],
            ..Default::default()
        };
        let findings = BoundaryViolationRule::new(config).check(&files);
        assert_eq!(findings.len(), 1);
        let (index, finding) = &findings[0];
        assert_eq!(*index, 0);
        assert!(finding.message.contains("`core` depends on `infra`"));
    }

    #[test]
    fn silent_when_the_import_stays_within_declared_boundaries() {
        let files = parsed(&[("bin/a.ts", "import { b } from '../core/b';\n"), ("core/b.ts", "export const b = 1;\n")]);
        let config = ArchitectureConfig {
            allowed_dependencies: vec![DependencyEdge::new("bin", "core")],
            ..Default::default()
        };
        assert!(BoundaryViolationRule::new(config).check(&files).is_empty());
    }
}
