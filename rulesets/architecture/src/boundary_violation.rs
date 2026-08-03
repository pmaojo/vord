//! Rule: an import edge that crosses a declared architecture boundary
//! (`[architecture]` in `vord.toml`, parsed into
//! `vord_import_graph::ArchitectureConfig`). Unlike `DependencyCycleRule`,
//! this rule carries config — it isn't part of `all_cross_rules()`'s
//! zero-config chain, and the composition root constructs and registers it
//! once `vord.toml` is in scope (mirroring how
//! `AnalyzerService::with_duplication_config` is applied after
//! `default_service` builds the zero-config rule set, not baked into the
//! registry itself).

use std::collections::HashMap;

use vord_ast::{AstNode, SourceFile};
use vord_import_graph::{ArchitectureConfig, ImportGraph, TsPathAliases, ViolationKind, component_of};
use vord_rules_engine::{CrossFileRule, Finding, IssueType, RuleId, RuleMetadata, Severity};

pub struct BoundaryViolationRule {
    id: RuleId,
    config: ArchitectureConfig,
    rust_crates: HashMap<String, String>,
    ts_aliases: TsPathAliases,
}

impl BoundaryViolationRule {
    /// `rust_crates` is `vord_infra_fs::discover_rust_crates`'s output
    /// (crate identifier -> directory) — empty for a project with no Rust
    /// (or none discovered), in which case Rust files simply contribute no
    /// edges, same as any other unresolved specifier.
    pub fn new(config: ArchitectureConfig, rust_crates: HashMap<String, String>) -> Self {
        Self {
            id: RuleId::new("architecture:boundary-violation").expect("valid rule id"),
            config,
            rust_crates,
            ts_aliases: TsPathAliases::default(),
        }
    }

    /// See `DependencyCycleRule::with_ts_aliases` — same rationale, same
    /// no-op-when-empty default.
    pub fn with_ts_aliases(mut self, ts_aliases: TsPathAliases) -> Self {
        self.ts_aliases = ts_aliases;
        self
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
            description: "An import crosses a dependency edge this project has declared out of bounds in `[architecture]` (vord.toml) — either explicitly forbidden, or, once `allowed_dependencies` is declared, simply never allow-listed.".into(),
            tags: vec!["architecture".into(), "coupling".into(), "cross-file".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, files: &[(SourceFile, AstNode)]) -> Vec<(usize, Finding)> {
        if self.config.is_empty() {
            return Vec::new();
        }
        let views: Vec<(&str, &AstNode)> =
            files.iter().map(|(file, ast)| (file.path(), ast)).collect();
        let graph = ImportGraph::build_with_options(&views, &self.rust_crates, &self.ts_aliases);
        let mut findings = Vec::new();
        for violation in self.config.violations(&graph) {
            let reason = match violation.kind {
                ViolationKind::Forbidden => "forbidden by `[architecture] forbidden_dependencies`",
                ViolationKind::Undeclared => {
                    "not declared in `[architecture] allowed_dependencies`"
                }
            };
            // Attach the finding to every file that is itself the source of
            // an edge landing in this violation's component pair, so a
            // developer sees the actual import line(s) responsible, not
            // just the component-level verdict.
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
    use vord_ast::LanguageIdentifier;
    use vord_import_graph::DependencyEdge;
    use vord_rules_engine::AstParser;

    fn parsed(files: &[(&str, &str)]) -> Vec<(SourceFile, AstNode)> {
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

    fn parsed_rust(files: &[(&str, &str)]) -> Vec<(SourceFile, AstNode)> {
        let parser = vord_parser_rust::RustParser::new();
        files
            .iter()
            .map(|(path, code)| {
                let file = SourceFile::new(*path, *code, LanguageIdentifier::rust()).unwrap();
                let ast = parser.parse(&file).unwrap();
                (file, ast)
            })
            .collect()
    }

    #[test]
    fn silent_with_no_architecture_config() {
        let files = parsed(&[
            ("core/a.ts", "import { b } from '../infra/b';\n"),
            ("infra/b.ts", "export const b = 1;\n"),
        ]);
        let rule = BoundaryViolationRule::new(ArchitectureConfig::default(), HashMap::new());
        assert!(rule.check(&files).is_empty());
    }

    #[test]
    fn flags_a_forbidden_tier_import_at_the_importing_file() {
        let files = parsed(&[
            ("core/a.ts", "import { b } from '../infra/b';\n"),
            ("infra/b.ts", "export const b = 1;\n"),
        ]);
        let config = ArchitectureConfig {
            forbidden_dependencies: vec![DependencyEdge::new("core", "infra")],
            ..Default::default()
        };
        let findings = BoundaryViolationRule::new(config, HashMap::new()).check(&files);
        assert_eq!(findings.len(), 1);
        let (index, finding) = &findings[0];
        assert_eq!(*index, 0);
        assert!(finding.message.contains("`core` depends on `infra`"));
    }

    #[test]
    fn a_path_aliased_forbidden_import_is_invisible_without_ts_aliases_but_flagged_with_them() {
        let files = parsed(&[
            ("core/a.ts", "import { b } from '@/infra/b';\n"),
            ("infra/b.ts", "export const b = 1;\n"),
        ]);
        let config = ArchitectureConfig {
            forbidden_dependencies: vec![DependencyEdge::new("core", "infra")],
            ..Default::default()
        };

        assert!(
            BoundaryViolationRule::new(config.clone(), HashMap::new())
                .check(&files)
                .is_empty()
        );

        let aliases = TsPathAliases::new(vec![("@/*".to_string(), vec!["*".to_string()])]);
        let findings = BoundaryViolationRule::new(config, HashMap::new())
            .with_ts_aliases(aliases)
            .check(&files);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].1.message.contains("`core` depends on `infra`"));
    }

    #[test]
    fn silent_when_the_import_stays_within_declared_boundaries() {
        let files = parsed(&[
            ("bin/a.ts", "import { b } from '../core/b';\n"),
            ("core/b.ts", "export const b = 1;\n"),
        ]);
        let config = ArchitectureConfig {
            allowed_dependencies: vec![DependencyEdge::new("bin", "core")],
            ..Default::default()
        };
        assert!(
            BoundaryViolationRule::new(config, HashMap::new())
                .check(&files)
                .is_empty()
        );
    }

    #[test]
    fn flags_a_forbidden_rust_crate_dependency_via_the_crate_index() {
        let files = parsed_rust(&[
            (
                "core/rules-engine/src/lib.rs",
                "use vord_infra_fs::Thing;\n",
            ),
            ("infra/fs/src/lib.rs", "pub struct Thing;\n"),
        ]);
        let config = ArchitectureConfig {
            forbidden_dependencies: vec![DependencyEdge::new("core", "infra")],
            ..Default::default()
        };
        let rust_crates: HashMap<String, String> =
            HashMap::from([("vord_infra_fs".to_string(), "infra/fs".to_string())]);
        let findings = BoundaryViolationRule::new(config, rust_crates).check(&files);
        assert_eq!(findings.len(), 1);
        assert!(
            findings[0]
                .1
                .message
                .contains("`core/rules-engine` depends on `infra/fs`")
        );
    }

    #[test]
    fn silent_on_rust_use_with_no_matching_crate_index_entry() {
        let files = parsed_rust(&[(
            "core/rules-engine/src/lib.rs",
            "use vord_infra_fs::Thing;\n",
        )]);
        let config = ArchitectureConfig {
            forbidden_dependencies: vec![DependencyEdge::new("core", "infra")],
            ..Default::default()
        };
        assert!(
            BoundaryViolationRule::new(config, HashMap::new())
                .check(&files)
                .is_empty()
        );
    }

    #[test]
    fn flags_a_forbidden_rust_dependency_with_no_use_statement_at_all() {
        // The gap found while verifying the test-code fix: Rust needs no
        // `use` at all to reach another crate's items, unlike TS/Python.
        let files = parsed_rust(&[(
            "core/rules-engine/src/lib.rs",
            "pub fn open() -> vord_infra_fs::Thing {\n    vord_infra_fs::Thing::new()\n}\n",
        )]);
        let config = ArchitectureConfig {
            forbidden_dependencies: vec![DependencyEdge::new("core", "infra")],
            ..Default::default()
        };
        let rust_crates: HashMap<String, String> =
            HashMap::from([("vord_infra_fs".to_string(), "infra/fs".to_string())]);
        let findings = BoundaryViolationRule::new(config, rust_crates).check(&files);
        assert_eq!(findings.len(), 1);
        assert!(
            findings[0]
                .1
                .message
                .contains("`core/rules-engine` depends on `infra/fs`")
        );
    }
}
