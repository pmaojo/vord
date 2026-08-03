//! Rule: an import that points *outward* — domain code depending on the
//! application layer, application code depending on an adapter,
//! infrastructure leaking into either. The single load-bearing constraint of
//! Ports & Adapters / Clean Architecture / Onion, and the one every one of
//! those styles states the same way: **dependencies point inward**.
//!
//! Zero-config by design, and that is the point of it next to
//! `architecture:boundary-violation`: that rule enforces the components *you*
//! declared in `vord.toml`, so it can say nothing at all until someone writes
//! the table. This one reads the layering vocabulary the industry already
//! shares off the path topology (`vord_import_graph::layer_of`) and fails a
//! build on the first inversion — no config, first scan.
//!
//! Whole-program (`CrossFileRule`), built on
//! `ImportGraph::build_with_rust_modules` so a single-crate Rust layout
//! (`src/domain`, `src/infrastructure`) is covered without a workspace crate
//! index, alongside TypeScript and Python relative/absolute imports.

use vord_ast::{AstNode, SourceFile};
use vord_import_graph::{
    ImportGraph, LayerTaxonomy, TsPathAliases, inward_dependency_violations_with_taxonomy,
};
use vord_rules_engine::{CrossFileRule, Finding, IssueType, RuleId, RuleMetadata, Severity};

pub struct HexagonalLayerRule {
    id: RuleId,
    taxonomy: LayerTaxonomy,
    ts_aliases: TsPathAliases,
}

impl HexagonalLayerRule {
    pub fn new() -> Self {
        Self::with_taxonomy(LayerTaxonomy::default())
    }

    /// Same rule, classifying paths through a project's declared
    /// `[[architecture.layer]]` taxonomy first — falls back to the
    /// zero-config heuristic for anything it doesn't match, so this is a
    /// strict extension of [`Self::new`], never a different rule.
    pub fn with_taxonomy(taxonomy: LayerTaxonomy) -> Self {
        Self {
            id: RuleId::new("architecture:hexagonal-layer-violation").expect("valid rule id"),
            taxonomy,
            ts_aliases: TsPathAliases::default(),
        }
    }

    /// See `DependencyCycleRule::with_ts_aliases` — same rationale, same
    /// no-op-when-empty default. Chains onto either constructor above.
    pub fn with_ts_aliases(mut self, ts_aliases: TsPathAliases) -> Self {
        self.ts_aliases = ts_aliases;
        self
    }
}

impl Default for HexagonalLayerRule {
    fn default() -> Self {
        Self::new()
    }
}

impl CrossFileRule for HexagonalLayerRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn default_severity(&self) -> Severity {
        Severity::Major
    }

    fn remediation_effort_minutes(&self) -> u32 {
        45
    }

    fn issue_type(&self) -> IssueType {
        IssueType::CodeSmell
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "An import points outward through the hexagon (domain -> application, application -> adapter/infrastructure), inverting the dependency direction Ports & Adapters is built on. Invert it: let the inner ring declare a port and have the outer ring implement it.".into(),
            tags: vec![
                "architecture".into(),
                "hexagonal".into(),
                "dependency-inversion".into(),
                "cross-file".into(),
            ],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, files: &[(SourceFile, AstNode)]) -> Vec<(usize, Finding)> {
        let views: Vec<(&str, &AstNode)> =
            files.iter().map(|(file, ast)| (file.path(), ast)).collect();
        let graph = ImportGraph::build_with_rust_modules_and_ts_aliases(&views, &self.ts_aliases);
        inward_dependency_violations_with_taxonomy(&graph, &self.taxonomy)
            .into_iter()
            .filter_map(|violation| {
                let index = files.iter().position(|(file, _)| file.path() == violation.from)?;
                Some((
                    index,
                    Finding::new(
                        format!(
                            "hexagonal layer violation: {} code `{}` imports {} code `{}` — dependencies must point inward; declare a port in the {} layer and implement it in the {} layer instead",
                            violation.from_layer.label(),
                            violation.from,
                            violation.to_layer.label(),
                            violation.to,
                            violation.from_layer.label(),
                            violation.to_layer.label(),
                        ),
                        violation.span,
                    ),
                ))
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

    fn parsed_python(files: &[(&str, &str)]) -> Vec<(SourceFile, AstNode)> {
        let parser = vord_parser_python::PythonParser::new();
        files
            .iter()
            .map(|(path, code)| {
                let file = SourceFile::new(*path, *code, LanguageIdentifier::python()).unwrap();
                let ast = parser.parse(&file).unwrap();
                (file, ast)
            })
            .collect()
    }

    #[test]
    fn flags_a_typescript_entity_importing_a_repository_implementation() {
        let files = parsed_ts(&[
            (
                "src/domain/order.ts",
                "import { pool } from '../infrastructure/postgres';\nexport class Order {}\n",
            ),
            ("src/infrastructure/postgres.ts", "export const pool = 1;\n"),
        ]);
        let findings = HexagonalLayerRule::new().check(&files);
        assert_eq!(findings.len(), 1);
        let (index, finding) = &findings[0];
        assert_eq!(files[*index].0.path(), "src/domain/order.ts");
        assert!(
            finding.message.contains("domain code"),
            "{}",
            finding.message
        );
        assert!(
            finding.message.contains("infrastructure code"),
            "{}",
            finding.message
        );
        assert!(
            finding.message.contains("declare a port"),
            "{}",
            finding.message
        );
    }

    #[test]
    fn silent_when_the_adapter_depends_on_the_domain() {
        let files = parsed_ts(&[
            (
                "src/adapters/order_controller.ts",
                "import { Order } from '../domain/order';\nexport const c = Order;\n",
            ),
            ("src/domain/order.ts", "export class Order {}\n"),
        ]);
        assert!(HexagonalLayerRule::new().check(&files).is_empty());
    }

    #[test]
    fn flags_an_application_service_reaching_into_infrastructure() {
        let files = parsed_ts(&[
            (
                "src/application/place_order.ts",
                "import { pool } from '../infrastructure/postgres';\nexport const place = pool;\n",
            ),
            ("src/infrastructure/postgres.ts", "export const pool = 1;\n"),
        ]);
        let findings = HexagonalLayerRule::new().check(&files);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].1.message.contains("application code"));
    }

    #[test]
    fn flags_a_rust_domain_module_using_an_intra_crate_infrastructure_module() {
        let files = parsed_rust(&[
            (
                "svc/src/domain/order.rs",
                "use crate::infrastructure::db::Pool;\n\npub struct Order {\n    pool: Pool,\n}\n",
            ),
            ("svc/src/infrastructure/db.rs", "pub struct Pool;\n"),
        ]);
        let findings = HexagonalLayerRule::new().check(&files);
        assert_eq!(findings.len(), 1);
        assert!(
            findings[0]
                .1
                .message
                .contains("svc/src/infrastructure/db.rs"),
            "{}",
            findings[0].1.message
        );
    }

    #[test]
    fn silent_on_a_rust_adapter_using_the_domain() {
        let files = parsed_rust(&[
            (
                "svc/src/adapters/http.rs",
                "use crate::domain::order::Order;\n\npub fn handle(_o: Order) {}\n",
            ),
            ("svc/src/domain/order.rs", "pub struct Order;\n"),
        ]);
        assert!(HexagonalLayerRule::new().check(&files).is_empty());
    }

    #[test]
    fn flags_a_python_domain_package_importing_a_gateway() {
        let files = parsed_python(&[
            (
                "src/domain/order.py",
                "from src.gateway.stripe import charge\n",
            ),
            ("src/gateway/stripe.py", "def charge():\n    pass\n"),
        ]);
        let findings = HexagonalLayerRule::new().check(&files);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].1.message.contains("infrastructure code"));
    }

    #[test]
    fn silent_on_unclassified_paths() {
        let files = parsed_ts(&[
            (
                "src/lib/a.ts",
                "import { b } from './b';\nexport const a = b;\n",
            ),
            ("src/lib/b.ts", "export const b = 1;\n"),
        ]);
        assert!(HexagonalLayerRule::new().check(&files).is_empty());
    }

    #[test]
    fn reports_one_finding_per_offending_import_line() {
        let files = parsed_ts(&[
            (
                "src/domain/order.ts",
                "import { pool } from '../infrastructure/postgres';\nimport { bus } from '../infrastructure/kafka';\nexport const x = [pool, bus];\n",
            ),
            ("src/infrastructure/postgres.ts", "export const pool = 1;\n"),
            ("src/infrastructure/kafka.ts", "export const bus = 1;\n"),
        ]);
        let findings = HexagonalLayerRule::new().check(&files);
        assert_eq!(findings.len(), 2);
        let lines: Vec<u32> = findings.iter().map(|(_, f)| f.span.start_line).collect();
        assert_eq!(lines, vec![1, 2]);
    }
}
