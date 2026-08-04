//! Rule: an import cycle — module A imports B imports C imports A (directly
//! or transitively) — across the whole analyzed file set. A whole-program
//! rule by nature (`CrossFileRule`, same plugin model as
//! `owasp:cross-file-injection`), built on `vord_import_graph::ImportGraph`.

use vord_ast::{AstNode, SourceFile, Span};
use vord_import_graph::{ImportGraph, TsPathAliases};
use vord_rules_engine::{CrossFileRule, Finding, IssueType, RuleId, RuleMetadata, Severity};

pub struct DependencyCycleRule {
    id: RuleId,
    ts_aliases: TsPathAliases,
}

impl DependencyCycleRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("architecture:dependency-cycle").expect("valid rule id"),
            ts_aliases: TsPathAliases::default(),
        }
    }

    /// Resolves TS/JS `@/`-style path-aliased imports against `ts_aliases`
    /// (`vord_infra_fs::discover_ts_path_aliases`'s output) before building
    /// the import graph this rule walks — without it, a project whose
    /// imports go through a `tsconfig.json` alias looks like it has no
    /// edges at all, silently hiding real cycles. An empty `TsPathAliases`
    /// (the default) changes nothing.
    pub fn with_ts_aliases(mut self, ts_aliases: TsPathAliases) -> Self {
        self.ts_aliases = ts_aliases;
        self
    }
}

impl Default for DependencyCycleRule {
    fn default() -> Self {
        Self::new()
    }
}

impl CrossFileRule for DependencyCycleRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn default_severity(&self) -> Severity {
        Severity::Major
    }

    fn remediation_effort_minutes(&self) -> u32 {
        60
    }

    fn issue_type(&self) -> IssueType {
        IssueType::CodeSmell
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "Modules import each other in a cycle (A -> B -> ... -> A), coupling them so neither can be understood, tested, or changed independently.".into(),
            tags: vec!["architecture".into(), "coupling".into(), "cross-file".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, files: &[(SourceFile, AstNode)]) -> Vec<(usize, Finding)> {
        let views: Vec<(&str, &AstNode)> =
            files.iter().map(|(file, ast)| (file.path(), ast)).collect();
        let graph = ImportGraph::build_with_rust_modules_and_ts_aliases(&views, &self.ts_aliases);
        let mut findings = Vec::new();
        for cycle in graph.cycles() {
            let chain = cycle.join(" -> ");
            for pair in cycle.windows(2) {
                let (from, to) = (&pair[0], &pair[1]);
                let Some(index) = files.iter().position(|(file, _)| file.path() == from) else {
                    continue;
                };
                let span = graph.edge_span(from, to).unwrap_or(Span::new(1, 1, 1, 1));
                findings.push((
                    index,
                    Finding::new(
                        format!(
                            "import cycle: {chain} — `{from}` depends on `{to}`, closing the loop"
                        ),
                        span,
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

    #[test]
    fn flags_a_two_file_ts_import_cycle() {
        let a = SourceFile::new(
            "a.ts",
            "import { b } from './b';\n",
            LanguageIdentifier::typescript(),
        )
        .unwrap();
        let b = SourceFile::new(
            "b.ts",
            "import { a } from './a';\n",
            LanguageIdentifier::typescript(),
        )
        .unwrap();
        let parser = vord_parser_typescript::TypeScriptParser::new();
        let files = vec![
            (a.clone(), parser.parse(&a).unwrap()),
            (b.clone(), parser.parse(&b).unwrap()),
        ];

        let findings = DependencyCycleRule::new().check(&files);
        assert_eq!(findings.len(), 2); // one per file in the cycle
        assert!(
            findings
                .iter()
                .all(|(_, f)| f.message.contains("import cycle"))
        );
    }

    #[test]
    fn a_path_aliased_cycle_is_invisible_without_ts_aliases_but_flagged_with_them() {
        let a = SourceFile::new(
            "src/a.ts",
            "import { b } from '@/b';\n",
            LanguageIdentifier::typescript(),
        )
        .unwrap();
        let b = SourceFile::new(
            "src/b.ts",
            "import { a } from '@/a';\n",
            LanguageIdentifier::typescript(),
        )
        .unwrap();
        let parser = vord_parser_typescript::TypeScriptParser::new();
        let files = vec![
            (a.clone(), parser.parse(&a).unwrap()),
            (b.clone(), parser.parse(&b).unwrap()),
        ];

        assert!(DependencyCycleRule::new().check(&files).is_empty());

        let aliases = TsPathAliases::new(vec![("@/*".to_string(), vec!["src/*".to_string()])]);
        let findings = DependencyCycleRule::new()
            .with_ts_aliases(aliases)
            .check(&files);
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn silent_on_an_acyclic_import_chain() {
        let a = SourceFile::new(
            "a.ts",
            "import { b } from './b';\n",
            LanguageIdentifier::typescript(),
        )
        .unwrap();
        let b = SourceFile::new(
            "b.ts",
            "export const b = 1;\n",
            LanguageIdentifier::typescript(),
        )
        .unwrap();
        let parser = vord_parser_typescript::TypeScriptParser::new();
        let files = vec![
            (a.clone(), parser.parse(&a).unwrap()),
            (b.clone(), parser.parse(&b).unwrap()),
        ];

        assert!(DependencyCycleRule::new().check(&files).is_empty());
    }

    #[test]
    fn flags_a_python_import_cycle() {
        let a = SourceFile::new(
            "pkg/a.py",
            "from .b import thing\n",
            LanguageIdentifier::python(),
        )
        .unwrap();
        let b = SourceFile::new(
            "pkg/b.py",
            "from .a import other\n",
            LanguageIdentifier::python(),
        )
        .unwrap();
        let parser = vord_parser_python::PythonParser::new();
        let files = vec![
            (a.clone(), parser.parse(&a).unwrap()),
            (b.clone(), parser.parse(&b).unwrap()),
        ];

        let findings = DependencyCycleRule::new().check(&files);
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn silent_when_only_external_packages_are_imported() {
        let a = SourceFile::new(
            "a.ts",
            "import React from 'react';\n",
            LanguageIdentifier::typescript(),
        )
        .unwrap();
        let parser = vord_parser_typescript::TypeScriptParser::new();
        let files = vec![(a.clone(), parser.parse(&a).unwrap())];

        assert!(DependencyCycleRule::new().check(&files).is_empty());
    }
}
