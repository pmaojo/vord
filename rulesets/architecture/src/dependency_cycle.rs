//! Rule: an import cycle — module A imports B imports C imports A (directly
//! or transitively) — across the whole analyzed file set. A whole-program
//! rule by nature (`CrossFileRule`, same plugin model as
//! `owasp:cross-file-injection`), built on `yunq_import_graph::ImportGraph`.

use yunq_ast::{AstNode, SourceFile, Span};
use yunq_import_graph::ImportGraph;
use yunq_rules_engine::{CrossFileRule, Finding, IssueType, RuleId, RuleMetadata, Severity};

pub struct DependencyCycleRule {
    id: RuleId,
}

impl DependencyCycleRule {
    pub fn new() -> Self {
        Self { id: RuleId::new("architecture:dependency-cycle").expect("valid rule id") }
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
        let views: Vec<(&str, &AstNode)> = files.iter().map(|(file, ast)| (file.path(), ast)).collect();
        let graph = ImportGraph::build(&views);
        let mut findings = Vec::new();
        for cycle in graph.cycles() {
            let chain = cycle.join(" -> ");
            for pair in cycle.windows(2) {
                let (from, to) = (&pair[0], &pair[1]);
                let Some(index) = files.iter().position(|(file, _)| file.path() == from) else { continue };
                let span = graph.edge_span(from, to).unwrap_or(Span::new(1, 1, 1, 1));
                findings.push((
                    index,
                    Finding::new(format!("import cycle: {chain} — `{from}` depends on `{to}`, closing the loop"), span),
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
    use yunq_rules_engine::AstParser;

    #[test]
    fn flags_a_two_file_ts_import_cycle() {
        let a = SourceFile::new("a.ts", "import { b } from './b';\n", LanguageIdentifier::typescript()).unwrap();
        let b = SourceFile::new("b.ts", "import { a } from './a';\n", LanguageIdentifier::typescript()).unwrap();
        let parser = yunq_parser_typescript::TypeScriptParser::new();
        let files = vec![(a.clone(), parser.parse(&a).unwrap()), (b.clone(), parser.parse(&b).unwrap())];

        let findings = DependencyCycleRule::new().check(&files);
        assert_eq!(findings.len(), 2); // one per file in the cycle
        assert!(findings.iter().all(|(_, f)| f.message.contains("import cycle")));
    }

    #[test]
    fn silent_on_an_acyclic_import_chain() {
        let a = SourceFile::new("a.ts", "import { b } from './b';\n", LanguageIdentifier::typescript()).unwrap();
        let b = SourceFile::new("b.ts", "export const b = 1;\n", LanguageIdentifier::typescript()).unwrap();
        let parser = yunq_parser_typescript::TypeScriptParser::new();
        let files = vec![(a.clone(), parser.parse(&a).unwrap()), (b.clone(), parser.parse(&b).unwrap())];

        assert!(DependencyCycleRule::new().check(&files).is_empty());
    }

    #[test]
    fn flags_a_python_import_cycle() {
        let a = SourceFile::new("pkg/a.py", "from .b import thing\n", LanguageIdentifier::python()).unwrap();
        let b = SourceFile::new("pkg/b.py", "from .a import other\n", LanguageIdentifier::python()).unwrap();
        let parser = yunq_parser_python::PythonParser::new();
        let files = vec![(a.clone(), parser.parse(&a).unwrap()), (b.clone(), parser.parse(&b).unwrap())];

        let findings = DependencyCycleRule::new().check(&files);
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn silent_when_only_external_packages_are_imported() {
        let a = SourceFile::new("a.ts", "import React from 'react';\n", LanguageIdentifier::typescript()).unwrap();
        let parser = yunq_parser_typescript::TypeScriptParser::new();
        let files = vec![(a.clone(), parser.parse(&a).unwrap())];

        assert!(DependencyCycleRule::new().check(&files).is_empty());
    }
}
