use yunq_ast::{AstNode, SourceFile};
use yunq_rules_engine::{CrossFileRule, Finding, RuleId, RuleMetadata, Severity};
use yunq_taint::{CrossFileTaint, TaintConfig};

/// Inter-procedural, cross-file injection detection: user input passed into
/// a function — possibly defined in another file — whose parameter reaches a
/// code- or command-execution sink.
pub struct CrossFileInjectionRule {
    id: RuleId,
    analysis: CrossFileTaint,
}

impl CrossFileInjectionRule {
    pub fn new() -> Self {
        let config = TaintConfig::new()
            .with_source_marker("process.argv")
            .with_source_marker("process.env")
            .with_source_marker("req.query")
            .with_source_marker("req.body")
            .with_source_marker("req.params")
            .with_source_marker("sys.argv")
            .with_source_marker("os.Args")
            .with_sink("eval")
            .with_sink("exec")
            .with_sink("execSync")
            .with_sink("spawn")
            .with_sink("spawnSync")
            .with_sink("system")
            .with_sink("popen")
            .with_sink("query")
            .with_sink("Command::new");
        Self {
            id: RuleId::new("owasp:cross-file-injection").expect("valid rule id"),
            analysis: CrossFileTaint::new(config),
        }
    }
}

impl Default for CrossFileInjectionRule {
    fn default() -> Self {
        Self::new()
    }
}

impl CrossFileRule for CrossFileInjectionRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn default_severity(&self) -> Severity {
        Severity::Blocker
    }

    fn remediation_effort_minutes(&self) -> u32 {
        30
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "Inter-procedural taint analysis: user input must not reach execution sinks, even through functions defined in other files.".into(),
            tags: vec!["security".into(), "owasp-a03".into(), "cross-file".into()],
            cwe: Some(94),
            produces_hotspots: false,
        }
    }

    fn check(&self, files: &[(SourceFile, AstNode)]) -> Vec<(usize, Finding)> {
        let views: Vec<(&str, &AstNode)> =
            files.iter().map(|(file, ast)| (file.path(), ast)).collect();
        self.analysis
            .find_flows(&views)
            .into_iter()
            .filter_map(|flow| {
                let index = files.iter().position(|(file, _)| file.path() == flow.file)?;
                Some((index, Finding::new(flow.message, flow.span)))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use yunq_ast::{LanguageIdentifier, SourceFile};
    use yunq_rules_engine::AstParser;

    use super::*;

    #[test]
    fn detects_injection_through_an_imported_helper() {
        let lib = SourceFile::new(
            "lib.ts",
            "import cp from 'child_process';\nexport function run(cmd: string) {\n  cp.execSync(cmd);\n}\nexport function launch(x: string) {\n  run(x);\n}\n",
            LanguageIdentifier::typescript(),
        )
        .unwrap();
        let main = SourceFile::new(
            "main.ts",
            "import { launch } from './lib';\nconst target = process.argv[2];\nlaunch(target);\n",
            LanguageIdentifier::typescript(),
        )
        .unwrap();

        let parser = yunq_parser_typescript::TypeScriptParser::new();
        let files = vec![
            (lib.clone(), parser.parse(&lib).unwrap()),
            (main.clone(), parser.parse(&main).unwrap()),
        ];

        let findings = CrossFileInjectionRule::new().check(&files);
        assert_eq!(findings.len(), 1);
        let (index, finding) = &findings[0];
        assert_eq!(files[*index].0.path(), "main.ts");
        assert!(finding.message.contains("process.argv"));
        assert!(finding.message.contains("execSync"));
        assert!(finding.message.contains("launch"));
    }

    #[test]
    fn clean_cross_file_calls_are_silent() {
        let lib = SourceFile::new(
            "lib.ts",
            "import cp from 'child_process';\nexport function run(cmd: string) {\n  cp.execSync(cmd);\n}\n",
            LanguageIdentifier::typescript(),
        )
        .unwrap();
        let main = SourceFile::new(
            "main.ts",
            "import { run } from './lib';\nrun(\"ls -la\");\n",
            LanguageIdentifier::typescript(),
        )
        .unwrap();

        let parser = yunq_parser_typescript::TypeScriptParser::new();
        let files = vec![
            (lib.clone(), parser.parse(&lib).unwrap()),
            (main.clone(), parser.parse(&main).unwrap()),
        ];
        assert!(CrossFileInjectionRule::new().check(&files).is_empty());
    }
}
