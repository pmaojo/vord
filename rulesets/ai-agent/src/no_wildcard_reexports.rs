use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use yunq_rules_engine::{declare_rule_id, Finding, IssueType, Rule, RuleId, Severity};

declare_rule_id!(NoWildcardReexportsRule, "ai-agent:no-wildcard-reexports");

impl Rule for NoWildcardReexportsRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, language: &LanguageIdentifier) -> bool {
        *language == LanguageIdentifier::typescript()
    }

    fn default_severity(&self) -> Severity {
        Severity::Major
    }

    fn issue_type(&self) -> IssueType {
        IssueType::CodeSmell
    }

    fn remediation_effort_minutes(&self) -> u32 {
        5
    }

    fn metadata(&self) -> yunq_rules_engine::RuleMetadata {
        yunq_rules_engine::RuleMetadata {
            description: "Wildcard re-exports (`export * from ...`) in index files hide public API boundaries, confusing AI code indexing and semantic graph analysis. Use explicit re-exports (`export { Name } from ...`).".into(),
            tags: vec!["ai-agent".into(), "typescript".into(), "maintainability".into(), "architecture".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        let path = file.path();
        if !is_index_file(path) {
            return Vec::new();
        }

        let mut findings = Vec::new();

        fn walk<'a>(node: &'a AstNode, out: &mut Vec<Finding>) {
            let kind_str = match node.kind() {
                NodeKind::Other(k) => k.as_ref(),
                _ => "",
            };

            if kind_str == "export_statement" || node.text().trim_start().starts_with("export *") {
                let text = node.text().trim_start();
                if is_wildcard_export(text) {
                    out.push(Finding::new(
                        "Avoid wildcard re-export `export * from ...` in index files; use explicit re-exports (`export { Name } from ...`) for deterministic AI indexing.",
                        node.span(),
                    ));
                    return;
                }
            }

            for child in node.children() {
                walk(child, out);
            }
        }

        walk(ast, &mut findings);
        findings
    }
}

fn is_index_file(path: &str) -> bool {
    let filename = path.rsplit('/').next().unwrap_or(path);
    filename.starts_with("index.") || filename == "index"
}

fn is_wildcard_export(text: &str) -> bool {
    text.starts_with("export *") || text.starts_with("export type *")
}

#[cfg(test)]
mod tests {
    use yunq_ast::SourceFile;
    use yunq_rules_engine::AstParser;

    use super::*;

    fn check_file(path: &str, code: &str) -> Vec<Finding> {
        let file = SourceFile::new(path, code, LanguageIdentifier::typescript()).unwrap();
        let ast = yunq_parser_typescript::TypeScriptParser::new()
            .parse(&file)
            .unwrap();
        NoWildcardReexportsRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_wildcard_reexport_in_index_ts() {
        let findings = check_file("src/index.ts", "export * from './components';\n");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("wildcard re-export"));
    }

    #[test]
    fn flags_wildcard_as_ns_reexport_in_index_tsx() {
        let findings = check_file("components/index.tsx", "export * as components from './components';\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_wildcard_type_reexport_in_index_d_ts() {
        let findings = check_file("types/index.d.ts", "export type * from './types';\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn allows_explicit_reexport_in_index_ts() {
        let findings = check_file("src/index.ts", "export { Button, Card } from './components';\n");
        assert!(findings.is_empty());
    }

    #[test]
    fn allows_wildcard_reexport_in_non_index_file() {
        let findings = check_file("src/components.ts", "export * from './button';\n");
        assert!(findings.is_empty());
    }
}
