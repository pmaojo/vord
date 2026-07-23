use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use yunq_rules_engine::{Finding, Rule, RuleId, Severity};

/// Flags functions longer than a configurable number of lines. Skips
/// `tests/*.rs` integration test files — a single long, sequential,
/// assertion-heavy end-to-end test sharing one expensive setup is often
/// clearer than splitting it just to satisfy a line count.
pub struct LongFunctionRule {
    id: RuleId,
    max_lines: u32,
}

impl LongFunctionRule {
    pub fn new(max_lines: u32) -> Self {
        Self { id: RuleId::new("smells:long-function").expect("valid rule id"), max_lines }
    }
}

impl Default for LongFunctionRule {
    fn default() -> Self {
        Self::new(50)
    }
}

impl Rule for LongFunctionRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, _language: &LanguageIdentifier) -> bool {
        true
    }

    fn default_severity(&self) -> Severity {
        Severity::Minor
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        if yunq_rules_engine::is_test_only_path(file.path()) {
            return Vec::new();
        }
        ast.descendants()
            .filter(|n| *n.kind() == NodeKind::FunctionDef)
            .filter(|f| f.span().line_count() > self.max_lines)
            .map(|f| {
                Finding::new(
                    format!(
                        "function spans {} lines (max {})",
                        f.span().line_count(),
                        self.max_lines
                    ),
                    f.span(),
                )
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use yunq_ast::SourceFile;
    use yunq_rules_engine::AstParser;

    use super::*;

    #[test]
    fn flags_functions_over_threshold() {
        let body: String = (0..10).map(|i| format!("    let x{i} = {i};\n")).collect();
        let code = format!("fn long() {{\n{body}}}\n\nfn short() {{}}\n");
        let file = SourceFile::new("t.rs", code, LanguageIdentifier::rust()).unwrap();
        let ast = yunq_parser_rust::RustParser::new().parse(&file).unwrap();

        let findings = LongFunctionRule::new(5).check(&file, &ast);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("12 lines"));
    }

    #[test]
    fn ignores_long_functions_in_integration_test_files() {
        let body: String = (0..10).map(|i| format!("    let x{i} = {i};\n")).collect();
        let code = format!("fn long() {{\n{body}}}\n");
        let file = SourceFile::new("tests/e2e.rs", code, LanguageIdentifier::rust()).unwrap();
        let ast = yunq_parser_rust::RustParser::new().parse(&file).unwrap();

        assert!(LongFunctionRule::new(5).check(&file, &ast).is_empty());
    }
}
