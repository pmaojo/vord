use ruff_python_parser::{parse, Mode};
use vord_ast::{AstNode, LanguageIdentifier, SourceFile, Span};
use vord_rules_engine::{declare_rule_id, Finding, IssueType, Rule, RuleId, Severity};

declare_rule_id!(RuffAdapterRule, "python:ruff-analyzer");

impl Rule for RuffAdapterRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, language: &LanguageIdentifier) -> bool {
        *language == LanguageIdentifier::python()
    }

    fn default_severity(&self) -> Severity {
        Severity::Major
    }

    fn issue_type(&self) -> IssueType {
        IssueType::CodeSmell
    }

    fn check(&self, file: &SourceFile, _ast: &AstNode) -> Vec<Finding> {
        let mut findings = Vec::new();
        match parse(file.content(), Mode::Module.into()) {
            Ok(parsed) => {
                for err in parsed.errors() {
                    let msg = err.to_string();
                    let start = err.location.start().to_u32();
                    let end = err.location.end().to_u32();
                    let span = Span::new(1, 1, start + 1, end + 1);

                    findings.push(Finding::new(
                        format!("Ruff diagnostic: {}", msg),
                        span,
                    ));
                }
            }
            Err(err) => {
                let msg = err.to_string();
                let start = err.location.start().to_u32();
                let end = err.location.end().to_u32();
                let span = Span::new(1, 1, start + 1, end + 1);

                findings.push(Finding::new(
                    format!("Ruff parse error: {}", msg),
                    span,
                ));
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_python_code_and_reports_ruff_diagnostics() {
        let code = "def foo():\n    syntax error ::::\n";
        let file = SourceFile::new("test.py", code, LanguageIdentifier::python()).unwrap();
        let ast = AstNode::new(
            vord_ast::NodeKind::SourceUnit,
            Span::new(1, 1, 1, code.len() as u32),
            code,
            vec![],
        );

        let rule = RuffAdapterRule::new();
        let findings = rule.check(&file, &ast);
        assert!(!findings.is_empty());
    }
}
