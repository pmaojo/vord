use oxc::allocator::Allocator;
use oxc::parser::{Parser, ParserReturn};
use oxc::span::SourceType;
use yunq_ast::{AstNode, LanguageIdentifier, SourceFile, Span};
use yunq_rules_engine::{Finding, IssueType, Rule, RuleId, Severity, declare_rule_id};

declare_rule_id!(OxlintAdapterRule, "typescript:oxlint-analyzer");

impl Rule for OxlintAdapterRule {
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

    fn check(&self, file: &SourceFile, _ast: &AstNode) -> Vec<Finding> {
        let mut findings = Vec::new();
        let allocator = Allocator::default();
        let source_type = SourceType::from_path(file.path()).unwrap_or_default();
        let ParserReturn { errors, .. } =
            Parser::new(&allocator, file.content(), source_type).parse();

        for err in errors {
            let msg = err.to_string();
            let start = err
                .labels
                .as_ref()
                .and_then(|l| l.first())
                .map(|lbl| lbl.offset())
                .unwrap_or(0) as u32;
            let len = err
                .labels
                .as_ref()
                .and_then(|l| l.first())
                .map(|lbl| lbl.len())
                .unwrap_or(1) as u32;

            // Map byte offset to line/column inside file
            let span = Span::new(1, 1, start + 1, start + len + 1);
            findings.push(Finding::new(format!("Oxlint diagnostic: {}", msg), span));
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_js_ts_and_reports_syntax_diagnostics() {
        let code = "const a: any = 123; syntax error {{{";
        let file = SourceFile::new("app.ts", code, LanguageIdentifier::typescript()).unwrap();
        let ast = AstNode::new(
            yunq_ast::NodeKind::SourceUnit,
            Span::new(1, 1, 1, code.len() as u32),
            code,
            vec![],
        );

        let rule = OxlintAdapterRule::new();
        let findings = rule.check(&file, &ast);
        assert!(!findings.is_empty());
    }
}
