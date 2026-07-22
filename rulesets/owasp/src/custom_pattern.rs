//! User-defined custom pattern rule (Semgrep-style matching from `yunq.toml`).

use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use yunq_rules_engine::{Finding, Rule, RuleId, Severity};

pub struct CustomPatternRule {
    id: RuleId,
    message: String,
    pattern: String,
    severity: Severity,
}

impl CustomPatternRule {
    pub fn new(id_str: &str, message: impl Into<String>, pattern: impl Into<String>, severity: Severity) -> Option<Self> {
        let id = RuleId::new(id_str).ok()?;
        Some(Self {
            id,
            message: message.into(),
            pattern: pattern.into(),
            severity,
        })
    }
}

impl Rule for CustomPatternRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, _lang: &LanguageIdentifier) -> bool {
        true
    }

    fn default_severity(&self) -> Severity {
        self.severity
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        if ast.kind() != &NodeKind::SourceUnit {
            return Vec::new();
        }

        let mut findings = Vec::new();
        let content = file.content();

        for (idx, line) in content.lines().enumerate() {
            if line.contains(&self.pattern) {
                findings.push(Finding::new(
                    &self.message,
                    yunq_ast::Span::new((idx + 1) as u32, 1, (idx + 1) as u32, line.len().max(1) as u32),
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
    fn flags_custom_pattern() {
        let code = "console.log('hello world');\n";
        let file = SourceFile::new("app.js", code, LanguageIdentifier::typescript()).unwrap();
        let ast = AstNode::new(NodeKind::SourceUnit, yunq_ast::Span::new(1, 1, 1, code.len() as u32), code, vec![]);
        let rule = CustomPatternRule::new("custom:no-console-log", "Remove console.log", "console.log", Severity::Minor).unwrap();

        let findings = rule.check(&file, &ast);
        assert_eq!(findings.len(), 1);
    }
}
