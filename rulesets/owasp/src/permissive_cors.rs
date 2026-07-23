//! Rule: flags CORS configuration that allows any origin.

use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use yunq_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

pub struct PermissiveCorsRule {
    id: RuleId,
}

impl PermissiveCorsRule {
    pub fn new() -> Self {
        Self { id: RuleId::new("owasp:permissive-cors").expect("valid rule id") }
    }
}

impl Default for PermissiveCorsRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for PermissiveCorsRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, lang: &LanguageIdentifier) -> bool {
        *lang != LanguageIdentifier::rust()
    }

    fn default_severity(&self) -> Severity {
        Severity::Major
    }

    fn issue_type(&self) -> IssueType {
        IssueType::Vulnerability
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        if ast.kind() != &NodeKind::SourceUnit {
            return Vec::new();
        }

        let mut findings = Vec::new();
        for (idx, line) in file.content().lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.starts_with("//") || trimmed.starts_with('#') || trimmed.starts_with('*') {
                continue;
            }

            let mentions_cors = line.contains("Access-Control-Allow-Origin")
                || line.contains("origin:")
                || line.contains("origin =")
                || line.contains("CORS(");
            let allows_any_origin =
                line.contains("'*'") || line.contains("\"*\"") || line.contains("origin: true");

            if mentions_cors && allows_any_origin {
                findings.push(Finding::new(
                    "CORS configured to allow any origin ('*'); restrict to a known allowlist",
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
    fn flags_wildcard_access_control_header() {
        let code = "res.setHeader('Access-Control-Allow-Origin', '*');\n";
        let file = SourceFile::new("app.ts", code, LanguageIdentifier::typescript()).unwrap();
        let ast = AstNode::new(NodeKind::SourceUnit, yunq_ast::Span::new(1, 1, 1, code.len() as u32), code, vec![]);
        let findings = PermissiveCorsRule::new().check(&file, &ast);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_cors_middleware_origin_true() {
        let code = "app.use(cors({ origin: true }));\n";
        let file = SourceFile::new("app.ts", code, LanguageIdentifier::typescript()).unwrap();
        let ast = AstNode::new(NodeKind::SourceUnit, yunq_ast::Span::new(1, 1, 1, code.len() as u32), code, vec![]);
        let findings = PermissiveCorsRule::new().check(&file, &ast);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn allows_restricted_origin() {
        let code = "res.setHeader('Access-Control-Allow-Origin', 'https://example.com');\n";
        let file = SourceFile::new("app.ts", code, LanguageIdentifier::typescript()).unwrap();
        let ast = AstNode::new(NodeKind::SourceUnit, yunq_ast::Span::new(1, 1, 1, code.len() as u32), code, vec![]);
        let findings = PermissiveCorsRule::new().check(&file, &ast);
        assert!(findings.is_empty());
    }
}
