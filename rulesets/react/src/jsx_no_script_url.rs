//! Rule: Flags `javascript:` URLs in JSX attributes (href, src, etc.) to prevent XSS vulnerabilities.

use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use yunq_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

pub struct JsxNoScriptUrlRule {
    id: RuleId,
}

impl JsxNoScriptUrlRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("react:jsx-no-script-url").expect("valid rule id"),
        }
    }
}

impl Default for JsxNoScriptUrlRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for JsxNoScriptUrlRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, lang: &LanguageIdentifier) -> bool {
        *lang == LanguageIdentifier::typescript()
    }

    fn default_severity(&self) -> Severity {
        Severity::Critical
    }

    fn issue_type(&self) -> IssueType {
        IssueType::Vulnerability
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "Avoid using `javascript:` URLs in JSX attributes (e.g. href, src). They introduce XSS vulnerabilities when evaluated by the browser.".into(),
            tags: vec!["react".into(), "security".into(), "xss".into(), "owasp-a03".into()],
            cwe: Some(79),
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        let mut findings = Vec::new();

        for node in ast.descendants() {
            if *node.kind() == NodeKind::StringLiteral {
                let text = node
                    .text()
                    .trim_matches(|c| c == '"' || c == '\'' || c == '`');
                let lower = text.to_lowercase();
                if lower.starts_with("javascript:") {
                    findings.push(Finding::new(
                        format!("Use of `javascript:` URL in JSX attribute value: `{text}` introduces XSS security risk"),
                        node.span(),
                    ));
                }
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use yunq_ast::Span;

    #[test]
    fn flags_script_url_in_jsx() {
        let rule = JsxNoScriptUrlRule::new();
        let file = SourceFile::new(
            "App.tsx",
            "<a href=\"javascript:void(0)\">Link</a>",
            LanguageIdentifier::typescript(),
        )
        .unwrap();
        let str_node = AstNode::new(
            NodeKind::StringLiteral,
            Span::new(1, 10, 1, 28),
            "\"javascript:void(0)\"",
            vec![],
        );

        let findings = rule.check(&file, &str_node);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("javascript:"));
    }

    #[test]
    fn allows_safe_urls() {
        let rule = JsxNoScriptUrlRule::new();
        let file = SourceFile::new(
            "App.tsx",
            "<a href=\"https://example.com\">Link</a>",
            LanguageIdentifier::typescript(),
        )
        .unwrap();
        let str_node = AstNode::new(
            NodeKind::StringLiteral,
            Span::new(1, 10, 1, 31),
            "\"https://example.com\"",
            vec![],
        );

        let findings = rule.check(&file, &str_node);
        assert!(findings.is_empty());
    }
}
