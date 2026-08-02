//! Rule: Warns against storing sensitive authentication tokens in `localStorage` or `sessionStorage` (OWASP A03 / ASVS 3.8.1).

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

pub struct AuthTokenInWebStorageRule {
    id: RuleId,
}

impl AuthTokenInWebStorageRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("react:auth-token-in-web-storage").expect("valid rule id"),
        }
    }
}

impl Default for AuthTokenInWebStorageRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for AuthTokenInWebStorageRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, lang: &LanguageIdentifier) -> bool {
        *lang == LanguageIdentifier::typescript()
    }

    fn default_severity(&self) -> Severity {
        Severity::Major
    }

    fn issue_type(&self) -> IssueType {
        IssueType::Vulnerability
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "Avoid storing sensitive authentication tokens (e.g. JWTs, bearer tokens) in `localStorage` or `sessionStorage`. Web Storage is accessible to any script on the origin, making tokens vulnerable to exfiltration via XSS. Store tokens in HttpOnly cookies or in-memory instead.".into(),
            tags: vec!["react".into(), "security".into(), "xss".into(), "owasp-a03".into()],
            cwe: Some(922),
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        let mut findings = Vec::new();
        let sensitive_keys = [
            "access_token",
            "id_token",
            "bearer",
            "session",
            "secret",
            "token",
            "auth",
            "jwt",
        ];

        for node in ast.descendants() {
            if *node.kind() == NodeKind::Call {
                let text = node.text();
                if text.contains("localStorage.setItem") || text.contains("sessionStorage.setItem")
                {
                    let lower = text.to_lowercase();
                    for key in &sensitive_keys {
                        if lower.contains(key) {
                            findings.push(Finding::new(
                                format!("Storing sensitive auth token key `{key}` in Web Storage introduces XSS exfiltration risk. Use HttpOnly cookies or memory instead."),
                                node.span(),
                            ));
                            break;
                        }
                    }
                }
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vord_ast::Span;

    #[test]
    fn flags_storing_token_in_local_storage() {
        let rule = AuthTokenInWebStorageRule::new();
        let file = SourceFile::new(
            "App.tsx",
            "localStorage.setItem('access_token', token);",
            LanguageIdentifier::typescript(),
        )
        .unwrap();

        let callee = AstNode::new(
            NodeKind::Identifier,
            Span::new(1, 1, 1, 21),
            "localStorage.setItem",
            vec![],
        );
        let arg = AstNode::new(
            NodeKind::StringLiteral,
            Span::new(1, 22, 1, 36),
            "'access_token'",
            vec![],
        );
        let call = AstNode::new(
            NodeKind::Call,
            Span::new(1, 1, 1, 43),
            "localStorage.setItem('access_token', token)",
            vec![callee, arg],
        );

        let findings = rule.check(&file, &call);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("access_token"));
    }

    #[test]
    fn allows_non_sensitive_keys() {
        let rule = AuthTokenInWebStorageRule::new();
        let file = SourceFile::new(
            "App.tsx",
            "localStorage.setItem('theme', 'dark');",
            LanguageIdentifier::typescript(),
        )
        .unwrap();

        let callee = AstNode::new(
            NodeKind::Identifier,
            Span::new(1, 1, 1, 21),
            "localStorage.setItem",
            vec![],
        );
        let arg = AstNode::new(
            NodeKind::StringLiteral,
            Span::new(1, 22, 1, 29),
            "'theme'",
            vec![],
        );
        let call = AstNode::new(
            NodeKind::Call,
            Span::new(1, 1, 1, 37),
            "localStorage.setItem('theme', 'dark')",
            vec![callee, arg],
        );

        let findings = rule.check(&file, &call);
        assert!(findings.is_empty());
    }
}
