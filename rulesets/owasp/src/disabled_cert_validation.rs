//! Rule: flags code that disables TLS/SSL certificate validation.

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

const MARKERS: &[&str] = &[
    "rejectUnauthorized: false",
    "rejectUnauthorized:false",
    "rejectUnauthorized = false",
    "NODE_TLS_REJECT_UNAUTHORIZED",
    "InsecureSkipVerify",
    "ssl._create_unverified_context",
    "CERT_NONE",
];

pub struct DisabledCertValidationRule {
    id: RuleId,
}

impl DisabledCertValidationRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("owasp:disabled-cert-validation").expect("valid rule id"),
        }
    }
}

impl Default for DisabledCertValidationRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for DisabledCertValidationRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, lang: &LanguageIdentifier) -> bool {
        *lang == LanguageIdentifier::typescript()
            || *lang == LanguageIdentifier::python()
            || *lang == LanguageIdentifier::go()
    }

    fn default_severity(&self) -> Severity {
        Severity::Critical
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

            let matched_marker = MARKERS.iter().find(|m| line.contains(*m));
            let matched_verify_false =
                line.contains("verify=False") || line.contains("verify = False");

            if let Some(marker) = matched_marker {
                findings.push(Finding::new(
                    format!("Certificate validation disabled via '{marker}'; this allows man-in-the-middle attacks"),
                    vord_ast::Span::new((idx + 1) as u32, 1, (idx + 1) as u32, line.len().max(1) as u32),
                ));
            } else if matched_verify_false {
                findings.push(Finding::new(
                    "Certificate validation disabled via 'verify=False'; this allows man-in-the-middle attacks",
                    vord_ast::Span::new((idx + 1) as u32, 1, (idx + 1) as u32, line.len().max(1) as u32),
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
    fn flags_node_reject_unauthorized_false() {
        let code = "https.request({ rejectUnauthorized: false }, cb);\n";
        let file = SourceFile::new("app.ts", code, LanguageIdentifier::typescript()).unwrap();
        let ast = AstNode::new(
            NodeKind::SourceUnit,
            vord_ast::Span::new(1, 1, 1, code.len() as u32),
            code,
            vec![],
        );
        let findings = DisabledCertValidationRule::new().check(&file, &ast);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_python_requests_verify_false() {
        let code = "resp = requests.get(url, verify=False)\n";
        let file = SourceFile::new("app.py", code, LanguageIdentifier::python()).unwrap();
        let ast = AstNode::new(
            NodeKind::SourceUnit,
            vord_ast::Span::new(1, 1, 1, code.len() as u32),
            code,
            vec![],
        );
        let findings = DisabledCertValidationRule::new().check(&file, &ast);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_go_insecure_skip_verify() {
        let code =
            "tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}\n";
        let file = SourceFile::new("main.go", code, LanguageIdentifier::go()).unwrap();
        let ast = AstNode::new(
            NodeKind::SourceUnit,
            vord_ast::Span::new(1, 1, 1, code.len() as u32),
            code,
            vec![],
        );
        let findings = DisabledCertValidationRule::new().check(&file, &ast);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn allows_default_validation() {
        let code = "https.request({ rejectUnauthorized: true }, cb);\n";
        let file = SourceFile::new("app.ts", code, LanguageIdentifier::typescript()).unwrap();
        let ast = AstNode::new(
            NodeKind::SourceUnit,
            vord_ast::Span::new(1, 1, 1, code.len() as u32),
            code,
            vec![],
        );
        let findings = DisabledCertValidationRule::new().check(&file, &ast);
        assert!(findings.is_empty());
    }
}
