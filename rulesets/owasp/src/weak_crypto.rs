//! Rule: flags weak cryptographic algorithms (MD5, SHA1, DES, RC4).

use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use yunq_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

pub struct WeakCryptoRule {
    id: RuleId,
}

impl WeakCryptoRule {
    pub fn new() -> Self {
        let id = match RuleId::new("owasp:weak-crypto") {
            Ok(id) => id,
            Err(_) => unreachable!(),
        };
        Self { id }
    }
}

impl Default for WeakCryptoRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for WeakCryptoRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, _lang: &LanguageIdentifier) -> bool {
        true
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
        if yunq_rules_engine::is_test_only_path(file.path()) {
            return Vec::new();
        }
        let test_ranges = yunq_rules_engine::rust_test_module_ranges(file.content());

        let mut findings = Vec::new();
        let content = file.content();
        let weak_patterns = ["MD5", "Md5", "md5", "SHA1", "Sha1", "sha1", "DES", "RC4"];

        for (idx, line) in content.lines().enumerate() {
            let line_no = (idx + 1) as u32;
            if yunq_rules_engine::in_ranges(&test_ranges, line_no) {
                continue;
            }
            let trimmed = line.trim();
            if trimmed.starts_with("//") || trimmed.starts_with('#') || trimmed.starts_with('*') {
                continue;
            }

            for pattern in weak_patterns {
                if line.contains(pattern) && (line.contains("hash") || line.contains("cipher") || line.contains("digest") || line.contains("crypto") || line.contains("createHash")) {
                    findings.push(Finding::new(
                        format!("Use of weak cryptographic algorithm '{pattern}'; prefer SHA-256 or AES-GCM"),
                        yunq_ast::Span::new((idx + 1) as u32, 1, (idx + 1) as u32, line.len().max(1) as u32),
                    ));
                    break;
                }
            }
        }
        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_md5_crypto_usage() {
        let code = "const hash = crypto.createHash('md5');\n";
        let file = SourceFile::new("app.js", code, LanguageIdentifier::typescript()).unwrap();
        let ast = AstNode::new(NodeKind::SourceUnit, yunq_ast::Span::new(1, 1, 1, code.len() as u32), code, vec![]);
        let rule = WeakCryptoRule::new();

        let findings = rule.check(&file, &ast);
        assert_eq!(findings.len(), 1);
    }
}
