//! Rule: flags weak cryptographic hash algorithms (MD5, SHA1) in crypto calls.

use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use yunq_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

fn mentions_algorithm_names_as_data(line: &str) -> bool {
    if line.contains("lower.contains")
        || line.contains("weak_patterns")
        || line.contains("is_weak_crypto")
        || line.contains("Finding::new")
        || line.contains("RuleId::new")
    {
        return true;
    }
    let backtick_wrapped = ["MD5", "Md5", "md5", "SHA1", "Sha1", "sha1", "SHA-1", "sha-1"]
        .iter()
        .any(|pattern| line.contains(&format!("`{pattern}`")));
    let quoted_tokens = line.matches('"').count() / 2 + line.matches('\'').count() / 2;
    backtick_wrapped || quoted_tokens >= 2
}

fn is_weak_crypto_hash(line: &str) -> bool {
    let lower = line.to_lowercase();
    let has_hash_call = lower.contains("createhash")
        || lower.contains("hashlib.md5")
        || lower.contains("hashlib.sha1")
        || lower.contains("crypto.createhash")
        || lower.contains("cryptojs.md5")
        || lower.contains("cryptojs.sha1");

    if !has_hash_call {
        return false;
    }

    lower.contains("\"md5\"")
        || lower.contains("'md5'")
        || lower.contains("\"sha1\"")
        || lower.contains("'sha1'")
        || lower.contains("\"sha-1\"")
        || lower.contains("'sha-1'")
        || lower.contains("hashlib.md5")
        || lower.contains("hashlib.sha1")
        || lower.contains("cryptojs.md5")
        || lower.contains("cryptojs.sha1")
}

pub struct WeakCryptoHashRule {
    id: RuleId,
}

impl WeakCryptoHashRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("owasp:weak-crypto-hash").expect("valid rule id"),
        }
    }
}

impl Default for WeakCryptoHashRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for WeakCryptoHashRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, language: &LanguageIdentifier) -> bool {
        *language != LanguageIdentifier::rust()
    }

    fn default_severity(&self) -> Severity {
        Severity::Critical
    }

    fn issue_type(&self) -> IssueType {
        IssueType::Vulnerability
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "Use of weak cryptographic hash algorithms (MD5, SHA1) in crypto functions is vulnerable to collision attacks. Prefer SHA-256 or SHA-512.".into(),
            tags: vec!["security".into(), "owasp-a02".into(), "crypto".into(), "hash".into()],
            cwe: Some(328),
            produces_hotspots: false,
        }
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

        for (idx, line) in content.lines().enumerate() {
            let line_no = (idx + 1) as u32;
            if yunq_rules_engine::in_ranges(&test_ranges, line_no) {
                continue;
            }
            let trimmed = line.trim();
            if trimmed.starts_with("//") || trimmed.starts_with('#') || trimmed.starts_with('*') {
                continue;
            }
            if mentions_algorithm_names_as_data(line) {
                continue;
            }

            if is_weak_crypto_hash(line) {
                findings.push(Finding::new(
                    "Weak cryptographic hash algorithm (MD5/SHA1) used in crypto call; prefer SHA-256 or SHA-512",
                    yunq_ast::Span::new(line_no, 1, line_no, line.len().max(1) as u32),
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
    fn flags_crypto_create_hash_md5() {
        let code = "const hash = crypto.createHash(\"md5\");\n";
        let file = SourceFile::new("app.js", code, LanguageIdentifier::typescript()).unwrap();
        let ast = AstNode::new(
            NodeKind::SourceUnit,
            yunq_ast::Span::new(1, 1, 1, code.len() as u32),
            code,
            vec![],
        );
        let rule = WeakCryptoHashRule::new();
        let findings = rule.check(&file, &ast);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_crypto_create_hash_sha1() {
        let code = "const hash = crypto.createHash('sha1');\n";
        let file = SourceFile::new("app.js", code, LanguageIdentifier::typescript()).unwrap();
        let ast = AstNode::new(
            NodeKind::SourceUnit,
            yunq_ast::Span::new(1, 1, 1, code.len() as u32),
            code,
            vec![],
        );
        let rule = WeakCryptoHashRule::new();
        let findings = rule.check(&file, &ast);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn allows_sha256() {
        let code = "const hash = crypto.createHash(\"sha256\");\n";
        let file = SourceFile::new("app.js", code, LanguageIdentifier::typescript()).unwrap();
        let ast = AstNode::new(
            NodeKind::SourceUnit,
            yunq_ast::Span::new(1, 1, 1, code.len() as u32),
            code,
            vec![],
        );
        let rule = WeakCryptoHashRule::new();
        let findings = rule.check(&file, &ast);
        assert!(findings.is_empty());
    }

    #[test]
    fn ignores_comments() {
        let code = "// crypto.createHash(\"md5\")\n";
        let file = SourceFile::new("app.js", code, LanguageIdentifier::typescript()).unwrap();
        let ast = AstNode::new(
            NodeKind::SourceUnit,
            yunq_ast::Span::new(1, 1, 1, code.len() as u32),
            code,
            vec![],
        );
        let rule = WeakCryptoHashRule::new();
        let findings = rule.check(&file, &ast);
        assert!(findings.is_empty());
    }
}
