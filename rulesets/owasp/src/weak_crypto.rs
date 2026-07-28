//! Rule: flags weak cryptographic algorithms (MD5, SHA1, DES, RC4).

use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use yunq_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

/// Line-level guard against the two shapes this rule's substring heuristic
/// otherwise flags on code that only *talks about* an algorithm name rather
/// than calling it: a Markdown-style backtick mention (`` `md5` ``, the
/// convention this codebase's own rule descriptions use) and a list literal
/// of two or more quoted string tokens (an allow-list/catalog of algorithm
/// names, e.g. `&["md5", "sha1", "hash", "crc32"]`). Real usage — a call
/// argument, a member access — carries at most one quoted token on its line
/// and is never backtick-wrapped in any language this rule scans.
fn mentions_algorithm_names_as_data(line: &str) -> bool {
    let backtick_wrapped = ["MD5", "Md5", "md5", "SHA1", "Sha1", "sha1", "DES", "RC4"]
        .iter()
        .any(|pattern| line.contains(&format!("`{pattern}`")));
    let quoted_tokens = line.matches('"').count() / 2 + line.matches('\'').count() / 2;
    backtick_wrapped || quoted_tokens >= 2
}

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
            if mentions_algorithm_names_as_data(line) {
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

    #[test]
    fn does_not_flag_an_algorithm_name_catalog_declared_as_data() {
        // A rule (or an allow-list, a config table, ...) that names several
        // hash algorithms as string data — not a call to any of them.
        let code = "const HASH_FUNCTIONS: &[&str] = &[\"md5\", \"sha1\", \"hash\", \"crc32\"];\n";
        let file = SourceFile::new("catalog.rs", code, LanguageIdentifier::rust()).unwrap();
        let ast = AstNode::new(NodeKind::SourceUnit, yunq_ast::Span::new(1, 1, 1, code.len() as u32), code, vec![]);
        let rule = WeakCryptoRule::new();

        assert!(rule.check(&file, &ast).is_empty(), "a data catalog of algorithm names is not usage");
    }

    #[test]
    fn does_not_flag_a_backtick_wrapped_mention_in_prose() {
        let code = "description: \"Comparing a hash (`md5`/`sha1`/`hash`/`crc32`) is unsafe\",\n";
        let file = SourceFile::new("docs.rs", code, LanguageIdentifier::rust()).unwrap();
        let ast = AstNode::new(NodeKind::SourceUnit, yunq_ast::Span::new(1, 1, 1, code.len() as u32), code, vec![]);
        let rule = WeakCryptoRule::new();

        assert!(rule.check(&file, &ast).is_empty(), "a documentation mention is not usage");
    }

    #[test]
    fn still_flags_a_direct_call_with_a_single_quoted_argument() {
        let code = "hash_val = hashlib.new('md5', data).hexdigest()\n";
        let file = SourceFile::new("app.py", code, LanguageIdentifier::python()).unwrap();
        let ast = AstNode::new(NodeKind::SourceUnit, yunq_ast::Span::new(1, 1, 1, code.len() as u32), code, vec![]);
        let rule = WeakCryptoRule::new();

        assert_eq!(rule.check(&file, &ast).len(), 1, "a single-quoted call argument must still be flagged");
    }
}
