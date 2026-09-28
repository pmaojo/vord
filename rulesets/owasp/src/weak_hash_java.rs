//! Rule: flags `MessageDigest`/`DigestUtils` hashing with a weak or
//! unprovable algorithm — the OWASP Benchmark "hash" family (CWE-328).
//!
//! Strategy: `MessageDigest.getInstance(alg)` is judged by the algorithm
//! *value*: a strong literal (`SHA-256`, `SHA-384`, `SHA-512`, `SHA3-*`)
//! is silent, a weak literal (`MD5`, `MD2`, `SHA-1`, …) is flagged, and a
//! non-literal (config property, request parameter, …) is flagged because
//! it cannot be proven strong at the call site. `DigestUtils.md5*`/
//! `sha1*` shortcuts are weak by definition.

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

use crate::java_servlet_taint::{split_call, ServletTaint};

const WEAK_ALGORITHMS: &[&str] = &[
    "MD2", "MD4", "MD5", "SHA-1", "SHA1", "SHA-0", "HAVAL-128", "RIPEMD-160",
];

const STRONG_ALGORITHM_PREFIXES: &[&str] = &[
    "SHA-256", "SHA-384", "SHA-512", "SHA256", "SHA384", "SHA512", "SHA3-224", "SHA3-256",
    "SHA3-384", "SHA3-512", "BLAKE2", "BLAKE3",
];

const WEAK_DIGEST_UTILS: &[&str] = &["md5", "md5Hex", "sha1", "sha1Hex", "md2", "md2Hex"];

fn is_weak_literal(alg: &str) -> bool {
    let upper = alg.trim().to_ascii_uppercase();
    WEAK_ALGORITHMS.iter().any(|w| upper == *w)
}

fn is_strong_literal(alg: &str) -> bool {
    let upper = alg.trim().to_ascii_uppercase();
    STRONG_ALGORITHM_PREFIXES
        .iter()
        .any(|s| upper.starts_with(*s))
}

pub struct WeakHashJavaRule {
    id: RuleId,
}

impl WeakHashJavaRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("owasp:weak-hash-java").expect("valid rule id"),
        }
    }
}

impl Default for WeakHashJavaRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for WeakHashJavaRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, language: &LanguageIdentifier) -> bool {
        *language == LanguageIdentifier::java()
    }

    fn default_severity(&self) -> Severity {
        Severity::Major
    }

    fn issue_type(&self) -> IssueType {
        IssueType::Vulnerability
    }

    fn remediation_effort_minutes(&self) -> u32 {
        10
    }

    fn metadata(&self) -> vord_rules_engine::RuleMetadata {
        vord_rules_engine::RuleMetadata {
            description: "A weak or unverifiable hash algorithm (MD5, SHA-1, or a value not statically known) is used in MessageDigest.getInstance; prefer SHA-256/SHA-512 or a password-hashing function like PBKDF2/bcrypt.".into(),
            tags: vec!["security".into(), "owasp-a02".into(), "crypto".into(), "java".into()],
            cwe: Some(328),
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        let state = ServletTaint::analyze(ast);
        ast.descendants()
            .filter(|n| *n.kind() == NodeKind::Call)
            .filter_map(|node| {
                let call = split_call(node)?;
                if call.method == "getInstance" && call.receiver_text.contains("MessageDigest") {
                    let alg = call.args.first()?;
                    let reason = match state.literal_of(alg) {
                        Some(lit) if is_weak_literal(&lit) => {
                            Some(format!("weak hash algorithm `{lit}`"))
                        }
                        Some(lit) if is_strong_literal(&lit) => None,
                        Some(lit) => Some(format!("non-standard hash algorithm `{lit}`")),
                        None => Some(
                            "a hash algorithm that is not statically known (configuration- or user-controlled)".to_string(),
                        ),
                    }?;
                    return Some(Finding::new(
                        format!(
                            "MessageDigest.getInstance uses {reason}; use SHA-256/SHA-512 or a password-hashing function instead — this is a use of a weak cryptographic hash"
                        ),
                        node.span(),
                    ));
                }
                if WEAK_DIGEST_UTILS.contains(&call.method.as_str()) {
                    return Some(Finding::new(
                        format!(
                            "weak hash shortcut `{}(…)` (MD5/SHA-1) used; prefer SHA-256/SHA-512 or a password-hashing function",
                            call.method
                        ),
                        node.span(),
                    ));
                }
                None
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use vord_ast::SourceFile;
    use vord_rules_engine::AstParser;

    use super::*;

    fn check(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("Test.java", code, LanguageIdentifier::java()).unwrap();
        let ast = vord_parser_java::JavaParser::new().parse(&file).unwrap();
        WeakHashJavaRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_md5_literal() {
        let findings = check(
            "class T { void f() {\n java.security.MessageDigest md = java.security.MessageDigest.getInstance(\"MD5\");\n} }",
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_variable_algorithm() {
        let findings = check(
            "class T { void f() {\n String algorithm = benchmarkprops.getProperty(\"hashAlg1\", \"SHA512\");\n java.security.MessageDigest md = java.security.MessageDigest.getInstance(algorithm);\n} }",
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn allows_strong_literal() {
        let findings = check(
            "class T { void f() {\n java.security.MessageDigest md = java.security.MessageDigest.getInstance(\"SHA-256\");\n} }",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn allows_strong_literal_through_variable() {
        let findings = check(
            "class T { void f() {\n String algorithm = \"SHA-256\";\n java.security.MessageDigest md = java.security.MessageDigest.getInstance(algorithm);\n} }",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn flags_md5_digest_utils() {
        let findings = check(
            "class T { void f(String s) {\n String h = org.apache.commons.codec.digest.DigestUtils.md5Hex(s);\n} }",
        );
        assert_eq!(findings.len(), 1);
    }
}
