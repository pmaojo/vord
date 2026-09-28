//! Rule: flags `random.*(...)` used to build a value assigned to a
//! security-sensitive-looking name (token, password, secret, key, otp,
//! nonce, salt). The `random` module is a Mersenne Twister: not
//! cryptographically secure, and its output is predictable from enough
//! samples. Use the `secrets` module for anything that needs to resist a
//! motivated attacker.

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

const SENSITIVE_WORDS: &[&str] = &[
    "token", "password", "passwd", "secret", "apikey", "api_key", "otp", "nonce", "salt", "csrf",
];

/// Compound names built on "key" with an ordinary data-structure or
/// database meaning, not a cryptographic one — `primary_key`/`sort_key`/
/// `cache_key` and friends are everyday DB/dict/sort vocabulary that has
/// nothing to do with security, and blanket-matching any name containing
/// "key" flagged these at the rule's default Critical severity.
const BENIGN_KEY_COMPOUNDS: &[&str] = &[
    "primary_key",
    "primarykey",
    "foreign_key",
    "foreignkey",
    "sort_key",
    "sortkey",
    "cache_key",
    "cachekey",
    "partition_key",
    "partitionkey",
    "shard_key",
    "shardkey",
    "hash_key",
    "hashkey",
    "dict_key",
    "dictkey",
    "map_key",
    "mapkey",
    "lookup_key",
    "lookupkey",
    "index_key",
    "indexkey",
    "composite_key",
    "compositekey",
    "unique_key",
    "uniquekey",
    "row_key",
    "rowkey",
    "group_key",
    "groupkey",
];

fn looks_security_sensitive(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    if SENSITIVE_WORDS.iter().any(|w| lower.contains(w)) {
        return true;
    }
    if !lower.contains("key") || lower.ends_with("keys") {
        return false;
    }
    !BENIGN_KEY_COMPOUNDS.iter().any(|c| lower.contains(c))
}

fn is_insecure_random_call(value: &AstNode) -> bool {
    value.kind() == &NodeKind::Call
        && value.first_child().is_some_and(|callee| {
            let text = callee.text();
            text.starts_with("random.") && !text.starts_with("random.SystemRandom")
        })
}

pub struct UnsafeRandomModuleForSecurityRule {
    id: RuleId,
}

impl UnsafeRandomModuleForSecurityRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("python:unsafe-random-module-for-security").expect("valid rule id"),
        }
    }
}

impl Default for UnsafeRandomModuleForSecurityRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for UnsafeRandomModuleForSecurityRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, lang: &LanguageIdentifier) -> bool {
        *lang == LanguageIdentifier::python()
    }

    fn default_severity(&self) -> Severity {
        Severity::Critical
    }

    fn issue_type(&self) -> IssueType {
        IssueType::Vulnerability
    }

    fn remediation_effort_minutes(&self) -> u32 {
        10
    }

    fn metadata(&self) -> vord_rules_engine::RuleMetadata {
        vord_rules_engine::RuleMetadata {
            description: "The random module is not cryptographically secure; its output is predictable from enough samples. Use the secrets module (secrets.token_urlsafe, secrets.choice) for tokens, passwords, and other security-sensitive values.".into(),
            tags: vec!["security".into(), "cryptography".into(), "cwe".into()],
            cwe: Some(330),
            produces_hotspots: false,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        if crate::common::is_test_file(file.path()) {
            return Vec::new();
        }
        ast.descendants()
            .filter(|n| *n.kind() == NodeKind::Assignment)
            .filter_map(|assignment| {
                let target = assignment.children().first()?;
                let value = assignment.children().last()?;
                if target.kind() != &NodeKind::Identifier || !looks_security_sensitive(target.text()) {
                    return None;
                }
                is_insecure_random_call(value).then(|| Finding::new("random module used to build a security-sensitive value; it is not cryptographically secure. Use the secrets module instead", assignment.span()))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use vord_rules_engine::AstParser;

    use super::*;

    fn findings(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.py", code, LanguageIdentifier::python()).unwrap();
        let ast = vord_parser_python::PythonParser::new()
            .parse(&file)
            .unwrap();
        UnsafeRandomModuleForSecurityRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_token_from_random_choice() {
        assert_eq!(
            findings("reset_token = random.choice(alphabet)\n").len(),
            1
        );
    }

    #[test]
    fn flags_otp_from_random_randint() {
        assert_eq!(findings("otp = random.randint(100000, 999999)\n").len(), 1);
    }

    #[test]
    fn allows_secrets_module() {
        assert!(findings("token = secrets.token_urlsafe(32)\n").is_empty());
    }

    #[test]
    fn allows_random_for_non_sensitive_name() {
        assert!(findings("dice_roll = random.randint(1, 6)\n").is_empty());
    }

    #[test]
    fn allows_system_random() {
        assert!(findings("token = random.SystemRandom().choice(alphabet)\n").is_empty());
    }

    /// Regression: `primary_key`/`sort_key`/etc. are ordinary DB/dict/sort
    /// vocabulary, not cryptographic material — the blanket "contains
    /// key" check used to flag these at Critical severity.
    #[test]
    fn allows_primary_key_from_random() {
        assert!(findings("primary_key = random.randint(1, 1000000)\n").is_empty());
    }

    #[test]
    fn allows_sort_key_from_random() {
        assert!(findings("sort_key = random.random()\n").is_empty());
    }

    #[test]
    fn allows_cache_key_from_random() {
        assert!(findings("cache_key = random.randint(1, 100)\n").is_empty());
    }

    /// A genuine security-sensitive "key" name must still be flagged —
    /// the benign-compound exclusion must not swallow real positives.
    #[test]
    fn flags_secret_key_from_random() {
        assert_eq!(findings("secret_key = random.choice(alphabet)\n").len(), 1);
    }

    #[test]
    fn flags_encryption_key_from_random() {
        assert_eq!(
            findings("encryption_key = random.randbytes(32)\n").len(),
            1
        );
    }
}
