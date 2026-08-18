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

fn looks_security_sensitive(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    SENSITIVE_WORDS.iter().any(|w| lower.contains(w))
        || (lower.contains("key") && !lower.ends_with("keys"))
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
}
