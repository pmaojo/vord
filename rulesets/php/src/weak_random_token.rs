use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use yunq_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

const SENSITIVE_NAME_MARKERS: &[&str] = &["token", "password", "passwd", "secret", "apikey", "session"];
const WEAK_RANDOM_MARKERS: &[&str] = &["rand(", "mt_rand(", "uniqid("];

fn looks_sensitive(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    SENSITIVE_NAME_MARKERS.iter().any(|marker| lower.contains(marker))
}

fn uses_weak_random(value: &AstNode) -> bool {
    WEAK_RANDOM_MARKERS.iter().any(|marker| value.subtree_contains_text(marker))
}

fn flagged_target(assignment: &AstNode) -> Option<&AstNode> {
    if *assignment.kind() != NodeKind::Assignment {
        return None;
    }
    let target = assignment.first_child()?;
    if *target.kind() != NodeKind::Identifier || !looks_sensitive(target.text()) {
        return None;
    }
    assignment.children().iter().skip(1).any(uses_weak_random).then_some(target)
}

/// `rand()`/`mt_rand()`/`uniqid()` are not cryptographically secure — their
/// output is predictable (a linear PRNG seeded from time, in `uniqid()`'s
/// case literally the microsecond timestamp) — so building a token,
/// password, secret, API key, or session id from one lets an attacker
/// reconstruct or brute-force it. Use `random_bytes()`/`random_int()` (or
/// `bin2hex(random_bytes(...))` for a hex token) instead.
pub struct WeakRandomTokenRule {
    id: RuleId,
}

impl WeakRandomTokenRule {
    pub fn new() -> Self {
        Self { id: RuleId::new("php:weak-random-token").expect("valid rule id") }
    }
}

impl Default for WeakRandomTokenRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for WeakRandomTokenRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, language: &LanguageIdentifier) -> bool {
        *language == LanguageIdentifier::php()
    }

    fn default_severity(&self) -> Severity {
        Severity::Critical
    }

    fn issue_type(&self) -> IssueType {
        IssueType::Vulnerability
    }

    fn metadata(&self) -> yunq_rules_engine::RuleMetadata {
        yunq_rules_engine::RuleMetadata {
            description: "`rand()`/`mt_rand()`/`uniqid()` are not cryptographically secure; \
                using one to build a token, password, secret, API key, or session id makes \
                that value predictable. Use `random_bytes()`/`random_int()` instead."
                .into(),
            tags: vec!["security".into(), "php".into()],
            cwe: Some(338),
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter_map(flagged_target)
            .map(|target| {
                Finding::new(
                    format!(
                        "`{}` is built from a non-cryptographic random source; use \
                        `random_bytes()`/`random_int()` instead",
                        target.text()
                    ),
                    target.span(),
                )
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use yunq_ast::SourceFile;
    use yunq_rules_engine::AstParser;

    use super::*;

    fn check(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.php", code, LanguageIdentifier::php()).unwrap();
        let ast = yunq_parser_php::PhpParser::new().parse(&file).unwrap();
        WeakRandomTokenRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_token_from_mt_rand() {
        assert_eq!(check("<?php\n$token = md5(mt_rand());\n").len(), 1);
    }

    #[test]
    fn flags_session_id_from_uniqid() {
        assert_eq!(check("<?php\n$sessionId = uniqid();\n").len(), 1);
    }

    #[test]
    fn ignores_secure_random_source() {
        assert!(check("<?php\n$token = bin2hex(random_bytes(32));\n").is_empty());
    }

    #[test]
    fn ignores_unrelated_variable_names() {
        assert!(check("<?php\n$jitter = rand(0, 100);\n").is_empty());
    }
}
