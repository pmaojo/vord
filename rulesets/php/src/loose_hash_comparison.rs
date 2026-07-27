use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use yunq_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

use crate::common::{callee_node, is_other, operator_between};

const HASH_FUNCTIONS: &[&str] = &["md5", "sha1", "hash", "crc32"];

fn is_hash_call(node: &AstNode) -> bool {
    *node.kind() == NodeKind::Call && callee_node(node).is_some_and(|c| *c.kind() == NodeKind::Identifier && HASH_FUNCTIONS.contains(&c.text()))
}

/// PHP's loose `==`/`!=` compares two numeric-looking strings as numbers.
/// `md5()`/`sha1()`/`hash()`/`crc32()` all return hex strings, and some
/// fraction of them happen to match PHP's scientific-notation number
/// format (`"0e1234...")` — every one of those compares loosely-equal to
/// every other one, and to plain `0`. That's the "magic hash"
/// authentication bypass: an attacker who can influence one side of the
/// comparison (or who just knows a same-shaped hash) can make an
/// unrelated-looking hash match. Use `===`/`!==` (or `hash_equals()` for a
/// constant-time comparison of secrets) instead.
pub struct LooseHashComparisonRule {
    id: RuleId,
}

impl LooseHashComparisonRule {
    pub fn new() -> Self {
        Self { id: RuleId::new("php:loose-hash-comparison").expect("valid rule id") }
    }
}

impl Default for LooseHashComparisonRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for LooseHashComparisonRule {
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

    fn remediation_effort_minutes(&self) -> u32 {
        15
    }

    fn metadata(&self) -> yunq_rules_engine::RuleMetadata {
        yunq_rules_engine::RuleMetadata {
            description: "Comparing a hash (`md5`/`sha1`/`hash`/`crc32`) with `==`/`!=` is \
                vulnerable to PHP's \"magic hash\" type-juggling bug: two different hashes that \
                both happen to look like scientific notation (`\"0e...\"`) compare equal. Use \
                `===`/`!==`, or `hash_equals()` for a constant-time comparison of secrets."
                .into(),
            tags: vec!["security".into(), "php".into()],
            cwe: Some(697),
            produces_hotspots: false,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter(|n| is_other(n.kind(), "binary_expression"))
            .filter_map(|expr| match expr.children() {
                [left, right] => Some((expr, left, right)),
                _ => None,
            })
            .filter(|(_, left, right)| is_hash_call(left) || is_hash_call(right))
            .filter_map(|(expr, left, right)| {
                let op = operator_between(file.content(), left, right);
                (op == "==" || op == "!=").then(|| {
                    Finding::new(
                        format!(
                            "`{}` compares a hash with `{op}`, which is vulnerable to PHP's \
                            \"magic hash\" type-juggling bug; use `===`/`!==` or `hash_equals()` \
                            instead",
                            expr.text()
                        ),
                        expr.span(),
                    )
                })
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
        LooseHashComparisonRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_md5_loose_equality() {
        assert_eq!(check("<?php\nif (md5($a) == $hash) { ok(); }\n").len(), 1);
    }

    #[test]
    fn flags_sha1_loose_inequality_reversed_operands() {
        assert_eq!(check("<?php\nif ($hash != sha1($a)) { ok(); }\n").len(), 1);
    }

    #[test]
    fn ignores_strict_comparison() {
        assert!(check("<?php\nif (md5($a) === $hash) { ok(); }\n").is_empty());
    }

    #[test]
    fn ignores_unrelated_loose_comparison() {
        assert!(check("<?php\nif ($a == $b) { ok(); }\n").is_empty());
    }
}
