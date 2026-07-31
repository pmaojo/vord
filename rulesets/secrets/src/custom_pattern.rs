//! User-configurable secret pattern: lets teams describe a private or
//! self-hosted service's token/credential format as a regex, without
//! touching yunq source code — the same extensibility point the OWASP
//! ruleset already offers for generic patterns
//! (`yunq_rules_owasp::CustomPatternRule`), specialized here for secrets so
//! findings carry the right tags/CWE and severity default.

use regex::Regex;
use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile, Span};
use yunq_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

/// A secret-detection rule built from a user-supplied regex pattern. Wire
/// this up from `yunq.toml`/quality-profile parameters (one instance per
/// configured pattern) to detect private-service credentials the built-in
/// provider rules don't know about.
pub struct CustomSecretPatternRule {
    id: RuleId,
    message: String,
    pattern: Regex,
    severity: Severity,
}

impl CustomSecretPatternRule {
    /// Builds the rule, or returns `None` if `id_str` isn't a valid
    /// `namespace:code` rule id or `pattern` isn't a valid regex — callers
    /// loading this from user configuration should surface that as a
    /// configuration error rather than panicking.
    pub fn new(
        id_str: &str,
        message: impl Into<String>,
        pattern: &str,
        severity: Severity,
    ) -> Option<Self> {
        let id = RuleId::new(id_str).ok()?;
        let pattern = Regex::new(pattern).ok()?;
        Some(Self {
            id,
            message: message.into(),
            pattern,
            severity,
        })
    }

    /// Convenience constructor for the default id
    /// (`secrets:custom-secret-pattern`) when only one custom pattern is
    /// configured.
    pub fn with_default_id(
        message: impl Into<String>,
        pattern: &str,
        severity: Severity,
    ) -> Option<Self> {
        Self::new("secrets:custom-secret-pattern", message, pattern, severity)
    }
}

impl Rule for CustomSecretPatternRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, _language: &LanguageIdentifier) -> bool {
        true
    }

    fn default_severity(&self) -> Severity {
        self.severity
    }

    fn issue_type(&self) -> IssueType {
        IssueType::Vulnerability
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: format!("User-defined secret pattern: {}", self.message),
            tags: vec!["security".into(), "secrets".into(), "custom".into()],
            cwe: Some(798),
            produces_hotspots: false,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        if *ast.kind() != NodeKind::SourceUnit {
            return Vec::new();
        }

        let mut findings = Vec::new();
        for (idx, line) in file.content().lines().enumerate() {
            if self.pattern.is_match(line) {
                findings.push(Finding::new(
                    &self.message,
                    Span::new(
                        (idx + 1) as u32,
                        1,
                        (idx + 1) as u32,
                        line.len().max(1) as u32,
                    ),
                ));
            }
        }
        findings
    }
}

#[cfg(test)]
mod tests {
    use yunq_ast::SourceFile;
    use yunq_rules_engine::AstParser;

    use super::*;

    fn check_ts(rule: &CustomSecretPatternRule, code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.ts", code, LanguageIdentifier::typescript()).unwrap();
        let ast = yunq_parser_typescript::TypeScriptParser::new()
            .parse(&file)
            .unwrap();
        rule.check(&file, &ast)
    }

    #[test]
    fn rejects_invalid_regex() {
        assert!(
            CustomSecretPatternRule::with_default_id("bad", "(unclosed", Severity::Major).is_none()
        );
    }

    #[test]
    fn rejects_invalid_rule_id() {
        assert!(
            CustomSecretPatternRule::new("no-namespace", "msg", "foo", Severity::Major).is_none()
        );
    }

    #[test]
    fn flags_internal_service_token_format() {
        // Example private/self-hosted service token: `acme_live_<32 hex chars>`.
        let rule = CustomSecretPatternRule::with_default_id(
            "hardcoded Acme internal service token",
            r"\bacme_live_[0-9a-f]{32}\b",
            Severity::Blocker,
        )
        .unwrap();

        let code = "const token = \"acme_live_0123456789abcdef0123456789abcdef\";\n";
        let findings = check_ts(&rule, code);
        assert_eq!(findings.len(), 1);
        assert_eq!(rule.default_severity(), Severity::Blocker);
    }

    #[test]
    fn ignores_non_matching_code() {
        let rule = CustomSecretPatternRule::with_default_id(
            "hardcoded Acme internal service token",
            r"\bacme_live_[0-9a-f]{32}\b",
            Severity::Blocker,
        )
        .unwrap();

        assert!(check_ts(&rule, "const token = \"acme_test_deadbeef\";\n").is_empty());
    }

    #[test]
    fn supports_custom_rule_id() {
        let rule = CustomSecretPatternRule::new(
            "secrets:internal-acme-token",
            "hardcoded Acme internal service token",
            r"\bacme_live_[0-9a-f]{32}\b",
            Severity::Critical,
        )
        .unwrap();
        assert_eq!(rule.id().as_str(), "secrets:internal-acme-token");
    }
}
