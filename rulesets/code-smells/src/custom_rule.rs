//! A project-declared custom rule (`[[rules.custom]]` in `vord.toml`): a
//! regex a team writes to flag a convention vord has no built-in rule for,
//! without touching vord's source. Same shape as
//! `vord_rules_secrets::CustomSecretPatternRule` (real regex, matched line
//! by line) minus the secrets-specific framing (`IssueType::Vulnerability`,
//! CWE-798) — a custom rule is a code-smell/convention check by default,
//! not implicitly a vulnerability.

use regex::Regex;
use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile, Span};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

pub struct CustomRule {
    id: RuleId,
    message: String,
    pattern: Regex,
    severity: Severity,
}

impl CustomRule {
    /// Builds the rule, or `None` if `id_str` isn't a valid `namespace:code`
    /// rule id or `pattern` isn't a valid regex — a caller loading this from
    /// `vord.toml` should surface either as a configuration error, never
    /// silently drop the declared rule (a custom rule a team wrote and
    /// believes is active, but that never runs, is worse than one that
    /// fails the scan loudly at startup).
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
}

impl Rule for CustomRule {
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
        IssueType::CodeSmell
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
    use super::*;
    use vord_rules_engine::AstParser;

    fn check_ts(rule: &CustomRule, code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.ts", code, LanguageIdentifier::typescript()).unwrap();
        let ast = vord_parser_typescript::TypeScriptParser::new()
            .parse(&file)
            .unwrap();
        rule.check(&file, &ast)
    }

    #[test]
    fn rejects_invalid_regex() {
        assert!(CustomRule::new("custom:bad", "bad", "(unclosed", Severity::Major).is_none());
    }

    #[test]
    fn rejects_invalid_rule_id() {
        assert!(CustomRule::new("no-namespace", "msg", "foo", Severity::Major).is_none());
    }

    #[test]
    fn flags_a_matching_line_as_a_code_smell_not_a_vulnerability() {
        let rule = CustomRule::new(
            "custom:no-console-log",
            "Remove console.log before merging",
            r"console\.log\(",
            Severity::Minor,
        )
        .unwrap();

        let findings = check_ts(&rule, "console.log('debug');\n");
        assert_eq!(findings.len(), 1);
        assert_eq!(rule.issue_type(), IssueType::CodeSmell);
        assert_eq!(rule.default_severity(), Severity::Minor);
    }

    #[test]
    fn ignores_non_matching_code() {
        let rule = CustomRule::new(
            "custom:no-console-log",
            "Remove console.log before merging",
            r"console\.log\(",
            Severity::Minor,
        )
        .unwrap();

        assert!(check_ts(&rule, "logger.debug('fine');\n").is_empty());
    }

    #[test]
    fn a_real_regex_pattern_is_not_treated_as_a_literal_substring() {
        // `\bfetch\(` should not match `refetch(` — a literal-substring
        // implementation would; this proves the pattern is really compiled
        // as a regex.
        let rule = CustomRule::new(
            "custom:no-bare-fetch",
            "fetch only allowed in the api adapter",
            r"\bfetch\(",
            Severity::Major,
        )
        .unwrap();

        assert!(check_ts(&rule, "refetch();\n").is_empty());
        assert_eq!(check_ts(&rule, "fetch('/x');\n").len(), 1);
    }
}
