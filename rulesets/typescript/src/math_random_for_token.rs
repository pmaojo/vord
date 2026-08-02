//! Rule: flags `Math.random()` used to build a value whose declared/assigned
//! name suggests it's security-sensitive (a token, password, secret, API
//! key, or session id). `Math.random()` is not cryptographically secure —
//! its output is predictable enough to reconstruct or brute-force — so any
//! such value must come from `crypto.randomBytes`/`crypto.randomUUID`/
//! `crypto.getRandomValues` instead.

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{
    Finding, IssueType, Rule, RuleId, RuleMetadata, Severity, declare_rule_id,
};

const SENSITIVE_NAME_MARKERS: &[&str] =
    &["token", "password", "passwd", "secret", "apikey", "session"];

fn looks_sensitive(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    SENSITIVE_NAME_MARKERS
        .iter()
        .any(|marker| lower.contains(marker))
}

fn flagged_target(decl: &AstNode) -> Option<&AstNode> {
    if !matches!(decl.kind(), NodeKind::VariableDecl | NodeKind::Assignment) {
        return None;
    }
    let target = decl.first_child()?;
    if !matches!(target.kind(), NodeKind::Identifier | NodeKind::MemberAccess) {
        return None;
    }
    if !looks_sensitive(target.text()) {
        return None;
    }
    decl.children()
        .iter()
        .skip(1)
        .any(|value| value.subtree_contains_text("Math.random("))
        .then_some(target)
}

declare_rule_id!(MathRandomForTokenRule, "typescript:math-random-for-token");

impl Rule for MathRandomForTokenRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, lang: &LanguageIdentifier) -> bool {
        *lang == LanguageIdentifier::typescript()
    }

    fn default_severity(&self) -> Severity {
        Severity::Critical
    }

    fn issue_type(&self) -> IssueType {
        IssueType::Vulnerability
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "`Math.random()` is not cryptographically secure; using it to build a token, password, secret, or session id makes that value predictable. Use `crypto.randomBytes`/`crypto.randomUUID`/`crypto.getRandomValues` instead.".into(),
            tags: vec!["typescript".into(), "security".into(), "cwe".into()],
            cwe: Some(338),
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter_map(flagged_target)
            .map(|target| {
                Finding::new(
                    format!("`{}` is built from `Math.random()`, which is not cryptographically secure; use `crypto.randomBytes`/`crypto.randomUUID` instead", target.text()),
                    target.span(),
                )
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
        let file = SourceFile::new("t.ts", code, LanguageIdentifier::typescript()).unwrap();
        let ast = vord_parser_typescript::TypeScriptParser::new()
            .parse(&file)
            .unwrap();
        MathRandomForTokenRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_token_built_from_math_random() {
        let findings = check("const token = Math.random().toString(36);\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_password_assignment() {
        let findings = check("user.password = Math.random().toString(36);\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_session_id() {
        assert_eq!(check("const sessionId = String(Math.random());\n").len(), 1);
    }

    #[test]
    fn allows_math_random_for_unrelated_names() {
        assert!(check("const jitter = Math.random() * 100;\n").is_empty());
    }

    #[test]
    fn allows_crypto_random_bytes_for_token() {
        assert!(check("const token = crypto.randomBytes(32).toString('hex');\n").is_empty());
    }
}
