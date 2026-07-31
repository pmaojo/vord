//! Rule: flags `localStorage.setItem`/`sessionStorage.setItem` calls whose
//! key name suggests the value is security-sensitive (a token, password,
//! secret, API key, or session id). Web Storage is plain text, readable by
//! any script running on the page (including via XSS) and never expires on
//! its own (`localStorage`) or clears only at tab close (`sessionStorage`)
//! — neither offers the protection a credential needs.

use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use yunq_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

use crate::common::call_arguments;

const SENSITIVE_KEY_MARKERS: &[&str] = &[
    "token", "password", "passwd", "secret", "apikey", "session", "auth",
];

fn looks_sensitive(key_text: &str) -> bool {
    let lower = key_text.to_ascii_lowercase();
    SENSITIVE_KEY_MARKERS
        .iter()
        .any(|marker| lower.contains(marker))
}

fn flagged_call(node: &AstNode) -> Option<&AstNode> {
    if *node.kind() != NodeKind::Call {
        return None;
    }
    let callee = node.first_child()?;
    if *callee.kind() != NodeKind::MemberAccess {
        return None;
    }
    let receiver = callee.first_child()?;
    let property = callee.children().last()?;
    let is_web_storage = matches!(receiver.text(), "localStorage" | "sessionStorage");
    let is_set_item = *property.kind() == NodeKind::Identifier && property.text() == "setItem";
    if !(is_web_storage && is_set_item) {
        return None;
    }
    let key = call_arguments(node).first()?;
    (*key.kind() == NodeKind::StringLiteral && looks_sensitive(key.text())).then_some(node)
}

pub struct SensitiveDataInWebStorageRule {
    id: RuleId,
}

impl SensitiveDataInWebStorageRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("typescript:sensitive-data-in-web-storage").expect("valid rule id"),
        }
    }
}

impl Default for SensitiveDataInWebStorageRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for SensitiveDataInWebStorageRule {
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
            description: "localStorage/sessionStorage store plain text readable by any script on the page (including via XSS); storing a token, password, secret, or session id there exposes it to script-injection attacks.".into(),
            tags: vec!["typescript".into(), "security".into(), "cwe".into()],
            cwe: Some(312),
            produces_hotspots: true,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter_map(flagged_call)
            .map(|n| Finding::hotspot("storing what looks like a credential in Web Storage exposes it to any script on the page, including via XSS", n.span()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use yunq_ast::SourceFile;
    use yunq_rules_engine::AstParser;

    use super::*;

    fn check(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.ts", code, LanguageIdentifier::typescript()).unwrap();
        let ast = yunq_parser_typescript::TypeScriptParser::new()
            .parse(&file)
            .unwrap();
        SensitiveDataInWebStorageRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_local_storage_token() {
        assert_eq!(check("localStorage.setItem('token', t);\n").len(), 1);
    }

    #[test]
    fn flags_session_storage_password() {
        assert_eq!(check("sessionStorage.setItem('password', p);\n").len(), 1);
    }

    #[test]
    fn allows_non_sensitive_key() {
        assert!(check("localStorage.setItem('theme', 'dark');\n").is_empty());
    }

    #[test]
    fn allows_dynamic_key_name() {
        assert!(check("localStorage.setItem(key, value);\n").is_empty());
    }

    #[test]
    fn allows_unrelated_object_set_item() {
        assert!(check("cache.setItem('token', t);\n").is_empty());
    }
}
