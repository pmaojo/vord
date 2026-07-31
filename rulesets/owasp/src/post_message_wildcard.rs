//! Rule: flags `postMessage(..., "*")`.

use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use yunq_rules_engine::{
    declare_rule_id, Finding, IssueType, Rule, RuleId, RuleMetadata, Severity,
};

fn is_wildcard_post_message(call: &AstNode) -> bool {
    let Some(callee) = call.first_child() else {
        return false;
    };

    let name = match callee.kind() {
        NodeKind::MemberAccess => {
            if let Some(prop) = callee.children().get(1) {
                prop.text()
            } else {
                return false;
            }
        }
        NodeKind::Identifier => callee.text(),
        _ => return false,
    };

    if name != "postMessage" {
        return false;
    }

    let Some(args) = call.children().iter().find(|c| match c.kind() {
        NodeKind::Other(k) => k.as_ref() == "arguments",
        _ => false,
    }) else {
        return false;
    };

    if let Some(target_origin) = args.children().get(1) {
        return target_origin.text() == "'*'"
            || target_origin.text() == "\"*\""
            || target_origin.text() == "`*`";
    }

    false
}

declare_rule_id!(PostMessageWildcardRule, "owasp:post-message-wildcard");

impl Rule for PostMessageWildcardRule {
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
            description: "Using '*' as the target origin in postMessage allows any website to intercept the message, which can lead to sensitive data exposure. Specify an exact target origin instead.".into(),
            tags: vec!["security".into(), "owasp".into(), "cwe-346".into()],
            cwe: Some(346),
            produces_hotspots: false,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        if yunq_rules_engine::is_test_only_path(file.path()) {
            return Vec::new();
        }
        ast.descendants()
            .filter(|n| *n.kind() == NodeKind::Call)
            .filter(|call| is_wildcard_post_message(call))
            .map(|call| {
                Finding::new(
                    "postMessage with '*' target origin exposes data to any origin",
                    call.span(),
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
        let file = SourceFile::new("t.ts", code, LanguageIdentifier::typescript()).unwrap();
        let ast = yunq_parser_typescript::TypeScriptParser::new()
            .parse(&file)
            .unwrap();
        PostMessageWildcardRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_window_post_message_wildcard() {
        assert_eq!(check("window.postMessage(secret, '*');\n").len(), 1);
    }

    #[test]
    fn flags_post_message_wildcard() {
        assert_eq!(check("postMessage(secret, '*');\n").len(), 1);
    }

    #[test]
    fn allows_specific_origin() {
        assert!(check("window.postMessage(secret, 'https://example.com');\n").is_empty());
    }
}
