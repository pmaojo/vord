//! Rule: flags `window.location`/`document.location`/`location` (or their
//! `.href`) assigned a non-literal value. The browser navigates to whatever
//! string ends up there, so if that value can carry external input
//! (a query param, a stored redirect target, ...) unvalidated, the page
//! sends the user to an attacker-chosen URL — an open redirect, often the
//! first step of a phishing chain. A string-literal assignment is exempted
//! since its destination is fixed at the call site.

use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use yunq_rules_engine::{
    Finding, IssueType, Rule, RuleId, RuleMetadata, Severity, declare_rule_id,
};

/// The finite set of navigation targets this rule recognizes — deliberately
/// an exact-text allowlist rather than "any `*.location`/`*.href`" so an
/// unrelated business object with its own `location`/`href` field (`job
/// .location = city`, `link.href = path`) is never mistaken for browser
/// navigation.
const LOCATION_TARGETS: &[&str] = &[
    "location",
    "location.href",
    "window.location",
    "window.location.href",
    "document.location",
    "document.location.href",
    "self.location",
    "self.location.href",
    "globalThis.location",
    "globalThis.location.href",
];

fn flagged_assignment(node: &AstNode) -> Option<&AstNode> {
    if *node.kind() != NodeKind::Assignment {
        return None;
    }
    let target = node.first_child()?;
    if !LOCATION_TARGETS.contains(&target.text()) {
        return None;
    }
    let value = node.children().get(1)?;
    (*value.kind() != NodeKind::StringLiteral).then_some(node)
}

declare_rule_id!(
    OpenRedirectLocationAssignmentRule,
    "typescript:open-redirect-location-assignment"
);

impl Rule for OpenRedirectLocationAssignmentRule {
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
            description: "Assigning a non-literal value to window.location/document.location navigates the browser to whatever that value is; unvalidated external input there is an open redirect.".into(),
            tags: vec!["typescript".into(), "security".into(), "owasp-a01".into()],
            cwe: Some(601),
            produces_hotspots: true,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter_map(flagged_assignment)
            .map(|n| Finding::hotspot("navigating to a non-literal URL here is an open redirect unless the value is validated against an allowlist", n.span()))
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
        OpenRedirectLocationAssignmentRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_window_location_assignment() {
        assert_eq!(check("window.location = userUrl;\n").len(), 1);
    }

    #[test]
    fn flags_window_location_href_assignment() {
        assert_eq!(check("window.location.href = userUrl;\n").len(), 1);
    }

    #[test]
    fn flags_bare_location_href_assignment() {
        assert_eq!(check("location.href = userUrl;\n").len(), 1);
    }

    #[test]
    fn allows_literal_url() {
        assert!(check("window.location = '/home';\n").is_empty());
    }

    #[test]
    fn allows_unrelated_location_field() {
        assert!(check("job.location = city;\n").is_empty());
    }
}
