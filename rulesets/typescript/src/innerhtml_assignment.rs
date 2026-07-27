//! Rule: flags any assignment to `.innerHTML` outside JSX (JSX's
//! equivalent, `dangerouslySetInnerHTML`, is covered by
//! `react:dangerously-set-inner-html`). Setting `innerHTML` parses its
//! string as HTML and inserts it into the DOM with no escaping — a classic
//! DOM-based XSS sink the moment the value isn't fully trusted, static
//! markup. Flagged unconditionally (like its JSX counterpart) since even a
//! literal assignment can't be told apart here from one built from a
//! template that embeds external data.

use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use yunq_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

fn flagged_assignment(node: &AstNode) -> Option<&AstNode> {
    if *node.kind() != NodeKind::Assignment {
        return None;
    }
    let target = node.first_child()?;
    if *target.kind() != NodeKind::MemberAccess {
        return None;
    }
    let property = target.children().last()?;
    (*property.kind() == NodeKind::Identifier && property.text() == "innerHTML").then_some(node)
}

pub struct InnerHtmlAssignmentRule {
    id: RuleId,
}

impl InnerHtmlAssignmentRule {
    pub fn new() -> Self {
        Self { id: RuleId::new("typescript:innerhtml-assignment").expect("valid rule id") }
    }
}

impl Default for InnerHtmlAssignmentRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for InnerHtmlAssignmentRule {
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
            description: "Assigning to `.innerHTML` parses the value as HTML and inserts it into the DOM with no escaping, making it an XSS sink unless the markup is fully trusted and static.".into(),
            tags: vec!["typescript".into(), "security".into(), "xss".into()],
            cwe: Some(79),
            produces_hotspots: true,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter_map(flagged_assignment)
            .map(|n| Finding::hotspot("`.innerHTML` assignment injects raw HTML with no escaping — verify the value can never carry attacker-controlled markup", n.span()))
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
        let ast = yunq_parser_typescript::TypeScriptParser::new().parse(&file).unwrap();
        InnerHtmlAssignmentRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_direct_inner_html_assignment() {
        assert_eq!(check("el.innerHTML = data;\n").len(), 1);
    }

    #[test]
    fn flags_chained_inner_html_assignment() {
        assert_eq!(check("document.getElementById('x').innerHTML = data;\n").len(), 1);
    }

    #[test]
    fn allows_text_content_assignment() {
        assert!(check("el.textContent = data;\n").is_empty());
    }
}
