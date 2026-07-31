//! Rule: flags any use of `dangerouslySetInnerHTML`. It bypasses React's
//! automatic escaping and injects raw HTML into the DOM — a stored/reflected
//! XSS sink the moment the value isn't fully trusted, static markup.

use yunq_ast::{AstNode, LanguageIdentifier, SourceFile};
use yunq_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

use crate::common::{attribute_name, is_other};

pub struct DangerouslySetInnerHtmlRule {
    id: RuleId,
}

impl DangerouslySetInnerHtmlRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("react:dangerously-set-inner-html").expect("valid rule id"),
        }
    }
}

impl Default for DangerouslySetInnerHtmlRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for DangerouslySetInnerHtmlRule {
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
            description: "`dangerouslySetInnerHTML` bypasses React's escaping and injects raw HTML, making it an XSS sink unless the markup is fully trusted and static.".into(),
            tags: vec!["react".into(), "security".into(), "xss".into()],
            cwe: Some(79),
            produces_hotspots: true,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter(|n| is_other(n, "jsx_attribute"))
            .filter(|attr| attribute_name(attr) == Some("dangerouslySetInnerHTML"))
            .map(|attr| {
                Finding::hotspot(
                    "`dangerouslySetInnerHTML` injects raw HTML, bypassing React's escaping — verify the value can never carry attacker-controlled markup",
                    attr.span(),
                )
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use yunq_ast::SourceFile;
    use yunq_rules_engine::AstParser;

    fn check(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.tsx", code, LanguageIdentifier::typescript()).unwrap();
        let ast = yunq_parser_typescript::TypeScriptParser::new()
            .parse(&file)
            .unwrap();
        DangerouslySetInnerHtmlRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_dangerously_set_inner_html() {
        let findings = check("const el = <div dangerouslySetInnerHTML={{__html: html}} />;\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn allows_ordinary_children() {
        let findings = check("const el = <div>{text}</div>;\n");
        assert!(findings.is_empty());
    }
}
