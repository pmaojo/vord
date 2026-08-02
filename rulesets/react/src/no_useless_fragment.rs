//! Rule: flags unnecessary `<>...</>` or `<React.Fragment>...</React.Fragment>`
//! fragments that wrap a single JSX element child.

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{declare_rule_id, Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

use crate::common::{attributes, is_jsx_kind, is_other, opening_tag};

declare_rule_id!(NoUselessFragmentRule, "react:no-useless-fragment");

impl Rule for NoUselessFragmentRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, language: &LanguageIdentifier) -> bool {
        *language == LanguageIdentifier::typescript()
    }

    fn default_severity(&self) -> Severity {
        Severity::Minor
    }

    fn issue_type(&self) -> IssueType {
        IssueType::CodeSmell
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "Using a fragment (`<>...</>` or `<React.Fragment>...</React.Fragment>`) that contains only a single JSX element child is redundant and adds unnecessary noise.".into(),
            tags: vec!["react".into(), "style".into(), "clean-code".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        let mut findings = Vec::new();
        for node in ast.descendants() {
            if useless_fragment_single_child(node).is_some() {
                findings.push(Finding::new(
                    "Avoid useless `<>` / `<React.Fragment>` fragment wrapping a single JSX element child. Remove the fragment wrapper.",
                    node.span(),
                ));
            }
        }
        findings
    }
}

fn is_fragment(el: &AstNode) -> bool {
    if is_other(el, "jsx_fragment") {
        return true;
    }
    if is_other(el, "jsx_element") {
        if let Some(tag) = opening_tag(el) {
            if let Some(first_child) = tag.first_child() {
                let name = first_child.text().trim();
                if name == "Fragment" || name == "React.Fragment" {
                    return attributes(el).is_empty();
                } else if name == "<" || name == ">" || name.is_empty() {
                    return true;
                }
            } else {
                return true;
            }
        }
    }
    false
}

fn useless_fragment_single_child(el: &AstNode) -> Option<&AstNode> {
    if !is_fragment(el) {
        return None;
    }

    let real_children: Vec<&AstNode> = el
        .children()
        .iter()
        .filter(|c| {
            if is_jsx_kind(c) || is_other(c, "jsx_expression") {
                return true;
            }
            if is_other(c, "jsx_text") || *c.kind() == NodeKind::StringLiteral {
                return !c.text().trim().is_empty();
            }
            false
        })
        .collect();

    if real_children.len() == 1 && is_jsx_kind(real_children[0]) {
        Some(real_children[0])
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vord_rules_engine::AstParser;

    fn check(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.tsx", code, LanguageIdentifier::typescript()).unwrap();
        let ast = vord_parser_typescript::TypeScriptParser::new()
            .parse(&file)
            .unwrap();
        NoUselessFragmentRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_shorthand_fragment_wrapping_single_element() {
        let code = "const el = <><div>Hello</div></>;\n";
        let findings = check(code);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("useless"));
    }

    #[test]
    fn flags_react_fragment_wrapping_single_element() {
        let code = "const el = <React.Fragment><span>Hello</span></React.Fragment>;\n";
        let findings = check(code);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_imported_fragment_wrapping_single_element() {
        let code = "const el = <Fragment><h1>Title</h1></Fragment>;\n";
        let findings = check(code);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn allows_fragment_with_multiple_children() {
        let code = "const el = <><div>One</div><div>Two</div></>;\n";
        let findings = check(code);
        assert!(findings.is_empty());
    }

    #[test]
    fn allows_fragment_with_key_attribute() {
        let code = "const el = <React.Fragment key={item.id}><Child /></React.Fragment>;\n";
        let findings = check(code);
        assert!(findings.is_empty());
    }

    #[test]
    fn allows_fragment_with_text_and_element() {
        let code = "const el = <>Text <div>Child</div></>;\n";
        let findings = check(code);
        assert!(findings.is_empty());
    }
}
