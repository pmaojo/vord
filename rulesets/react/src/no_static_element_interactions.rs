//! Rule: flags a non-interactive JSX element (`<div>`, `<article>`,
//! `<span>`, ...) that carries a mouse or keyboard event handler
//! (`onClick`, `onMouseDown`, `onKeyDown`, ...) without also declaring
//! `role` and `tabIndex` — the minimum needed for assistive technology to
//! recognize the element as interactive and for keyboard users to reach it.
//! `<button>`, `<a>`, form controls, and anything already carrying a `role`
//! are left alone: they're either natively interactive or have opted into
//! a specific interactive semantic already.

use vord_ast::{AstNode, LanguageIdentifier, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

use crate::common::{attribute_name, attributes, is_jsx_kind, tag_name};

/// Elements that are either natively interactive (get their own keyboard
/// and mouse semantics for free) or aren't rendered content at all, so an
/// event handler on them isn't a static-element-interaction violation.
const INTERACTIVE_OR_EXEMPT_TAGS: &[&str] = &[
    "a", "button", "input", "select", "textarea", "option", "label", "form", "audio", "video",
    "details", "summary", "dialog", "menuitem",
];

const EVENT_HANDLER_PREFIXES: &[&str] = &["onClick", "onMouseDown", "onMouseUp", "onKeyDown", "onKeyUp", "onKeyPress"];

fn has_event_handler(el: &AstNode) -> bool {
    attributes(el)
        .into_iter()
        .filter_map(attribute_name)
        .any(|name| EVENT_HANDLER_PREFIXES.contains(&name))
}

/// Both `role` (so assistive technology announces the element as
/// interactive) and `tabIndex` (so keyboard users can reach it) are
/// required — either alone leaves the other gap open, so this only
/// suppresses a finding when the element has opted into both.
fn has_interactive_role_and_tabindex(el: &AstNode) -> bool {
    let names: Vec<&str> = attributes(el).into_iter().filter_map(attribute_name).collect();
    names.contains(&"role") && names.contains(&"tabIndex")
}

fn flagged_element(el: &AstNode) -> Option<&AstNode> {
    if !is_jsx_kind(el) {
        return None;
    }
    let tag = tag_name(el)?;
    // A capitalized tag name is a custom component, not a raw DOM element —
    // its accessibility semantics are the component's own concern.
    if tag.chars().next().is_some_and(|c| c.is_ascii_uppercase()) {
        return None;
    }
    if INTERACTIVE_OR_EXEMPT_TAGS.contains(&tag) {
        return None;
    }
    if !has_event_handler(el) {
        return None;
    }
    (!has_interactive_role_and_tabindex(el)).then_some(el)
}

pub struct NoStaticElementInteractionsRule {
    id: RuleId,
}

impl NoStaticElementInteractionsRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("react:no-static-element-interactions").expect("valid rule id"),
        }
    }
}

impl Default for NoStaticElementInteractionsRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for NoStaticElementInteractionsRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, lang: &LanguageIdentifier) -> bool {
        *lang == LanguageIdentifier::typescript()
    }

    fn default_severity(&self) -> Severity {
        Severity::Major
    }

    fn issue_type(&self) -> IssueType {
        IssueType::CodeSmell
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "A non-interactive element (not a `<button>`, `<a>`, or form control) has a mouse/keyboard handler but no `role`/`tabIndex`, so assistive technology can't tell it's interactive and keyboard users can't reach it.".into(),
            tags: vec!["react".into(), "accessibility".into(), "a11y".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter_map(flagged_element)
            .map(|el| {
                Finding::new(
                    "non-interactive elements should not be assigned mouse or keyboard event listeners; add a `role` and `tabIndex`, or use an interactive element like `<button>`",
                    el.span(),
                )
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vord_ast::SourceFile;
    use vord_rules_engine::AstParser;

    fn check(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.tsx", code, LanguageIdentifier::typescript()).unwrap();
        let ast = vord_parser_typescript::TypeScriptParser::new()
            .parse(&file)
            .unwrap();
        NoStaticElementInteractionsRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_article_with_onclick_and_no_role() {
        let findings = check("const el = <article onClick={handleClick}>text</article>;\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_div_with_onkeydown_and_no_role() {
        let findings = check("const el = <div onKeyDown={handleKey}>text</div>;\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn allows_article_with_role_and_tabindex() {
        let findings = check(
            "const el = <article role=\"button\" tabIndex={0} onClick={handleClick} onKeyDown={handleKey}>text</article>;\n",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn flags_article_with_role_but_no_tabindex() {
        // `role` alone announces the semantic but keyboard users still
        // can't tab to it.
        let findings =
            check("const el = <article role=\"button\" onClick={handleClick}>text</article>;\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_article_with_tabindex_but_no_role() {
        // `tabIndex` alone makes it reachable but assistive technology
        // still doesn't know it's interactive.
        let findings =
            check("const el = <article tabIndex={0} onClick={handleClick}>text</article>;\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn allows_button_with_onclick() {
        let findings = check("const el = <button onClick={handleClick}>text</button>;\n");
        assert!(findings.is_empty());
    }

    #[test]
    fn allows_custom_component_with_onclick() {
        let findings = check("const el = <Card onClick={handleClick}>text</Card>;\n");
        assert!(findings.is_empty());
    }

    #[test]
    fn allows_static_element_without_handlers() {
        let findings = check("const el = <div className=\"box\">text</div>;\n");
        assert!(findings.is_empty());
    }
}
