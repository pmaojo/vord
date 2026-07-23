//! Rule: flags a `.map()` callback that returns JSX with no `key` prop at
//! all (including a shorthand `<>...</>` fragment, which can't carry one).
//! Without a key, React falls back to matching list children by position,
//! which is exactly the bug `react:array-index-key` warns about — except
//! here there isn't even an attempt.

use yunq_ast::{AstNode, LanguageIdentifier, SourceFile};
use yunq_rules_engine::{Finding, Rule, RuleId, RuleMetadata, Severity};

use crate::common::{find_attribute, is_jsx_kind, is_other, map_callback_functions, own_scope_descendants, tag_name};

/// True for a shorthand `<>...</>` fragment: tree-sitter-typescript parses
/// it as an ordinary `jsx_element` whose opening tag just has no name —
/// there's no dedicated `jsx_fragment` node kind in the wired grammar
/// version, only the empty tag name distinguishes it from a real element.
fn is_fragment_shorthand(el: &AstNode) -> bool {
    is_other(el, "jsx_fragment") || (is_other(el, "jsx_element") && tag_name(el).is_none())
}

pub struct MissingListKeyRule {
    id: RuleId,
}

impl MissingListKeyRule {
    pub fn new() -> Self {
        Self { id: RuleId::new("react:missing-list-key").expect("valid rule id") }
    }
}

impl Default for MissingListKeyRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for MissingListKeyRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, lang: &LanguageIdentifier) -> bool {
        *lang == LanguageIdentifier::typescript()
    }

    fn default_severity(&self) -> Severity {
        Severity::Major
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "A `.map()` callback returns JSX with no `key` prop, so React matches the resulting list children by position instead of identity.".into(),
            tags: vec!["react".into(), "correctness".into(), "lists".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        map_callback_functions(ast)
            .into_iter()
            // The first JSX node in source order within the callback's own
            // scope is its returned element — a parent always precedes its
            // children in this pre-order walk, so nested JSX inside it never
            // gets considered as its own separate candidate.
            .filter_map(|arrow| own_scope_descendants(arrow).into_iter().find(|n| is_jsx_kind(n)))
            .filter_map(|root| {
                if is_fragment_shorthand(root) {
                    return Some(Finding::new(
                        "list item is a `<>...</>` fragment shorthand, which can't carry a `key`; use `<React.Fragment key={...}>` explicitly",
                        root.span(),
                    ));
                }
                find_attribute(root, "key").is_none().then(|| {
                    Finding::new("list item returned from `.map()` is missing a `key` prop", root.span())
                })
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
        let ast = yunq_parser_typescript::TypeScriptParser::new().parse(&file).unwrap();
        MissingListKeyRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_map_callback_without_key() {
        let findings = check("const els = items.map(item => <li>{item.name}</li>);\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_fragment_shorthand() {
        let findings = check("const els = items.map(item => <>{item.name}</>);\n");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("Fragment"));
    }

    #[test]
    fn allows_map_callback_with_key() {
        let findings = check("const els = items.map(item => <li key={item.id}>{item.name}</li>);\n");
        assert!(findings.is_empty());
    }

    #[test]
    fn ignores_map_callback_not_returning_jsx() {
        let findings = check("const ids = items.map(item => item.id);\n");
        assert!(findings.is_empty());
    }

    #[test]
    fn only_the_outermost_element_is_considered() {
        // The outer `<li>` carries the key; an inner `<span>` without one is
        // not a separate violation.
        let findings = check(
            "const els = items.map(item => <li key={item.id}><span>{item.name}</span></li>);\n",
        );
        assert!(findings.is_empty());
    }
}
