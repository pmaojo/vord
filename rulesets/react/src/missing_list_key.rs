//! Rule: flags a `.map()` callback that returns JSX with no `key` prop at
//! all (including a shorthand `<>...</>` fragment, which can't carry one).
//! Without a key, React falls back to matching list children by position,
//! which is exactly the bug `react:array-index-key` warns about — except
//! here there isn't even an attempt.

use vord_ast::{AstNode, LanguageIdentifier, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

use crate::common::{
    find_attribute, is_jsx_kind, is_other, map_callback_functions, own_scope_descendants, tag_name,
    unwrap_parentheses,
};

/// True for a shorthand `<>...</>` fragment: tree-sitter-typescript parses
/// it as an ordinary `jsx_element` whose opening tag just has no name —
/// there's no dedicated `jsx_fragment` node kind in the wired grammar
/// version, only the empty tag name distinguishes it from a real element.
fn is_fragment_shorthand(el: &AstNode) -> bool {
    is_other(el, "jsx_fragment") || (is_other(el, "jsx_element") && tag_name(el).is_none())
}

/// The JSX element(s) a `.map()` callback actually hands back to React as
/// list children: the callback's own return value(s), unwrapped of
/// parentheses and (for an array-literal return) expanded one level. A JSX
/// element that merely appears *inside* the callback — e.g. tucked into an
/// object literal's property, to be rendered later by something else
/// entirely — is not a returned list child and must not be treated as one;
/// that mismatch is exactly what previously false-positived on a `.map()`
/// callback returning `{ key, card: <Foo/> }`.
fn map_callback_returned_roots(arrow: &AstNode) -> Vec<&AstNode> {
    let Some(body) = arrow.children().last() else {
        return Vec::new();
    };

    let return_values: Vec<&AstNode> = if is_other(body, "statement_block") {
        own_scope_descendants(body)
            .into_iter()
            .filter(|n| is_other(n, "return_statement"))
            .filter_map(|ret| ret.first_child())
            .collect()
    } else {
        vec![body]
    };

    let mut roots = Vec::new();
    for value in return_values {
        let value = unwrap_parentheses(value);
        if is_jsx_kind(value) {
            roots.push(value);
        } else if is_other(value, "array") {
            roots.extend(
                value
                    .children()
                    .iter()
                    .map(unwrap_parentheses)
                    .filter(|c| is_jsx_kind(c)),
            );
        }
    }
    roots
}

pub struct MissingListKeyRule {
    id: RuleId,
}

impl MissingListKeyRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("react:missing-list-key").expect("valid rule id"),
        }
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

    fn issue_type(&self) -> IssueType {
        IssueType::Bug
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
            .flat_map(map_callback_returned_roots)
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
    use vord_ast::SourceFile;
    use vord_rules_engine::AstParser;

    fn check(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.tsx", code, LanguageIdentifier::typescript()).unwrap();
        let ast = vord_parser_typescript::TypeScriptParser::new()
            .parse(&file)
            .unwrap();
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
        let findings =
            check("const els = items.map(item => <li key={item.id}>{item.name}</li>);\n");
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

    #[test]
    fn ignores_jsx_tucked_into_an_object_literal_property_instead_of_returned_as_a_list_child() {
        // The callback returns an object `{ key, card }`; the JSX lives in a
        // property value, not as the list child itself — rendered later
        // elsewhere with its own `key={key}`.
        let findings = check(
            "const cards = items.map((item) => ({\n  key: getRenderableCardKey(item),\n  card: <RenderableCard item={item} />,\n}));\n",
        );
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn flags_jsx_returned_from_inside_a_block_bodied_map_callback() {
        let findings = check(
            "const els = items.map((item) => {\n  return <li>{item.name}</li>;\n});\n",
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_each_jsx_element_of_a_directly_returned_array() {
        let findings = check(
            "const els = items.map((item) => [<li>{item.name}</li>, <span>{item.id}</span>]);\n",
        );
        assert_eq!(findings.len(), 2);
    }
}
