//! Rule: flags `.map((item, index) => ...)` callbacks that use the loop
//! index as (or inside) a JSX `key`. Keys must identify an item stably
//! across reorders/insertions/deletions; the index doesn't — it identifies
//! a *position*, so React can misattribute state/DOM nodes to the wrong
//! item after the list changes shape.

use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use yunq_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

use crate::common::{attribute_value, find_attribute, is_jsx_kind, map_callback_functions, own_scope_descendants};

/// The name of a `.map()` callback's second (index) parameter, if it takes
/// one — `formal_parameters`' children are each a plain `Identifier` (a bare
/// destructure-free parameter) or an `Other` wrapper (`required_parameter`,
/// `optional_parameter`) around one.
fn index_param_name(arrow: &AstNode) -> Option<&str> {
    let params = arrow.first_child().filter(|c| matches!(c.kind(), NodeKind::Other(k) if k == "formal_parameters"))?;
    let index = params.children().get(1)?;
    let name_node = if *index.kind() == NodeKind::Identifier { index } else { index.first_child()? };
    (*name_node.kind() == NodeKind::Identifier).then(|| name_node.text())
}

pub struct ArrayIndexKeyRule {
    id: RuleId,
}

impl ArrayIndexKeyRule {
    pub fn new() -> Self {
        Self { id: RuleId::new("react:array-index-key").expect("valid rule id") }
    }
}

impl Default for ArrayIndexKeyRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for ArrayIndexKeyRule {
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
            description: "A `.map()` callback's `key` prop is derived from the loop index, which identifies a list position rather than the item — reorders/insertions/deletions can misattribute state to the wrong item.".into(),
            tags: vec!["react".into(), "correctness".into(), "lists".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        let mut findings = Vec::new();
        for arrow in map_callback_functions(ast) {
            let Some(index_name) = index_param_name(arrow) else { continue };
            for node in own_scope_descendants(arrow) {
                if !is_jsx_kind(node) {
                    continue;
                }
                let Some(key_attr) = find_attribute(node, "key") else { continue };
                let Some(value) = attribute_value(key_attr) else { continue };
                // An exact-identifier match (not a raw substring search) so
                // a single-letter index name like `i` can't false-positive
                // against an unrelated key such as `item.id`.
                if value.descendants().any(|n| *n.kind() == NodeKind::Identifier && n.text() == index_name) {
                    findings.push(Finding::new(
                        format!("list item `key` is derived from the loop index `{index_name}`, not a stable per-item id"),
                        key_attr.span(),
                    ));
                }
            }
        }
        findings
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
        ArrayIndexKeyRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_direct_index_as_key() {
        let findings = check("const els = items.map((item, index) => <li key={index}>{item}</li>);\n");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("index"));
    }

    #[test]
    fn flags_index_used_inside_a_template_key() {
        let findings = check(
            "const els = items.map((item, i) => <li key={`item-${i}`}>{item}</li>);\n",
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn allows_stable_id_as_key() {
        let findings = check("const els = items.map((item, index) => <li key={item.id}>{item.name}</li>);\n");
        assert!(findings.is_empty());
    }

    #[test]
    fn ignores_map_without_index_parameter() {
        let findings = check("const els = items.map(item => <li key={item.id}>{item.name}</li>);\n");
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_confuse_a_single_letter_index_name_with_a_substring_of_the_key() {
        // Index param is `i`; the key is `item.id`, which contains the
        // letter "i" several times but references no such identifier.
        let findings = check("const els = items.map((item, i) => <li key={item.id}>{item.name}</li>);\n");
        assert!(findings.is_empty());
    }

    #[test]
    fn ignores_non_map_calls() {
        let findings = check("const els = items.filter((item, index) => <li key={index}>{item}</li>);\n");
        assert!(findings.is_empty());
    }
}
