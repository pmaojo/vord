//! Rule: flags an inline arrow function/object/array literal passed as a
//! prop to a custom component (a JSX tag starting with an uppercase
//! letter). A literal like this is a new reference on every render, which
//! defeats `React.memo`/`PureComponent` on the receiving component — its
//! shallow prop comparison sees "changed" every time no matter what.
//! Restricted to custom components (not native DOM elements, where the
//! same pattern is harmless) to keep this from firing on the common,
//! unproblematic `onClick={() => ...}` on a plain `<button>`.

use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use yunq_rules_engine::{Finding, Rule, RuleId, RuleMetadata, Severity};

use crate::common::{attribute_name, attributes, jsx_expression_inner, tag_name};

const EXCLUDED_ATTRS: &[&str] = &["style", "key", "ref"];

fn is_object_or_array_literal(node: &AstNode) -> bool {
    matches!(node.kind(), NodeKind::Other(k) if k.as_ref() == "object" || k.as_ref() == "array")
}

pub struct InlinePropFunctionInComponentRule {
    id: RuleId,
}

impl InlinePropFunctionInComponentRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("react:inline-prop-function-in-component").expect("valid rule id"),
        }
    }
}

impl Default for InlinePropFunctionInComponentRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for InlinePropFunctionInComponentRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, lang: &LanguageIdentifier) -> bool {
        *lang == LanguageIdentifier::typescript()
    }

    fn default_severity(&self) -> Severity {
        Severity::Minor
    }

    fn remediation_effort_minutes(&self) -> u32 {
        5
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "An inline function/object/array literal passed as a prop to a custom component is a new reference every render, defeating `React.memo`/`PureComponent` on the receiving side.".into(),
            tags: vec!["react".into(), "performance".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter(|el| tag_name(el).is_some_and(|t| t.starts_with(|c: char| c.is_ascii_uppercase())))
            .flat_map(|el| {
                attributes(el).into_iter().filter_map(|attr| {
                    let name = attribute_name(attr)?;
                    if EXCLUDED_ATTRS.contains(&name) {
                        return None;
                    }
                    let value = jsx_expression_inner(attr.children().get(1)?)?;
                    let shape = if *value.kind() == NodeKind::FunctionDef {
                        "function"
                    } else if is_object_or_array_literal(value) {
                        "object/array"
                    } else {
                        return None;
                    };
                    Some(Finding::new(
                        format!("prop `{name}` is an inline {shape} literal; it's a new reference on every render and defeats memoization on the receiving component"),
                        attr.span(),
                    ))
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
        let ast = yunq_parser_typescript::TypeScriptParser::new()
            .parse(&file)
            .unwrap();
        InlinePropFunctionInComponentRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_inline_arrow_function_prop_on_a_component() {
        let findings = check("const el = <Row onSelect={() => pick(id)} />;\n");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("onSelect"));
    }

    #[test]
    fn flags_inline_object_prop_on_a_component() {
        let findings = check("const el = <Widget config={{size: 10}} />;\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn allows_stable_reference_props() {
        let findings = check("const el = <Row onSelect={handleSelect} id={id} />;\n");
        assert!(findings.is_empty());
    }

    #[test]
    fn ignores_native_dom_elements() {
        let findings = check("const el = <button onClick={() => pick(id)}>go</button>;\n");
        assert!(findings.is_empty());
    }

    #[test]
    fn ignores_excluded_attributes() {
        let findings = check("const el = <Widget style={{color: 'red'}} />;\n");
        assert!(findings.is_empty());
    }
}
