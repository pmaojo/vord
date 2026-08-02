//! Rule: flags inline object/array literal default parameters in React component
//! parameter destructuring (e.g. `function Component({ items = [] })` or `({ config = {} })`).

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{declare_rule_id, Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

use crate::common::{is_jsx_kind, is_other};

declare_rule_id!(NoUnstableDefaultPropsRule, "react:no-unstable-default-props");

impl Rule for NoUnstableDefaultPropsRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, language: &LanguageIdentifier) -> bool {
        language.is_typescript() || language.is_javascript()
    }

    fn default_severity(&self) -> Severity {
        Severity::Major
    }

    fn issue_type(&self) -> IssueType {
        IssueType::CodeSmell
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "Using inline object or array literal defaults in component props destructuring creates a new reference on every render, causing unnecessary re-renders or infinite loops in dependencies.".into(),
            tags: vec!["react".into(), "performance".into(), "default-props".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        let mut findings = Vec::new();

        for node in ast.descendants() {
            if !is_function_node(node) {
                continue;
            }

            if !is_component_function(node) {
                continue;
            }

            let Some(params) = node.children().iter().find(|c| is_other(c, "formal_parameters")) else {
                continue;
            };

            for param_desc in params.descendants() {
                if is_other(param_desc, "object_assignment_pattern")
                    || is_other(param_desc, "assignment_pattern")
                    || is_other(param_desc, "pair_pattern")
                    || *param_desc.kind() == NodeKind::Assignment
                {
                    if let Some(default_val) = get_default_value_node(param_desc) {
                        if is_object_or_array_literal(default_val) {
                            findings.push(Finding::new(
                                "Avoid inline object or array literal default parameters in React components (e.g. `{ items = [] }`). Move static default objects/arrays outside the component.",
                                param_desc.span(),
                            ));
                        }
                    }
                }
            }
        }

        findings
    }
}

fn is_function_node(node: &AstNode) -> bool {
    *node.kind() == NodeKind::FunctionDef
        || is_other(node, "arrow_function")
        || is_other(node, "function_declaration")
        || is_other(node, "function_expression")
}

fn is_component_function(node: &AstNode) -> bool {
    // Check if function name is PascalCase
    for child in node.children() {
        if *child.kind() == NodeKind::Identifier {
            let text = child.text();
            if text.starts_with(|c: char| c.is_ascii_uppercase()) {
                return true;
            }
        }
    }

    // Check if text preceding function contains PascalCase variable name: `const Comp = ...`
    let text = node.text();
    if (text.contains("function") || text.contains("=>")) && node.descendants().any(is_jsx_kind) {
        return true;
    }

    false
}

fn get_default_value_node(assignment: &AstNode) -> Option<&AstNode> {
    let children = assignment.children();
    if children.len() >= 2 {
        // Return the last non-operator child
        children.iter().rev().find(|c| c.text() != "=")
    } else {
        None
    }
}

fn unwrap_parentheses(mut node: &AstNode) -> &AstNode {
    while is_other(node, "parenthesized_expression") {
        if let Some(inner) = node.children().iter().find(|c| c.text() != "(" && c.text() != ")") {
            node = inner;
        } else {
            break;
        }
    }
    node
}

fn is_object_or_array_literal(node: &AstNode) -> bool {
    let node = unwrap_parentheses(node);
    is_other(node, "object") || is_other(node, "array")
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
        NoUnstableDefaultPropsRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_inline_array_default_in_destructuring() {
        let code = "function Component({ items = [] }) { return <div>{items.length}</div>; }\n";
        let findings = check(code);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("inline object or array"));
    }

    #[test]
    fn flags_inline_object_default_in_destructuring() {
        let code = "const Component = ({ config = {} }) => { return <div>{config.name}</div>; };\n";
        let findings = check(code);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn allows_stable_reference_default_prop() {
        let code = "const DEFAULT_ITEMS = [];\nfunction Component({ items = DEFAULT_ITEMS }) { return <div>{items.length}</div>; }\n";
        let findings = check(code);
        assert!(findings.is_empty());
    }

    #[test]
    fn allows_primitive_defaults() {
        let code = "function Component({ count = 0, name = 'guest', enabled = true }) { return <div>{name}</div>; }\n";
        let findings = check(code);
        assert!(findings.is_empty());
    }

    #[test]
    fn ignores_non_component_functions() {
        let code = "function processItems(items = []) { return items.map(x => x * 2); }\n";
        let findings = check(code);
        assert!(findings.is_empty());
    }
}
