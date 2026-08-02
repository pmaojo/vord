//! Rule: flags React component definitions created inside the render body of
//! another React component. Defining a component inside another component
//! recreates the inner component type on every render, resetting state and DOM
//! elements.

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{declare_rule_id, Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

use crate::common::{callee_name, is_hook_name, is_jsx_kind, own_scope_descendants};

declare_rule_id!(NoNestedComponentsRule, "react:no-nested-components");

impl Rule for NoNestedComponentsRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, language: &LanguageIdentifier) -> bool {
        *language == LanguageIdentifier::typescript()
    }

    fn default_severity(&self) -> Severity {
        Severity::Major
    }

    fn issue_type(&self) -> IssueType {
        IssueType::CodeSmell
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "Defining a React component function inside another component's render body causes the component type to be recreated on every render, resetting state and DOM elements.".into(),
            tags: vec!["react".into(), "performance".into(), "correctness".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        let mut findings = Vec::new();
        walk(ast, None, false, false, &mut findings);
        findings
    }
}

#[derive(Clone, Copy)]
struct OuterComponentContext<'a> {
    component_name: &'a str,
}

fn function_declaration_name(func: &AstNode) -> Option<&str> {
    if !func.text().trim_start().starts_with("function") {
        return None;
    }
    let first = func.first_child()?;
    (*first.kind() == NodeKind::Identifier).then(|| first.text())
}

fn variable_declaration_component_func(node: &AstNode) -> Option<(&str, &AstNode)> {
    if *node.kind() != NodeKind::VariableDecl {
        return None;
    }
    let name = node
        .first_child()
        .filter(|c| *c.kind() == NodeKind::Identifier)?
        .text();
    let func = node
        .descendants()
        .find(|c| *c.kind() == NodeKind::FunctionDef)?;
    Some((name, func))
}

fn is_pascal_case(name: &str) -> bool {
    name.chars().next().is_some_and(|c| c.is_ascii_uppercase())
}

fn is_callback_or_attr_node(node: &AstNode, current: bool) -> bool {
    if current {
        return true;
    }
    if crate::common::is_other(node, "jsx_attribute")
        || crate::common::is_other(node, "jsx_expression")
    {
        return true;
    }
    if *node.kind() == NodeKind::Call {
        if let Some(callee) = callee_name(node) {
            let is_array_method = matches!(
                callee,
                "map" | "filter" | "reduce" | "find" | "forEach" | "flatMap" | "some" | "every"
            );
            let is_hook = is_hook_name(callee);
            let is_async_or_timer = matches!(
                callee,
                "setTimeout"
                    | "setInterval"
                    | "requestAnimationFrame"
                    | "addEventListener"
                    | "removeEventListener"
                    | "then"
                    | "catch"
                    | "finally"
            );
            if is_array_method || is_hook || is_async_or_timer {
                return true;
            }
        }
    }
    false
}

fn walk<'a>(
    node: &'a AstNode,
    outer_component: Option<OuterComponentContext<'a>>,
    in_callback_or_attr: bool,
    is_initializer: bool,
    findings: &mut Vec<Finding>,
) {
    let component_info = if is_initializer {
        None
    } else if *node.kind() == NodeKind::FunctionDef {
        if let Some(name) = function_declaration_name(node) {
            let is_comp = is_pascal_case(name)
                || own_scope_descendants(node).iter().any(|n| is_jsx_kind(n));
            Some((name, node, is_comp))
        } else {
            let is_comp = own_scope_descendants(node).iter().any(|n| is_jsx_kind(n));
            if is_comp {
                Some(("anonymous component", node, true))
            } else {
                None
            }
        }
    } else if *node.kind() == NodeKind::VariableDecl {
        if let Some((name, func)) = variable_declaration_component_func(node) {
            let is_comp = is_pascal_case(name)
                || (name.starts_with("render")
                    && own_scope_descendants(func).iter().any(|n| is_jsx_kind(n)));
            Some((name, func, is_comp))
        } else {
            None
        }
    } else {
        None
    };

    if let Some((name, func_node, is_comp)) = component_info {
        if let Some(ref outer) = outer_component {
            let is_pascal = is_pascal_case(name);
            let is_render_fn_returning_jsx = !in_callback_or_attr
                && name.starts_with("render")
                && own_scope_descendants(func_node)
                    .iter()
                    .any(|n| is_jsx_kind(n));
            let is_fn_decl_returning_jsx = !in_callback_or_attr
                && *node.kind() == NodeKind::FunctionDef
                && own_scope_descendants(func_node)
                    .iter()
                    .any(|n| is_jsx_kind(n));

            if is_pascal || is_render_fn_returning_jsx || is_fn_decl_returning_jsx {
                findings.push(Finding::new(
                    format!(
                        "Do not define React component `{name}` inside render body of `{outer_name}`. Component definitions inside another component are recreated on every render, resetting state and DOM. Move `{name}` to top-level scope.",
                        outer_name = outer.component_name
                    ),
                    func_node.span(),
                ));
            }
        }

        let next_outer = if is_comp {
            Some(OuterComponentContext {
                component_name: name,
            })
        } else {
            outer_component
        };

        for child in node.children() {
            let next_in_cb = is_callback_or_attr_node(child, in_callback_or_attr);
            let child_is_init = *node.kind() == NodeKind::VariableDecl
                && *child.kind() == NodeKind::FunctionDef;
            walk(child, next_outer, next_in_cb, child_is_init, findings);
        }
        return;
    }

    for child in node.children() {
        let next_in_cb = is_callback_or_attr_node(child, in_callback_or_attr);
        let child_is_init =
            *node.kind() == NodeKind::VariableDecl && *child.kind() == NodeKind::FunctionDef;
        walk(child, outer_component, next_in_cb, child_is_init, findings);
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
        NoNestedComponentsRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_nested_function_component_declaration() {
        let code = "function Parent() {\n    function Child() {\n        return <div>Child</div>;\n    }\n    return <Child />;\n}\n";
        let findings = check(code);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("Child"));
        assert!(findings[0].message.contains("Parent"));
    }

    #[test]
    fn flags_nested_arrow_component_declaration() {
        let code = "const Parent = () => {\n    const SubComponent = () => <span>Sub</span>;\n    return <SubComponent />;\n};\n";
        let findings = check(code);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("SubComponent"));
    }

    #[test]
    fn flags_nested_render_function_returning_jsx() {
        let code = "function Dashboard() {\n    const renderHeader = () => <h1>Header</h1>;\n    return <div>{renderHeader()}</div>;\n}\n";
        let findings = check(code);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("renderHeader"));
    }

    #[test]
    fn allows_top_level_components() {
        let code = "function Header() {\n    return <h1>Header</h1>;\n}\nfunction App() {\n    return <Header />;\n}\n";
        let findings = check(code);
        assert!(findings.is_empty());
    }

    #[test]
    fn allows_map_callbacks() {
        let code = "function List({ items }: { items: string[] }) {\n    return (\n        <ul>\n            {items.map(item => (\n                <li key={item}>{item}</li>\n            ))}\n        </ul>\n    );\n}\n";
        let findings = check(code);
        assert!(findings.is_empty());
    }

    #[test]
    fn allows_event_handlers() {
        let code = "function Button() {\n    const handleClick = () => {\n        console.log('clicked');\n    };\n    return <button onClick={handleClick}>Click</button>;\n}\n";
        let findings = check(code);
        assert!(findings.is_empty());
    }
}
