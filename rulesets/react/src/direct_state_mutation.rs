//! Rule: flags calling an in-place mutating array method (`.push`, `.sort`,
//! ...) directly on a `useState`/`useReducer` value in the same function
//! scope. Mutating state in place doesn't create the new reference React's
//! `Object.is` change check relies on, so the component silently fails to
//! re-render even though the underlying data changed.

use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use yunq_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

use crate::common::{callee_name, is_other, own_scope_descendants};

const MUTATING_METHODS: &[&str] = &[
    "push",
    "pop",
    "shift",
    "unshift",
    "splice",
    "sort",
    "reverse",
    "fill",
    "copyWithin",
];

/// The state variable name from `const [name, setName] = useState(...)` /
/// `useReducer(...)`, if `decl` has that shape.
fn state_variable_name(decl: &AstNode) -> Option<&str> {
    let pattern = decl
        .first_child()
        .filter(|c| is_other(c, "array_pattern"))?;
    let name_node = pattern
        .children()
        .first()
        .filter(|c| *c.kind() == NodeKind::Identifier)?;
    let call = decl
        .children()
        .iter()
        .find(|c| *c.kind() == NodeKind::Call)?;
    matches!(callee_name(call), Some("useState") | Some("useReducer")).then(|| name_node.text())
}

/// A `<state>.<mutatingMethod>(...)` call, returning the method name.
fn mutation_on<'a>(call: &AstNode, state_vars: &[&'a str]) -> Option<(&'a str, &'static str)> {
    let callee = call
        .first_child()
        .filter(|c| *c.kind() == NodeKind::MemberAccess)?;
    let [object, property] = callee.children() else {
        return None;
    };
    if *object.kind() != NodeKind::Identifier || *property.kind() != NodeKind::Identifier {
        return None;
    }
    let var = state_vars.iter().find(|&&v| v == object.text())?;
    let method = MUTATING_METHODS.iter().find(|&&m| m == property.text())?;
    Some((var, method))
}

pub struct DirectStateMutationRule {
    id: RuleId,
}

impl DirectStateMutationRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("react:direct-state-mutation").expect("valid rule id"),
        }
    }
}

impl Default for DirectStateMutationRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for DirectStateMutationRule {
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
        IssueType::Bug
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "A `useState`/`useReducer` value is mutated in place instead of replaced, so React's reference-equality check never sees a change and the component doesn't re-render.".into(),
            tags: vec!["react".into(), "bug".into(), "state".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter(|n| *n.kind() == NodeKind::FunctionDef)
            .flat_map(|func| {
                // The state variable itself must be declared directly in
                // this function's own scope...
                let state_vars: Vec<&str> = own_scope_descendants(func)
                    .into_iter()
                    .filter(|n| *n.kind() == NodeKind::VariableDecl)
                    .filter_map(state_variable_name)
                    .collect();
                if state_vars.is_empty() {
                    return Vec::new();
                }
                // ...but the mutation itself is searched for across the
                // function's full body, including nested closures (event
                // handlers, timers, ...) that capture it — the common place
                // a mutation like this actually happens. A function with no
                // `useState` of its own (checked above) never contributes a
                // finding, so a nested closure that happens to redeclare the
                // same name doesn't get double-counted here.
                func.descendants()
                    .filter(|n| *n.kind() == NodeKind::Call)
                    .filter_map(|call| {
                        let (var, method) = mutation_on(call, &state_vars)?;
                        Some(Finding::new(
                            format!("`{var}.{method}(...)` mutates state in place; call the setter with a new array instead (e.g. `set{Var}([...{var}, ...])`)", Var = title_case(var)),
                            call.span(),
                        ))
                    })
                    .collect()
            })
            .collect()
    }
}

fn title_case(name: &str) -> String {
    let mut chars = name.chars();
    match chars.next() {
        Some(first) => first.to_ascii_uppercase().to_string() + chars.as_str(),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use yunq_rules_engine::AstParser;

    fn check(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.tsx", code, LanguageIdentifier::typescript()).unwrap();
        let ast = yunq_parser_typescript::TypeScriptParser::new()
            .parse(&file)
            .unwrap();
        DirectStateMutationRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_push_on_state_array() {
        let findings = check(
            "function Comp() {\n\
                const [items, setItems] = useState([]);\n\
                function add(x) {\n\
                    items.push(x);\n\
                }\n\
                return items;\n\
            }\n",
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("items.push"));
        assert!(findings[0].message.contains("setItems"));
    }

    #[test]
    fn flags_sort_on_reducer_state() {
        let findings = check(
            "function Comp() {\n\
                const [list, dispatch] = useReducer(reducer, []);\n\
                list.sort();\n\
                return list;\n\
            }\n",
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("list.sort"));
    }

    #[test]
    fn allows_mutation_via_a_copy() {
        let findings = check(
            "function Comp() {\n\
                const [items, setItems] = useState([]);\n\
                setItems([...items, 1]);\n\
            }\n",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn ignores_push_on_a_plain_local_array() {
        let findings = check(
            "function Comp() {\n\
                const items = [];\n\
                items.push(1);\n\
            }\n",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn ignores_same_named_variable_in_an_unrelated_function() {
        let findings = check(
            "function other() {\n\
                const items = getItems();\n\
                items.push(1);\n\
            }\n\
            function Comp() {\n\
                const [items, setItems] = useState([]);\n\
                return items;\n\
            }\n",
        );
        assert!(findings.is_empty());
    }
}
