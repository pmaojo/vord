//! Rule: a `useEffect`/`useLayoutEffect`/`useMemo`/`useCallback` hook whose
//! body references a component-scoped variable — a prop, a piece of state,
//! or a local helper — that isn't listed in its dependency array. Unlike
//! `react:hook-missing-deps-array` (which only checks whether an array is
//! present at all), this needs to know *which* identifiers in the hook body
//! are captured from the enclosing component's scope rather than locally
//! bound inside the callback or free from module scope — exactly the
//! same-file scope resolution `yunq_symbols::scope` provides.
//!
//! `useState` setters and `useRef` bindings are exempted: React guarantees
//! their identity is stable across renders, so `eslint-plugin-react-hooks`
//! doesn't require listing them either.

use std::collections::BTreeSet;

use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use yunq_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};
use yunq_symbols::{free_identifiers, own_bindings};

use crate::common::{call_arguments, hook_call_name, is_other, own_scope_descendants};

const DEPENDENCY_HOOKS: &[&str] = &["useEffect", "useLayoutEffect", "useMemo", "useCallback"];

/// Names bound in `component`'s own scope whose value React guarantees is
/// stable across renders: `useState`/`useReducer` setters/dispatchers, and
/// `useRef` results.
fn stable_names(component: &AstNode) -> BTreeSet<String> {
    let mut stable = BTreeSet::new();
    for decl in own_scope_descendants(component)
        .into_iter()
        .filter(|n| *n.kind() == NodeKind::VariableDecl)
    {
        let Some(call) = decl.children().iter().find(|c| *c.kind() == NodeKind::Call) else {
            continue;
        };
        let Some(hook) = hook_call_name(call) else {
            continue;
        };
        match hook {
            "useState" | "useReducer" => {
                if let Some(pattern) = decl.first_child().filter(|c| is_other(c, "array_pattern")) {
                    if let Some(setter) = pattern
                        .children()
                        .get(1)
                        .filter(|n| *n.kind() == NodeKind::Identifier)
                    {
                        stable.insert(setter.text().to_string());
                    }
                }
            }
            "useRef" => {
                if let Some(name) = decl
                    .first_child()
                    .filter(|n| *n.kind() == NodeKind::Identifier)
                {
                    stable.insert(name.text().to_string());
                }
            }
            _ => {}
        }
    }
    stable
}

/// The plain-identifier entries of a `[a, b, c]` dependency array literal.
/// Non-identifier entries (`obj.prop`, `a || b`, ...) are left out of the
/// "listed" set deliberately — this rule only flags a *missing* name, so an
/// unparsed complex entry never causes a false positive, only a potential
/// false negative on that one entry.
fn listed_deps(deps_array: &AstNode) -> BTreeSet<&str> {
    deps_array
        .children()
        .iter()
        .filter(|c| *c.kind() == NodeKind::Identifier)
        .map(|c| c.text())
        .collect()
}

fn check_hook_call(call: &AstNode, component: &AstNode, hook: &str, findings: &mut Vec<Finding>) {
    let args = call_arguments(call);
    let Some(callback) = args.first().filter(|a| *a.kind() == NodeKind::FunctionDef) else {
        return;
    };
    let Some(deps_array) = args.get(1).filter(|a| is_other(a, "array")) else {
        return;
    };

    let listed = listed_deps(deps_array);
    let free = free_identifiers(callback);
    let component_scope = own_bindings(component);
    let stable = stable_names(component);

    let mut missing: Vec<&str> = free
        .iter()
        .map(String::as_str)
        .filter(|name| component_scope.contains(*name))
        .filter(|name| !listed.contains(name))
        .filter(|name| !stable.contains(*name))
        .collect();
    if missing.is_empty() {
        return;
    }
    missing.sort_unstable();
    let names = missing
        .iter()
        .map(|n| format!("`{n}`"))
        .collect::<Vec<_>>()
        .join(", ");
    findings.push(Finding::new(
        format!(
            "`{hook}` is missing {names} from its dependency array — referenced in the effect body but not listed, so a stale value is captured until something else happens to trigger a re-run"
        ),
        call.span(),
    ));
}

/// Walks `node`, tracking the nearest enclosing `FunctionDef` (the
/// component/custom hook a hook call site is textually inside) so a hook
/// call found deeper in the tree can be checked against that function's own
/// scope. A hook call with no enclosing function (called at module scope,
/// which isn't valid React anyway) is skipped — there is no component scope
/// to compare against.
fn walk<'a>(node: &'a AstNode, enclosing: Option<&'a AstNode>, findings: &mut Vec<Finding>) {
    if *node.kind() == NodeKind::Call {
        if let Some(hook) = hook_call_name(node) {
            if DEPENDENCY_HOOKS.contains(&hook) {
                if let Some(component) = enclosing {
                    check_hook_call(node, component, hook, findings);
                }
            }
        }
    }
    let next_enclosing = if *node.kind() == NodeKind::FunctionDef {
        Some(node)
    } else {
        enclosing
    };
    for child in node.children() {
        walk(child, next_enclosing, findings);
    }
}

pub struct ExhaustiveDepsRule {
    id: RuleId,
}

impl ExhaustiveDepsRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("react:exhaustive-deps").expect("valid rule id"),
        }
    }
}

impl Default for ExhaustiveDepsRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for ExhaustiveDepsRule {
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
            description: "A hook's dependency array is missing a component-scoped value (prop, state, or local) its body actually reads, so the hook runs against a stale closure.".into(),
            tags: vec!["react".into(), "hooks".into(), "bug".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        let mut findings = Vec::new();
        walk(ast, None, &mut findings);
        findings
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
        ExhaustiveDepsRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_missing_prop_dependency() {
        let findings = check(
            "function Comp({ id }) {\n  useEffect(() => {\n    fetchData(id);\n  }, []);\n}\n",
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("`id`"));
        assert!(findings[0].message.contains("useEffect"));
    }

    #[test]
    fn allows_prop_listed_in_deps() {
        let findings = check(
            "function Comp({ id }) {\n  useEffect(() => {\n    fetchData(id);\n  }, [id]);\n}\n",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn flags_missing_state_in_use_memo() {
        let findings = check(
            "function Comp() {\n  const [count, setCount] = useState(0);\n  const doubled = useMemo(() => count * 2, []);\n}\n",
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("`count`"));
    }

    #[test]
    fn exempts_state_setter_from_deps() {
        let findings = check(
            "function Comp() {\n  const [count, setCount] = useState(0);\n  useEffect(() => {\n    setCount((c) => c + 1);\n  }, []);\n}\n",
        );
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn exempts_use_ref_binding_from_deps() {
        let findings = check(
            "function Comp() {\n  const ref = useRef(null);\n  useEffect(() => {\n    console.log(ref.current);\n  }, []);\n}\n",
        );
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn ignores_locally_declared_names_inside_the_callback() {
        let findings = check(
            "function Comp() {\n  useEffect(() => {\n    const local = 1;\n    doThing(local);\n  }, []);\n}\n",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn ignores_module_scope_free_names() {
        let findings = check(
            "function Comp() {\n  useEffect(() => {\n    console.log(GLOBAL_CONSTANT);\n  }, []);\n}\n",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn catches_dependency_captured_through_a_nested_helper() {
        let findings = check(
            "function Comp({ value }) {\n  useEffect(() => {\n    function helper() {\n      doThing(value);\n    }\n    helper();\n  }, []);\n}\n",
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("`value`"));
    }
}
