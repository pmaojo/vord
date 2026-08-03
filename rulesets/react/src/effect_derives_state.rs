//! Rule: flags a `useEffect`/`useLayoutEffect` whose entire body is nothing
//! but calls to `useState`/`useReducer` setters keyed off a dependency
//! array — the "Updating state based on props or state" (and its "Caching
//! expensive calculations" cousin) anti-pattern from
//! <https://react.dev/learn/you-might-not-need-an-effect>: syncing a value
//! that's already derivable from props/state into a *second* piece of state
//! via an Effect costs an extra render and leaves a stale window until the
//! Effect runs, when the value could just be computed directly during
//! rendering (or cached with `useMemo` if it's expensive).
//!
//! Kept deliberately narrow to stay precise: only effects whose body is
//! *purely* setter calls (no other call, no `return` cleanup) are flagged.
//! An effect that also fetches, subscribes, or logs is a different concern
//! and is left to the other Effect-focused rules.

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

use crate::common::{call_arguments, callee_name, hook_call_name, is_other, state_setter_names};

/// Whether `block` (a `statement_block`) is nothing but calls to names in
/// `setters`: no `return` anywhere (that would mean a cleanup, i.e. a
/// subscription effect, not a pure state-derivation one), and every
/// top-level statement is a setter call.
fn is_only_setter_calls(block: &AstNode, setters: &std::collections::BTreeSet<String>) -> bool {
    if block.descendants().any(|n| is_other(n, "return_statement")) {
        return false;
    }
    let statements = block.children();
    !statements.is_empty() && statements.iter().all(|stmt| statement_is_setter_call(stmt, setters))
}

fn statement_is_setter_call(stmt: &AstNode, setters: &std::collections::BTreeSet<String>) -> bool {
    let call = if *stmt.kind() == NodeKind::Call {
        Some(stmt)
    } else if is_other(stmt, "expression_statement") {
        stmt.children().first().filter(|c| *c.kind() == NodeKind::Call)
    } else {
        None
    };
    call.and_then(callee_name).is_some_and(|name| setters.contains(name))
}

fn check_effect_call(call: &AstNode, hook: &str, component: &AstNode, findings: &mut Vec<Finding>) {
    let args = call_arguments(call);
    // Require an explicit (even empty) dependency array: this rule targets
    // the "sync derived state when X changes" shape specifically.
    if args.len() < 2 {
        return;
    }
    let Some(callback) = args.first().filter(|a| *a.kind() == NodeKind::FunctionDef) else {
        return;
    };
    let Some(block) = callback
        .children()
        .iter()
        .find(|c| is_other(c, "statement_block"))
    else {
        return;
    };
    let setters = state_setter_names(component);
    if setters.is_empty() {
        return;
    }
    if is_only_setter_calls(block, &setters) {
        findings.push(Finding::new(
            format!(
                "`{hook}` only writes state that's derived from props/state already in scope — compute it directly during rendering (or cache it with `useMemo` if it's expensive) instead of syncing it through an Effect"
            ),
            call.span(),
        ));
    }
}

fn walk<'a>(node: &'a AstNode, enclosing: Option<&'a AstNode>, findings: &mut Vec<Finding>) {
    if *node.kind() == NodeKind::Call {
        if let Some(hook @ ("useEffect" | "useLayoutEffect")) = hook_call_name(node) {
            if let Some(component) = enclosing {
                check_effect_call(node, hook, component, findings);
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

pub struct EffectDerivesStateRule {
    id: RuleId,
}

impl EffectDerivesStateRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("react:effect-derives-state").expect("valid rule id"),
        }
    }
}

impl Default for EffectDerivesStateRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for EffectDerivesStateRule {
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
            description: "An Effect's only job is writing state derived from props/state already available during render, instead of computing it directly.".into(),
            tags: vec!["react".into(), "hooks".into(), "you-might-not-need-an-effect".into()],
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
    use vord_rules_engine::AstParser;

    fn check(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.tsx", code, LanguageIdentifier::typescript()).unwrap();
        let ast = vord_parser_typescript::TypeScriptParser::new()
            .parse(&file)
            .unwrap();
        EffectDerivesStateRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_effect_that_only_derives_state_from_props() {
        let findings = check(
            "function Comp({ items }) {\n  const [count, setCount] = useState(0);\n  useEffect(() => {\n    setCount(items.length);\n  }, [items]);\n}\n",
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("useEffect"));
    }

    #[test]
    fn flags_multiple_setter_calls() {
        let findings = check(
            "function Comp({ a, b }) {\n  const [x, setX] = useState(0);\n  const [y, setY] = useState(0);\n  useEffect(() => {\n    setX(a);\n    setY(b);\n  }, [a, b]);\n}\n",
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn allows_effect_that_also_fetches() {
        let findings = check(
            "function Comp({ id }) {\n  const [data, setData] = useState(null);\n  useEffect(() => {\n    fetchThing(id).then((d) => setData(d));\n  }, [id]);\n}\n",
        );
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn allows_effect_with_cleanup() {
        let findings = check(
            "function Comp({ id }) {\n  const [x, setX] = useState(0);\n  useEffect(() => {\n    setX(id);\n    return () => cleanup();\n  }, [id]);\n}\n",
        );
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn allows_effect_without_deps_array() {
        let findings = check(
            "function Comp({ id }) {\n  const [x, setX] = useState(0);\n  useEffect(() => {\n    setX(id);\n  });\n}\n",
        );
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn allows_effect_calling_a_non_setter_function() {
        let findings = check(
            "function Comp({ id }) {\n  useEffect(() => {\n    logThing(id);\n  }, [id]);\n}\n",
        );
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn ignores_effect_with_no_state_setters_in_scope() {
        let findings = check("function Comp({ id }) {\n  useEffect(() => {\n    doThing(id);\n  }, [id]);\n}\n");
        assert!(findings.is_empty(), "{findings:?}");
    }
}
