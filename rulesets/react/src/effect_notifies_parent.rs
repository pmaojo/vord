//! Rule: flags a `useEffect` whose entire body is nothing but calls to a
//! destructured `onX` callback prop, keyed off a dependency array — the
//! "Notifying parent components about state changes" (and its "Passing data
//! up to a parent" cousin) anti-pattern from
//! <https://react.dev/learn/you-might-not-need-an-effect>. Calling the
//! parent's callback from an Effect instead of from the event handler that
//! actually changed the state adds an extra render, and — if something else
//! in the component also updates that state — a spot where the parent finds
//! out about a change it didn't actually need updating for.
//!
//! Kept deliberately narrow: only effects whose body is *purely* calls to a
//! destructured `onX` prop (no other call, no `return` cleanup) are flagged.

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

use crate::common::{call_arguments, callee_name, destructured_on_prop_names, hook_call_name, is_other};

fn is_only_on_prop_calls(block: &AstNode, on_props: &std::collections::BTreeSet<String>) -> bool {
    if block.descendants().any(|n| is_other(n, "return_statement")) {
        return false;
    }
    let statements = block.children();
    !statements.is_empty() && statements.iter().all(|stmt| statement_is_on_prop_call(stmt, on_props))
}

fn statement_is_on_prop_call(stmt: &AstNode, on_props: &std::collections::BTreeSet<String>) -> bool {
    let call = if *stmt.kind() == NodeKind::Call {
        Some(stmt)
    } else if is_other(stmt, "expression_statement") {
        stmt.children().first().filter(|c| *c.kind() == NodeKind::Call)
    } else {
        None
    };
    call.and_then(callee_name).is_some_and(|name| on_props.contains(name))
}

fn check_effect_call(call: &AstNode, component: &AstNode, findings: &mut Vec<Finding>) {
    let args = call_arguments(call);
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
    let on_props = destructured_on_prop_names(component);
    if on_props.is_empty() {
        return;
    }
    if is_only_on_prop_calls(block, &on_props) {
        findings.push(Finding::new(
            "This Effect exists only to notify a parent via a callback prop whenever state changes — call the callback directly in the event handler that updates the state instead of syncing it through an Effect".to_string(),
            call.span(),
        ));
    }
}

fn walk<'a>(node: &'a AstNode, enclosing: Option<&'a AstNode>, findings: &mut Vec<Finding>) {
    if *node.kind() == NodeKind::Call && hook_call_name(node) == Some("useEffect") {
        if let Some(component) = enclosing {
            check_effect_call(node, component, findings);
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

pub struct EffectNotifiesParentRule {
    id: RuleId,
}

impl EffectNotifiesParentRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("react:effect-notifies-parent").expect("valid rule id"),
        }
    }
}

impl Default for EffectNotifiesParentRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for EffectNotifiesParentRule {
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
            description: "An Effect's only job is calling a callback prop in response to a state change, instead of calling it from the event handler that changed the state.".into(),
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
        EffectNotifiesParentRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_effect_that_only_calls_on_prop_on_state_change() {
        let findings = check(
            "function Comp({ onChange }) {\n  const [value, setValue] = useState(0);\n  useEffect(() => {\n    onChange(value);\n  }, [value]);\n}\n",
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_multiple_on_prop_calls() {
        let findings = check(
            "function Comp({ onChange, onDirty }) {\n  const [value, setValue] = useState(0);\n  useEffect(() => {\n    onChange(value);\n    onDirty(true);\n  }, [value]);\n}\n",
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn allows_effect_that_also_does_other_work() {
        let findings = check(
            "function Comp({ onChange }) {\n  const [value, setValue] = useState(0);\n  useEffect(() => {\n    logChange(value);\n    onChange(value);\n  }, [value]);\n}\n",
        );
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn allows_effect_with_cleanup() {
        let findings = check(
            "function Comp({ onChange }) {\n  const [value, setValue] = useState(0);\n  useEffect(() => {\n    onChange(value);\n    return () => cleanup();\n  }, [value]);\n}\n",
        );
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn ignores_on_named_call_that_is_not_a_destructured_prop() {
        // `onSomethingElse` matches the naming convention but isn't among
        // `Comp`'s destructured props (`onChange` is) — must not be treated
        // as a callback prop just because of its name.
        let findings = check(
            "function Comp({ onChange }) {\n  const [value, setValue] = useState(0);\n  useEffect(() => {\n    onSomethingElse(value);\n  }, [value]);\n}\n",
        );
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn allows_effect_without_deps_array() {
        let findings = check(
            "function Comp({ onChange }) {\n  const [value, setValue] = useState(0);\n  useEffect(() => {\n    onChange(value);\n  });\n}\n",
        );
        assert!(findings.is_empty(), "{findings:?}");
    }
}
