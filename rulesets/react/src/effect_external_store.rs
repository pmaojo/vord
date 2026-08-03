//! Rule: flags a `useEffect` that subscribes to something outside React
//! (`addEventListener`/`.subscribe(...)`) and writes the result into local
//! state, returning a cleanup — the "Subscribing to an external store"
//! anti-pattern from <https://react.dev/learn/you-might-not-need-an-effect>.
//! React has a Hook built exactly for this, `useSyncExternalStore`, which
//! also correctly handles concurrent rendering and server rendering in ways
//! a hand-rolled `useEffect` + `useState` pair doesn't.
//!
//! Detection is a same-effect heuristic, not a proof: a subscribe-shaped
//! call (`addEventListener`/`subscribe`), a `useState`/`useReducer` setter
//! called anywhere in the same effect (including inside the listener
//! callback), and a `return` (cleanup) — all three together are specific
//! enough in practice that a false positive would itself already be a
//! confusingly-shaped Effect.

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

use crate::common::{call_arguments, hook_call_name, is_other, state_setter_names};

const SUBSCRIBE_METHODS: &[&str] = &["addEventListener", "subscribe"];

/// Whether `node` is a call to `object.method(...)` where `method` is one of
/// `names` (`el.addEventListener(...)`, `store.subscribe(...)`, ...).
fn is_member_call(node: &AstNode, names: &[&str]) -> bool {
    if *node.kind() != NodeKind::Call {
        return false;
    }
    node.first_child().is_some_and(|callee| {
        *callee.kind() == NodeKind::MemberAccess
            && callee.children().last().is_some_and(|prop| {
                *prop.kind() == NodeKind::Identifier && names.contains(&prop.text())
            })
    })
}

fn has_setter_call(node: &AstNode, setters: &std::collections::BTreeSet<String>) -> bool {
    node.descendants().any(|n| {
        *n.kind() == NodeKind::Call
            && crate::common::callee_name(n).is_some_and(|name| setters.contains(name))
    })
}

fn check_effect_call(call: &AstNode, component: &AstNode, findings: &mut Vec<Finding>) {
    let args = call_arguments(call);
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

    let subscribes = block
        .descendants()
        .any(|n| is_member_call(n, SUBSCRIBE_METHODS));
    if !subscribes {
        return;
    }
    let has_cleanup = block.children().iter().any(|c| is_other(c, "return_statement"));
    if !has_cleanup {
        return;
    }
    let setters = state_setter_names(component);
    if setters.is_empty() || !has_setter_call(block, &setters) {
        return;
    }

    findings.push(Finding::new(
        "This Effect subscribes to an external store (`addEventListener`/`.subscribe`) and mirrors it into local state — use `useSyncExternalStore` instead, which handles this case (including concurrent and server rendering) directly".to_string(),
        call.span(),
    ));
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

pub struct EffectExternalStoreRule {
    id: RuleId,
}

impl EffectExternalStoreRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("react:effect-external-store").expect("valid rule id"),
        }
    }
}

impl Default for EffectExternalStoreRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for EffectExternalStoreRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, lang: &LanguageIdentifier) -> bool {
        *lang == LanguageIdentifier::typescript()
    }

    fn default_severity(&self) -> Severity {
        Severity::Minor
    }

    fn issue_type(&self) -> IssueType {
        IssueType::CodeSmell
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "A useEffect hand-rolls subscribing to an external store into local state; useSyncExternalStore exists for exactly this.".into(),
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
        EffectExternalStoreRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_add_event_listener_subscription_synced_to_state() {
        let findings = check(
            "function Comp() {\n  const [width, setWidth] = useState(window.innerWidth);\n  useEffect(() => {\n    function handleResize() {\n      setWidth(window.innerWidth);\n    }\n    window.addEventListener('resize', handleResize);\n    return () => window.removeEventListener('resize', handleResize);\n  }, []);\n}\n",
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("useSyncExternalStore"));
    }

    #[test]
    fn flags_store_subscribe_returning_the_unsubscribe_function() {
        let findings = check(
            "function Comp({ store }) {\n  const [state, setState] = useState(store.getState());\n  useEffect(() => {\n    const unsubscribe = store.subscribe(() => setState(store.getState()));\n    return unsubscribe;\n  }, [store]);\n}\n",
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn allows_subscription_without_cleanup() {
        // Missing cleanup is a different bug (a leak); not this rule's
        // concern, and not confidently the "sync an external store" shape.
        let findings = check(
            "function Comp() {\n  const [width, setWidth] = useState(0);\n  useEffect(() => {\n    window.addEventListener('resize', () => setWidth(window.innerWidth));\n  }, []);\n}\n",
        );
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn allows_subscription_that_never_touches_state() {
        let findings = check(
            "function Comp() {\n  useEffect(() => {\n    window.addEventListener('resize', logResize);\n    return () => window.removeEventListener('resize', logResize);\n  }, []);\n}\n",
        );
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn allows_effect_with_no_subscription() {
        let findings = check(
            "function Comp({ id }) {\n  const [data, setData] = useState(null);\n  useEffect(() => {\n    setData(id);\n    return () => cleanup();\n  }, [id]);\n}\n",
        );
        assert!(findings.is_empty(), "{findings:?}");
    }
}
