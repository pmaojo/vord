//! Rule: flags a Hook call reached only conditionally — inside an
//! `if`/loop/`switch`/ternary, or after an earlier `return` in the same
//! block. React relies on Hooks running in the same order on every render
//! (it tracks them by call index); either shape breaks that invariant and
//! desyncs a component's state.

use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use yunq_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

use crate::common::{hook_call_name, is_other};

const CONDITIONAL_KINDS: &[&str] = &[
    "if_statement",
    "ternary_expression",
    "for_statement",
    "for_in_statement",
    "for_of_statement",
    "while_statement",
    "do_statement",
    "switch_statement",
    "catch_clause",
];

fn is_conditional_kind(node: &AstNode) -> bool {
    matches!(node.kind(), NodeKind::Other(k) if CONDITIONAL_KINDS.contains(&k.as_ref()))
}

/// True for a statement that unconditionally exits its enclosing function
/// (a `return`/`throw`, or a block whose last statement does).
fn branch_terminates(node: &AstNode) -> bool {
    if is_other(node, "return_statement") || is_other(node, "throw_statement") {
        return true;
    }
    is_other(node, "statement_block") && node.children().last().is_some_and(branch_terminates)
}

/// An `if (cond) return/throw ...;` with no `else`: everything after it in
/// the same block only runs when `cond` was false, so it's reached
/// conditionally too — the textbook "early return before a Hook" violation.
fn is_early_return_guard(if_node: &AstNode) -> bool {
    let has_else = if_node
        .children()
        .iter()
        .any(|c| is_other(c, "else_clause"));
    !has_else && if_node.children().get(1).is_some_and(branch_terminates)
}

fn report_if_conditional_hook_call(node: &AstNode, conditional: bool, findings: &mut Vec<Finding>) {
    if !conditional {
        return;
    }
    if let Some(name) = hook_call_name(node) {
        findings.push(Finding::new(
            format!(
                "React Hook `{name}` is called conditionally; Hooks must run in the same order on every render"
            ),
            node.span(),
        ));
    }
}

/// A block/program's children run in sequence, so a statement after an
/// unconditional early exit (`return`/`throw`, or an early-return guard) is
/// itself reached conditionally even though it isn't nested inside a branch.
fn walk_block(node: &AstNode, conditional: bool, findings: &mut Vec<Finding>) {
    let mut after_return = false;
    for child in node.children() {
        if *child.kind() == NodeKind::FunctionDef {
            continue;
        }
        walk(
            child,
            conditional || after_return || is_conditional_kind(child),
            findings,
        );
        if is_other(child, "return_statement")
            || is_other(child, "throw_statement")
            || (is_other(child, "if_statement") && is_early_return_guard(child))
        {
            after_return = true;
        }
    }
}

/// Walks `node`'s subtree tracking whether the current position is reached
/// conditionally, stopping at nested `FunctionDef` boundaries (a hook call
/// inside a distinct nested function is that function's own concern, judged
/// independently when the top-level scan reaches it).
fn walk(node: &AstNode, conditional: bool, findings: &mut Vec<Finding>) {
    report_if_conditional_hook_call(node, conditional, findings);

    if is_other(node, "statement_block") || is_other(node, "program") {
        walk_block(node, conditional, findings);
        return;
    }

    for child in node.children() {
        if *child.kind() == NodeKind::FunctionDef {
            continue;
        }
        walk(child, conditional || is_conditional_kind(child), findings);
    }
}

pub struct RulesOfHooksConditionalRule {
    id: RuleId,
}

impl RulesOfHooksConditionalRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("react:rules-of-hooks-conditional").expect("valid rule id"),
        }
    }
}

impl Default for RulesOfHooksConditionalRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for RulesOfHooksConditionalRule {
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
            description: "A Hook is called conditionally (inside a branch/loop, or after an early return) instead of unconditionally at the top level, breaking React's per-render call-order invariant.".into(),
            tags: vec!["react".into(), "rules-of-hooks".into(), "bug".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter(|n| *n.kind() == NodeKind::FunctionDef)
            .flat_map(|func| {
                let mut findings = Vec::new();
                walk(func, false, &mut findings);
                findings
            })
            .collect()
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
        RulesOfHooksConditionalRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_hook_inside_if() {
        let findings = check(
            "function Comp({flag}: {flag: boolean}) {\n\
                if (flag) {\n\
                    const [x, setX] = useState(0);\n\
                }\n\
                return null;\n\
            }\n",
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("useState"));
    }

    #[test]
    fn flags_hook_after_early_return() {
        let findings = check(
            "function Comp({flag}: {flag: boolean}) {\n\
                if (!flag) return null;\n\
                const [x, setX] = useState(0);\n\
                return x;\n\
            }\n",
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_hook_inside_loop() {
        let findings = check(
            "function useThing(list: number[]) {\n\
                for (const item of list) {\n\
                    useEffect(() => {}, [item]);\n\
                }\n\
            }\n",
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("useEffect"));
    }

    #[test]
    fn allows_top_level_hooks() {
        let findings = check(
            "function Comp({flag}: {flag: boolean}) {\n\
                const [x, setX] = useState(0);\n\
                useEffect(() => {}, [x]);\n\
                if (flag) {\n\
                    return null;\n\
                }\n\
                return x;\n\
            }\n",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn ignores_ordinary_conditional_calls() {
        let findings = check(
            "function Comp({flag}: {flag: boolean}) {\n\
                if (flag) {\n\
                    doSomething();\n\
                }\n\
                return null;\n\
            }\n",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn nested_function_is_judged_independently() {
        // The outer component calls no hook conditionally itself; the inner
        // closure's own (unconditional, within its own body) hook call is
        // not this component's violation.
        let findings = check(
            "function Comp() {\n\
                const helper = () => {\n\
                    useState(0);\n\
                };\n\
                if (true) {\n\
                    helper();\n\
                }\n\
                return null;\n\
            }\n",
        );
        assert!(findings.is_empty());
    }
}
