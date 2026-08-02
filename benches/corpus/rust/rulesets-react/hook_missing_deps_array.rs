//! Rule: flags `useEffect`/`useLayoutEffect`/`useMemo`/`useCallback` called
//! without a second (dependency array) argument. For the effect hooks this
//! means the effect reruns after every render instead of only when its
//! dependencies change; for `useMemo`/`useCallback` it means the value or
//! callback is recreated every render, which defeats the memoization these
//! hooks exist for — there's no valid reason to call either without one.

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

use crate::common::{call_arguments, callee_name};

fn message_for(hook: &str) -> String {
    match hook {
        "useMemo" | "useCallback" => format!(
            "`{hook}` is missing its dependency array; the value is recomputed on every render, defeating the memoization `{hook}` exists for"
        ),
        _ => format!(
            "`{hook}` is missing its dependency array; the effect runs after every render instead of only when its dependencies change"
        ),
    }
}

pub struct HookMissingDepsArrayRule {
    id: RuleId,
}

impl HookMissingDepsArrayRule {
    pub fn new() -> Self {
        Self { id: RuleId::new("react:hook-missing-deps-array").expect("valid rule id") }
    }
}

impl Default for HookMissingDepsArrayRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for HookMissingDepsArrayRule {
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
            description: "`useEffect`/`useLayoutEffect`/`useMemo`/`useCallback` called without a dependency array runs or recomputes on every render.".into(),
            tags: vec!["react".into(), "hooks".into(), "performance".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter(|n| *n.kind() == NodeKind::Call)
            .filter_map(|call| {
                let name = callee_name(call)?;
                if !matches!(name, "useEffect" | "useLayoutEffect" | "useMemo" | "useCallback") {
                    return None;
                }
                (call_arguments(call).len() < 2).then(|| Finding::new(message_for(name), call.span()))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vord_rules_engine::AstParser;

    fn check(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.tsx", code, LanguageIdentifier::typescript()).unwrap();
        let ast = vord_parser_typescript::TypeScriptParser::new().parse(&file).unwrap();
        HookMissingDepsArrayRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_effect_without_deps() {
        let findings = check("useEffect(() => { doThing(); });\n");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("useEffect"));
    }

    #[test]
    fn flags_use_memo_and_use_callback_without_deps() {
        let findings = check("const v = useMemo(() => compute());\nconst f = useCallback(() => {});\n");
        assert_eq!(findings.len(), 2);
        assert!(findings[0].message.contains("useMemo"));
        assert!(findings[1].message.contains("useCallback"));
    }

    #[test]
    fn allows_effect_with_deps_array() {
        let findings = check("useEffect(() => { doThing(x); }, [x]);\n");
        assert!(findings.is_empty());
    }

    #[test]
    fn allows_effect_with_empty_deps_array() {
        let findings = check("useEffect(() => { doThing(); }, []);\n");
        assert!(findings.is_empty());
    }

    #[test]
    fn ignores_unrelated_calls() {
        let findings = check("setTimeout(() => {});\n");
        assert!(findings.is_empty());
    }
}
