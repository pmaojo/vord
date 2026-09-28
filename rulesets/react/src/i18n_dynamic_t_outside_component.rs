//! Rule: flags `i18n.t(...)` used in a file with no JSX (a hook or a
//! `utils`-shaped module, not a component's render body) — review feedback
//! on this codebase (`utils.ts`, `useWeddingProposalActions.ts`) pointed
//! out that `i18n.t` reads the *current* language once, at call time; a
//! statically imported `t` reads the same way but signals the same
//! non-reactivity more clearly, and is the codebase's convention for
//! non-component code. Inside a component's render body `i18n.t` is left
//! alone: `useTranslation()`'s `t` is the reactive one, and a component
//! calling `i18n.t` directly instead is a different (and already covered)
//! concern.

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

use crate::common::is_jsx_kind;

fn is_i18n_t_call(node: &AstNode) -> bool {
    if *node.kind() != NodeKind::Call {
        return false;
    }
    let Some(callee) = node.first_child() else {
        return false;
    };
    if *callee.kind() != NodeKind::MemberAccess {
        return false;
    }
    let [object, prop] = callee.children() else {
        return false;
    };
    *object.kind() == NodeKind::Identifier && object.text() == "i18n" && prop.text() == "t"
}

pub struct I18nDynamicTOutsideComponentRule {
    id: RuleId,
}

impl I18nDynamicTOutsideComponentRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("react:i18n-dynamic-t-outside-component").expect("valid rule id"),
        }
    }
}

impl Default for I18nDynamicTOutsideComponentRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for I18nDynamicTOutsideComponentRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, lang: &LanguageIdentifier) -> bool {
        lang.is_typescript() || lang.is_javascript()
    }

    fn default_severity(&self) -> Severity {
        Severity::Minor
    }

    fn issue_type(&self) -> IssueType {
        IssueType::CodeSmell
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "`i18n.t(...)` is called outside a component's JSX; import the static `t` instead (same non-reactivity, clearer intent) unless the file genuinely can't use the `useTranslation()` hook.".into(),
            tags: vec!["react".into(), "i18n".into(), "consistency".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        if vord_rules_engine::is_test_only_path(file.path()) {
            return Vec::new();
        }
        if ast.descendants().any(is_jsx_kind) {
            return Vec::new();
        }
        ast.descendants()
            .filter(|n| is_i18n_t_call(n))
            .map(|n| {
                Finding::new(
                    "`i18n.t(...)` outside a component; import the static `t` instead — keep in mind text rendered this way won't update reactively until the next call",
                    n.span(),
                )
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vord_rules_engine::AstParser;

    fn check_at(path: &str, code: &str) -> Vec<Finding> {
        let file = SourceFile::new(path, code, LanguageIdentifier::typescript()).unwrap();
        let ast = vord_parser_typescript::TypeScriptParser::new()
            .parse(&file)
            .unwrap();
        I18nDynamicTOutsideComponentRule::new().check(&file, &ast)
    }

    fn check(code: &str) -> Vec<Finding> {
        check_at("useWeddingProposalActions.ts", code)
    }

    #[test]
    fn flags_i18n_t_in_a_hook_file() {
        let findings = check("export function useX() {\n  return i18n.t('key');\n}\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn allows_i18n_t_in_a_component_with_jsx() {
        let findings = check_at(
            "Comp.tsx",
            "function Comp() {\n  const label = i18n.t('key');\n  return <div>{label}</div>;\n}\n",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn allows_static_t_import_usage() {
        let findings = check("export function useX() {\n  return t('key');\n}\n");
        assert!(findings.is_empty());
    }
}
