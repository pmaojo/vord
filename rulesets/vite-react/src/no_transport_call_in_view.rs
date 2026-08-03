//! Rule: a raw `fetch(...)`/`axios.<verb>(...)` call expression inside
//! `src/components/**` or `src/features/**/hooks/**` — the same "no direct
//! transport call outside the data layer" norm
//! `react:no-fetch-in-useeffect` already enforces, extended beyond
//! `useEffect` bodies specifically (any call site in a view or a
//! feature-scoped hook that isn't itself a data hook) and to `axios` too,
//! not just `fetch`.

use globset::GlobSet;
use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

use crate::common::{build_globset, is_dev_only_path, is_excepted, is_feature_hooks_path, is_view_path};

const AXIOS_VERBS: &[&str] = &[
    "get", "post", "put", "patch", "delete", "head", "options", "request",
];

pub struct NoTransportCallInViewRule {
    id: RuleId,
    exceptions: GlobSet,
}

impl NoTransportCallInViewRule {
    pub fn new() -> Self {
        Self::with_exceptions(Vec::new())
    }

    pub fn with_exceptions(globs: Vec<String>) -> Self {
        Self {
            id: RuleId::new("vite-react:no-transport-call-in-view").expect("valid rule id"),
            exceptions: build_globset(&globs),
        }
    }
}

impl Default for NoTransportCallInViewRule {
    fn default() -> Self {
        Self::new()
    }
}

fn transport_call_kind(call: &AstNode) -> Option<&'static str> {
    let callee = call.first_child()?;
    if *callee.kind() == NodeKind::Identifier && callee.text() == "fetch" {
        return Some("fetch");
    }
    if *callee.kind() == NodeKind::MemberAccess {
        let children = callee.children();
        let object = children.first()?;
        let property = children.last()?;
        if *object.kind() == NodeKind::Identifier
            && object.text() == "axios"
            && *property.kind() == NodeKind::Identifier
            && AXIOS_VERBS.contains(&property.text())
        {
            return Some("axios");
        }
    }
    None
}

fn walk(node: &AstNode, out: &mut Vec<Finding>) {
    if *node.kind() == NodeKind::Call {
        if let Some(kind) = transport_call_kind(node) {
            out.push(Finding::new(
                format!(
                    "raw `{kind}` call in the view layer — components and feature hooks must not fetch data directly; move this call into a data hook (`features/<feature>/api`) built on TanStack Query"
                ),
                node.span(),
            ));
        }
    }
    for child in node.children() {
        walk(child, out);
    }
}

impl Rule for NoTransportCallInViewRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, language: &LanguageIdentifier) -> bool {
        language.is_typescript() || language.is_javascript()
    }

    fn default_severity(&self) -> Severity {
        Severity::Blocker
    }

    fn issue_type(&self) -> IssueType {
        IssueType::CodeSmell
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "A raw `fetch`/`axios` call sits inside a component or a feature hook that isn't itself the data layer — caching, race conditions and error states are now the view's problem. Move the call into a data hook built on TanStack Query.".into(),
            tags: vec!["vite-react".into(), "bulletproof-react".into(), "layering".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        if is_dev_only_path(file.path()) {
            return Vec::new();
        }
        if !is_view_path(file.path()) && !is_feature_hooks_path(file.path()) {
            return Vec::new();
        }
        if is_excepted(file.path(), &self.exceptions) {
            return Vec::new();
        }
        let mut findings = Vec::new();
        walk(ast, &mut findings);
        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vord_rules_engine::AstParser;

    fn ts(path: &str, code: &str) -> Vec<Finding> {
        let file = SourceFile::new(path, code, LanguageIdentifier::typescript()).unwrap();
        let ast = vord_parser_typescript::TypeScriptParser::new()
            .parse(&file)
            .unwrap();
        NoTransportCallInViewRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_raw_fetch_in_a_component() {
        let findings = ts(
            "src/components/UserCard.tsx",
            "function UserCard() {\n  fetch('/api/user');\n  return null;\n}\n",
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("raw `fetch`"));
    }

    #[test]
    fn flags_axios_get_in_a_feature_hook() {
        let findings = ts(
            "src/features/auth/hooks/useLogin.ts",
            "export function useLogin() {\n  axios.get('/api/session');\n}\n",
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("raw `axios`"));
    }

    #[test]
    fn flags_axios_post() {
        let findings = ts(
            "src/components/LoginForm.tsx",
            "axios.post('/api/login', body);\n",
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn silent_on_a_wrapped_helper_call() {
        assert!(
            ts(
                "src/components/UserCard.tsx",
                "import { getUser } from '../features/user/api/queries';\ngetUser();\n"
            )
            .is_empty()
        );
    }

    #[test]
    fn silent_in_the_feature_api_directory() {
        assert!(
            ts(
                "src/features/auth/api/queries.ts",
                "export const login = () => axios.post('/api/login');\n"
            )
            .is_empty()
        );
    }

    #[test]
    fn silent_in_a_storybook_loader() {
        assert!(
            ts(
                "src/components/Button/Button.stories.tsx",
                "export const Loading = { loaders: [async () => { const r = await fetch('/mock-api/user'); return { user: await r.json() }; }] };\n"
            )
            .is_empty()
        );
    }

    #[test]
    fn silent_on_an_unrelated_axios_property_access() {
        assert!(
            ts(
                "src/components/UserCard.tsx",
                "const cancelled = axios.isCancel(err);\n"
            )
            .is_empty()
        );
    }
}
