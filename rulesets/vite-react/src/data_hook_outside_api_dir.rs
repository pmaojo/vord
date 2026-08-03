//! Rule: a `useQuery`/`useMutation`/`useInfiniteQuery` call, or a React
//! Query import, inside `src/features/**/hooks/**` — bulletproof-react's
//! convention keeps data-fetching hooks in `features/<feature>/api/` (e.g.
//! `queries.ts`) and reserves `hooks/` for UI-state hooks
//! (`useToggle`, `useDebouncedValue`) that hold no server data at all.
//! Mixing the two makes a component's data dependency invisible from its
//! import path alone.

use globset::GlobSet;
use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_import_graph::{imported_modules, matches_module};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

use crate::common::{build_globset, is_excepted, is_feature_api_path, is_feature_hooks_path};

const REACT_QUERY_HOOK_NAMES: &[&str] = &["useQuery", "useMutation", "useInfiniteQuery"];
const REACT_QUERY_MODULES: &[&str] = &["@tanstack/react-query", "react-query"];

pub struct DataHookOutsideApiDirRule {
    id: RuleId,
    exceptions: GlobSet,
}

impl DataHookOutsideApiDirRule {
    pub fn new() -> Self {
        Self::with_exceptions(Vec::new())
    }

    pub fn with_exceptions(globs: Vec<String>) -> Self {
        Self {
            id: RuleId::new("vite-react:data-hook-outside-api-dir").expect("valid rule id"),
            exceptions: build_globset(&globs),
        }
    }
}

impl Default for DataHookOutsideApiDirRule {
    fn default() -> Self {
        Self::new()
    }
}

fn call_findings(ast: &AstNode, out: &mut Vec<Finding>) {
    fn walk(node: &AstNode, out: &mut Vec<Finding>) {
        if *node.kind() == NodeKind::Call {
            if let Some(callee) = node.first_child() {
                if *callee.kind() == NodeKind::Identifier
                    && REACT_QUERY_HOOK_NAMES.contains(&callee.text())
                {
                    out.push(Finding::new(
                        format!(
                            "`{}` is called from a `hooks/` file — data-fetching hooks belong in the feature's `api/` directory (e.g. `api/queries.ts`), so a component's server-data dependency is visible from its import path",
                            callee.text()
                        ),
                        node.span(),
                    ));
                }
            }
        }
        for child in node.children() {
            walk(child, out);
        }
    }
    walk(ast, out);
}

impl Rule for DataHookOutsideApiDirRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, language: &LanguageIdentifier) -> bool {
        language.is_typescript() || language.is_javascript()
    }

    fn default_severity(&self) -> Severity {
        Severity::Major
    }

    fn issue_type(&self) -> IssueType {
        IssueType::CodeSmell
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "A `hooks/` file calls a React Query data-fetching hook (or imports React Query at all) — that convention's own layering keeps `hooks/` for UI-state hooks and `api/` for server-data hooks, so a data dependency stays visible from the import path.".into(),
            tags: vec![
                "vite-react".into(),
                "bulletproof-react".into(),
                "layering".into(),
            ],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        if vord_rules_engine::is_test_only_path(file.path()) {
            return Vec::new();
        }
        if !is_feature_hooks_path(file.path()) || is_feature_api_path(file.path()) {
            return Vec::new();
        }
        if is_excepted(file.path(), &self.exceptions) {
            return Vec::new();
        }
        let mut findings = Vec::new();
        call_findings(ast, &mut findings);
        for import in imported_modules(file, ast) {
            if REACT_QUERY_MODULES
                .iter()
                .any(|module| matches_module(&import.specifier, module))
            {
                findings.push(Finding::new(
                    format!(
                        "`{}` is imported from a `hooks/` file — React Query belongs in the feature's `api/` directory, not `hooks/`",
                        import.specifier
                    ),
                    import.span,
                ));
            }
        }
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
        DataHookOutsideApiDirRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_use_query_call_in_a_hooks_file() {
        let findings = ts(
            "src/features/user/hooks/useUser.ts",
            "export function useUser() {\n  return useQuery(['user'], fetchUser);\n}\n",
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("`useQuery`"));
    }

    #[test]
    fn flags_use_mutation_call() {
        let findings = ts(
            "src/features/auth/hooks/useLogin.ts",
            "export function useLogin() {\n  return useMutation(login);\n}\n",
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_a_react_query_import_with_no_call() {
        let findings = ts(
            "src/features/user/hooks/types.ts",
            "import type { UseQueryResult } from '@tanstack/react-query';\nexport type X = UseQueryResult;\n",
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("@tanstack/react-query"));
    }

    #[test]
    fn silent_in_the_api_directory() {
        assert!(
            ts(
                "src/features/user/api/queries.ts",
                "export function useUser() {\n  return useQuery(['user'], fetchUser);\n}\n",
            )
            .is_empty()
        );
    }

    #[test]
    fn silent_on_a_plain_ui_state_hook() {
        assert!(
            ts(
                "src/features/user/hooks/useToggle.ts",
                "export function useToggle(initial: boolean) {\n  return useState(initial);\n}\n",
            )
            .is_empty()
        );
    }

    #[test]
    fn silent_outside_the_hooks_directory() {
        assert!(
            ts(
                "src/features/user/components/UserCard.tsx",
                "export function UserCard() {\n  return useQuery(['user'], fetchUser);\n}\n",
            )
            .is_empty()
        );
    }
}
