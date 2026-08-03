//! Rule: a presentational file (`src/components/**` or
//! `src/features/**/components/**`) calling a data-fetching hook (React
//! Query's `useQuery`/`useMutation`/`useInfiniteQuery`/`useQueries`),
//! importing Zustand, or reaching straight into `src/infra/**` —
//! bulletproof-react's split between "how it looks" and "where the data
//! comes from" only holds if the view layer never does either. Per-file
//! (`Rule`): a file's own path and its own import list are all this needs,
//! the same shape as
//! `architecture:framework-in-domain` (`rulesets/architecture/src/framework_in_domain.rs`),
//! scanning a curated roster instead of inferring anything.
//!
//! Two things deliberately aren't banned here, both confirmed against the
//! actual bulletproof-react reference implementation
//! (github.com/alan2207/bulletproof-react, `apps/react-vite`):
//! - **Routing** (`react-router`/`react-router-dom`) isn't a data-layer
//!   concern the way React Query/Zustand are — it's part of the view.
//!   Reference code calls `useNavigate`/`useSearchParams`/`Link` directly in
//!   layouts and even wraps `Link` itself in a `components/ui/link`
//!   component; banning it here would flag the reference implementation's
//!   own idiomatic code.
//! - **`useQueryClient`** (cache reads/invalidation/prefetching, not
//!   fetching) is imported and called directly in reference components
//!   (`DiscussionsList` prefetches a detail query on hover via
//!   `queryClient`) — only the four hooks that actually *fetch* are banned,
//!   not the whole module.

use globset::GlobSet;
use vord_ast::{AstNode, LanguageIdentifier, SourceFile};
use vord_import_graph::{imported_modules, matches_module};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

use crate::common::{
    build_globset, import_statement_at, is_dev_only_path, is_excepted, is_infra_specifier,
    is_store_module_path, is_type_only_import_span, is_view_path, named_import_bindings,
};

const REACT_QUERY_MODULES: &[&str] = &["@tanstack/react-query", "react-query"];
const REACT_QUERY_DATA_HOOKS: &[&str] =
    &["useQuery", "useMutation", "useInfiniteQuery", "useQueries"];

pub struct NoDataLayerImportInViewRule {
    id: RuleId,
    exceptions: GlobSet,
}

impl NoDataLayerImportInViewRule {
    pub fn new() -> Self {
        Self::with_exceptions(Vec::new())
    }

    /// `globs` come from `vord.toml`'s
    /// `[vite_react.exceptions]."vite-react:no-data-layer-import-in-view"` —
    /// an explicit, reviewed escape hatch for a legacy component mid-migration,
    /// never an implicit one.
    pub fn with_exceptions(globs: Vec<String>) -> Self {
        Self {
            id: RuleId::new("vite-react:no-data-layer-import-in-view").expect("valid rule id"),
            exceptions: build_globset(&globs),
        }
    }
}

impl Default for NoDataLayerImportInViewRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for NoDataLayerImportInViewRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, language: &LanguageIdentifier) -> bool {
        language.is_typescript() || language.is_javascript()
    }

    fn default_severity(&self) -> Severity {
        Severity::Blocker
    }

    fn remediation_effort_minutes(&self) -> u32 {
        20
    }

    fn issue_type(&self) -> IssueType {
        IssueType::CodeSmell
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "A presentational component imports a data-fetching or state-management library (or reaches into `src/infra`) directly, coupling how it looks to where its data comes from. Move the call into a feature hook (`features/<feature>/hooks` or `.../api`) and pass the result down as a prop.".into(),
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
        if is_dev_only_path(file.path()) || is_store_module_path(file.path()) {
            return Vec::new();
        }
        if !is_view_path(file.path()) || is_excepted(file.path(), &self.exceptions) {
            return Vec::new();
        }
        imported_modules(file, ast)
            .into_iter()
            .filter_map(|import| {
                if is_type_only_import_span(ast, import.span) {
                    return None;
                }
                if is_infra_specifier(&import.specifier) {
                    return Some(vec![Finding::new(
                        format!(
                            "component code imports `{}` (an infra module) — the view layer must not talk to infra directly; consume it through a feature hook and pass the result down as a prop",
                            import.specifier
                        ),
                        import.span,
                    )]);
                }
                if matches_module(&import.specifier, "zustand") {
                    return Some(vec![Finding::new(
                        format!(
                            "component code imports `{}` (global client state) — the view layer must not depend on it directly; put the zustand call in a feature hook and pass the result down as a prop",
                            import.specifier
                        ),
                        import.span,
                    )]);
                }
                if REACT_QUERY_MODULES
                    .iter()
                    .any(|module| matches_module(&import.specifier, module))
                {
                    let node = import_statement_at(ast, import.span)?;
                    let hooks: Vec<&str> = named_import_bindings(node)
                        .into_iter()
                        .filter(|name| REACT_QUERY_DATA_HOOKS.contains(&name.as_str()))
                        .map(|name| {
                            REACT_QUERY_DATA_HOOKS
                                .iter()
                                .find(|&&h| h == name)
                                .copied()
                                .unwrap_or("useQuery")
                        })
                        .collect();
                    if hooks.is_empty() {
                        return None;
                    }
                    return Some(
                        hooks
                            .into_iter()
                            .map(|hook| {
                                Finding::new(
                                    format!(
                                        "component code imports `{hook}` from `{}` (the data-fetching layer) — the view layer must not fetch directly; put the {hook} call in a feature hook and pass the result down as a prop",
                                        import.specifier
                                    ),
                                    import.span,
                                )
                            })
                            .collect(),
                    );
                }
                None
            })
            .flatten()
            .collect()
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
        NoDataLayerImportInViewRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_react_query_in_a_component() {
        let findings = ts(
            "src/components/UserCard.tsx",
            "import { useQuery } from '@tanstack/react-query';\nexport const x = useQuery;\n",
        );
        assert_eq!(findings.len(), 1);
        assert!(
            findings[0].message.contains("imports `useQuery` from"),
            "{}",
            findings[0].message
        );
    }

    #[test]
    fn flags_use_mutation_alongside_use_query() {
        let findings = ts(
            "src/components/UserCard.tsx",
            "import { useQuery, useMutation } from '@tanstack/react-query';\nexport const x = [useQuery, useMutation];\n",
        );
        assert_eq!(findings.len(), 2, "{findings:?}");
    }

    #[test]
    fn silent_on_use_query_client() {
        // A real bulletproof-react component (`DiscussionsList`) calls
        // `useQueryClient()` directly to prefetch/invalidate — cache
        // management, not fetching.
        assert!(
            ts(
                "src/features/discussions/components/DiscussionsList.tsx",
                "import { useQueryClient } from '@tanstack/react-query';\nexport const x = useQueryClient;\n"
            )
            .is_empty()
        );
    }

    #[test]
    fn flags_zustand_in_a_feature_component() {
        let findings = ts(
            "src/features/auth/components/LoginForm.tsx",
            "import { create } from 'zustand';\nexport const x = create;\n",
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("global client state"));
    }

    #[test]
    fn flags_a_direct_infra_import() {
        let findings = ts(
            "src/components/UserCard.tsx",
            "import { httpClient } from '../infra/http';\n",
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("an infra module"));
    }

    #[test]
    fn silent_on_react_router() {
        // Routing is a view-layer concern, not a data-layer one — confirmed
        // against bulletproof-react's own reference implementation, which
        // uses `useNavigate`/`Link`/`useSearchParams` directly in layouts
        // and even wraps `Link` itself in a `components/ui/link` component.
        assert!(
            ts(
                "src/components/NavLink.tsx",
                "import { useNavigate } from 'react-router-dom';\nexport const x = useNavigate;\n"
            )
            .is_empty()
        );
        assert!(
            ts(
                "src/components/ui/link/link.tsx",
                "import { Link as RouterLink } from 'react-router';\nexport const Link = RouterLink;\n"
            )
            .is_empty()
        );
    }

    #[test]
    fn silent_on_a_store_module_file() {
        // bulletproof-react itself co-locates a widget's store under
        // `components/ui/<widget>/` (`notifications-store.ts` next to
        // `notifications.tsx`) — the store's own module is supposed to
        // import zustand; it isn't "the view depending on it."
        assert!(
            ts(
                "src/components/ui/notifications/notifications-store.ts",
                "import { create } from 'zustand';\nexport const useNotifications = create(() => ({}));\n"
            )
            .is_empty()
        );
    }

    #[test]
    fn silent_outside_the_view_layer() {
        assert!(
            ts(
                "src/features/auth/hooks/useLogin.ts",
                "import { useQuery } from '@tanstack/react-query';\n"
            )
            .is_empty()
        );
    }

    #[test]
    fn silent_on_a_plain_component_prop_import() {
        assert!(
            ts(
                "src/components/UserCard.tsx",
                "import { Button } from './Button';\n"
            )
            .is_empty()
        );
    }

    #[test]
    fn silent_on_a_type_only_import() {
        assert!(
            ts(
                "src/components/UserCard.tsx",
                "import type { QueryClient } from '@tanstack/react-query';\nexport type X = QueryClient;\n"
            )
            .is_empty()
        );
        assert!(
            ts(
                "src/components/UserCard.tsx",
                "import type { InfraLogger } from '../infra/logger';\nexport type X = InfraLogger;\n"
            )
            .is_empty()
        );
    }

    #[test]
    fn silent_in_a_storybook_file() {
        assert!(
            ts(
                "src/components/LoginForm.stories.tsx",
                "import { create } from 'zustand';\nexport const x = create;\n"
            )
            .is_empty()
        );
    }

    #[test]
    fn silent_when_the_path_is_excepted() {
        let file = SourceFile::new(
            "src/components/LegacyWidget/index.tsx",
            "import { create } from 'zustand';\n",
            LanguageIdentifier::typescript(),
        )
        .unwrap();
        let ast = vord_parser_typescript::TypeScriptParser::new()
            .parse(&file)
            .unwrap();
        let rule = NoDataLayerImportInViewRule::with_exceptions(vec![
            "src/components/LegacyWidget/**".to_string(),
        ]);
        assert!(rule.check(&file, &ast).is_empty());
    }
}
