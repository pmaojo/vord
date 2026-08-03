//! Rule: a presentational file (`src/components/**` or
//! `src/features/**/components/**`) importing a data-layer library
//! (TanStack/React Query, Zustand, React Router) or reaching straight into
//! `src/infra/**` — bulletproof-react's split between "how it looks" and
//! "where the data comes from" only holds if the view layer never imports
//! either. Per-file (`Rule`): a file's own path and its own import list are
//! all this needs, the same shape as
//! `architecture:framework-in-domain` (`rulesets/architecture/src/framework_in_domain.rs`),
//! scanning a curated roster instead of inferring anything.

use globset::GlobSet;
use vord_ast::{AstNode, LanguageIdentifier, SourceFile};
use vord_import_graph::{imported_modules, matches_module};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

use crate::common::{build_globset, is_excepted, is_infra_specifier, is_view_path, is_type_only_import_span};

struct RosterEntry {
    module: &'static str,
    concern: &'static str,
}

const ROSTER: &[RosterEntry] = &[
    RosterEntry {
        module: "@tanstack/react-query",
        concern: "the data-fetching layer",
    },
    RosterEntry {
        module: "react-query",
        concern: "the data-fetching layer",
    },
    RosterEntry {
        module: "zustand",
        concern: "global client state",
    },
    RosterEntry {
        module: "react-router-dom",
        concern: "routing",
    },
    RosterEntry {
        module: "react-router",
        concern: "routing",
    },
];

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
        if vord_rules_engine::is_test_only_path(file.path()) {
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
                    return Some(Finding::new(
                        format!(
                            "component code imports `{}` (an infra module) — the view layer must not talk to infra directly; consume it through a feature hook and pass the result down as a prop",
                            import.specifier
                        ),
                        import.span,
                    ));
                }
                let hit = ROSTER
                    .iter()
                    .find(|entry| matches_module(&import.specifier, entry.module))?;
                Some(Finding::new(
                    format!(
                        "component code imports `{}` ({}) — the view layer must not depend on it directly; put the {} call in a feature hook and pass the result down as a prop",
                        import.specifier, hit.concern, hit.module,
                    ),
                    import.span,
                ))
            })
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
            findings[0]
                .message
                .contains("component code imports `@tanstack/react-query`"),
            "{}",
            findings[0].message
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
    fn flags_react_router() {
        let findings = ts(
            "src/components/NavLink.tsx",
            "import { useNavigate } from 'react-router-dom';\nexport const x = useNavigate;\n",
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("routing"));
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
