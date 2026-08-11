//! The `vite-react-frontend-starter` profile: a curated activation list for
//! Vite+React projects that follow the bulletproof-react layered
//! convention (`src/components`, `src/features/<feature>/{api,hooks,components}`,
//! `src/infra`). Mirrors `builtin.rs`'s pattern — literal rule ids and
//! severities, cross-checked by hand against each rule's real
//! `RuleId::new(...)`/`default_severity()` (this crate can't depend on the
//! ruleset crates without a dependency cycle; see `builtin.rs`'s module
//! docs for the full rationale).
//!
//! Composed from three sources: this starter's own `rulesets/vite-react`
//! rules (the layering/transport/config checks bulletproof-react needs that
//! no generic ruleset already had), a curated subset of `rulesets/react`
//! (the folder-structure and hygiene rules that already implement this
//! starter's norms — reused, not reimplemented), and the generic
//! security/quality baseline (`secrets:*`, a subset of `owasp:*` and
//! `typescript:*`) every TypeScript project wants regardless of its own
//! directory convention.

use crate::{QualityProfile, RuleId, Severity};

/// The starter profile's name, resolved by [`crate::profile_by_name`] and
/// passed to `--profile` on the CLI.
pub const VITE_REACT_FRONTEND_STARTER_NAME: &str = "vite-react-frontend-starter";

fn rule(raw: &str) -> RuleId {
    RuleId::new(raw).expect("starter rule id is valid namespace:code")
}

/// `rulesets/vite-react`'s own rules — this starter's layered-architecture
/// enforcement (`rulesets/vite-react/src/lib.rs`'s `all_rules()`).
fn vite_react_own_activations() -> Vec<(RuleId, Severity)> {
    vec![
        (
            rule("vite-react:no-data-layer-import-in-view"),
            Severity::Blocker,
        ),
        (
            rule("vite-react:no-transport-call-in-view"),
            Severity::Blocker,
        ),
        (
            rule("vite-react:data-hook-outside-api-dir"),
            Severity::Major,
        ),
        (
            rule("vite-react:transport-client-outside-infra"),
            Severity::Blocker,
        ),
        (rule("vite-react:hardcoded-base-url"), Severity::Major),
        (rule("vite-react:tailwind-space-between"), Severity::Minor),
        (rule("vite-react:tailwind-redundant-size"), Severity::Minor),
    ]
}

/// `rulesets/react` rules that already implement (or directly support) this
/// starter's own conventions — reused as-is, never reimplemented.
///
/// `react:feature-directory-isolation` is deliberately *not* here: it bans
/// any deep import into a feature's subdirectories from outside that
/// feature, which is stricter than this starter's actual convention.
/// Checked against the reference implementation's own enforced lint config
/// (`alan2207/bulletproof-react`, `apps/react-vite/.eslintrc.cjs`'s
/// `import/no-restricted-paths`): it only forbids *cross-feature* imports
/// (feature A reaching into feature B) and the `features -> app` direction —
/// `src/app/routes/**` importing straight from
/// `features/<feature>/api/...`/`.../components/...` is explicitly allowed,
/// and the reference app does exactly that throughout. Activating this rule
/// here fired 8 times on that reference implementation alone, all on
/// idiomatic code.
fn react_reused_activations() -> Vec<(RuleId, Severity)> {
    vec![
        (rule("react:bulletproof-folder-structure"), Severity::Major),
        (rule("react:no-fetch-in-useeffect"), Severity::Major),
        (rule("react:rules-of-hooks-naming"), Severity::Major),
        (rule("react:rules-of-hooks-conditional"), Severity::Critical),
        (rule("react:exhaustive-deps"), Severity::Major),
        (rule("react:unsafe-target-blank"), Severity::Major),
        (rule("react:jsx-img-missing-alt"), Severity::Major),
        (rule("react:missing-list-key"), Severity::Major),
        (rule("react:no-async-client-component"), Severity::Major),
    ]
}

/// `secrets:*` (all of it — every project regardless of stack must not ship
/// a credential) and the OWASP/TypeScript baseline generic enough to apply
/// to any TypeScript/JSX codebase, same severities as `builtin.rs`'s
/// `generic_activations`/`typescript_activations` cross-check.
fn baseline_activations() -> Vec<(RuleId, Severity)> {
    vec![
        // rulesets/secrets — provider-pattern rules.
        (rule("secrets:high-entropy-string"), Severity::Major),
        (rule("secrets:aws-access-key-id"), Severity::Blocker),
        (rule("secrets:aws-secret-access-key"), Severity::Blocker),
        (rule("secrets:gcp-api-key"), Severity::Blocker),
        (rule("secrets:gcp-service-account-key"), Severity::Blocker),
        (
            rule("secrets:azure-storage-connection-string"),
            Severity::Blocker,
        ),
        (rule("secrets:azure-sas-token"), Severity::Blocker),
        (rule("secrets:stripe-live-key"), Severity::Blocker),
        (rule("secrets:private-key-block"), Severity::Blocker),
        (rule("secrets:github-token"), Severity::Blocker),
        (rule("secrets:slack-token"), Severity::Blocker),
        (rule("secrets:npm-token"), Severity::Blocker),
        (rule("secrets:jwt-like-token"), Severity::Blocker),
        // rulesets/owasp
        (rule("owasp:hardcoded-secret"), Severity::Blocker),
        (rule("owasp:xss"), Severity::Blocker),
        (rule("owasp:eval-usage"), Severity::Critical),
        (rule("owasp:injection"), Severity::Blocker),
        (rule("owasp:ssrf"), Severity::Blocker),
        (rule("owasp:permissive-cors"), Severity::Major),
        // rulesets/typescript
        (rule("typescript:loose-equality"), Severity::Minor),
        (rule("typescript:var-declaration"), Severity::Minor),
        (rule("typescript:leftover-debug-statement"), Severity::Minor),
        (
            rule("typescript:promise-then-without-catch"),
            Severity::Major,
        ),
        (rule("typescript:json-parse-unguarded"), Severity::Major),
        (
            rule("typescript:sensitive-data-in-web-storage"),
            Severity::Critical,
        ),
        (rule("typescript:innerhtml-assignment"), Severity::Critical),
        (rule("typescript:swallowed-exception"), Severity::Major),
    ]
}

fn vite_react_frontend_starter_activations() -> Vec<(RuleId, Severity)> {
    let mut activations = vite_react_own_activations();
    activations.extend(react_reused_activations());
    activations.extend(baseline_activations());
    activations
}

/// The `vite-react-frontend-starter` profile, resolved by
/// [`crate::profile_by_name`].
pub fn vite_react_frontend_starter() -> QualityProfile {
    QualityProfile::from_activations(
        VITE_REACT_FRONTEND_STARTER_NAME,
        vite_react_frontend_starter_activations(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_name_is_stable() {
        assert_eq!(
            vite_react_frontend_starter().name(),
            "vite-react-frontend-starter"
        );
    }

    #[test]
    fn activates_its_own_layering_rules_at_the_documented_severity() {
        let profile = vite_react_frontend_starter();
        assert_eq!(
            profile.severity_of(&RuleId::new("vite-react:no-data-layer-import-in-view").unwrap()),
            Some(Severity::Blocker)
        );
        assert_eq!(
            profile.severity_of(&RuleId::new("vite-react:tailwind-space-between").unwrap()),
            Some(Severity::Minor)
        );
        assert_eq!(
            profile.severity_of(&RuleId::new("vite-react:tailwind-redundant-size").unwrap()),
            Some(Severity::Minor)
        );
    }

    #[test]
    fn reuses_react_and_secrets_rules() {
        let profile = vite_react_frontend_starter();
        assert!(profile.is_active(&RuleId::new("react:bulletproof-folder-structure").unwrap()));
        assert!(profile.is_active(&RuleId::new("secrets:aws-access-key-id").unwrap()));
        assert!(profile.is_active(&RuleId::new("owasp:hardcoded-secret").unwrap()));
    }

    #[test]
    fn does_not_activate_feature_directory_isolation() {
        // Stricter than the reference implementation's own enforced
        // boundary (see `react_reused_activations`'s doc comment) — not
        // part of this profile.
        assert!(
            !vite_react_frontend_starter()
                .is_active(&RuleId::new("react:feature-directory-isolation").unwrap())
        );
    }

    #[test]
    fn does_not_activate_rust_or_python_specific_rules() {
        let profile = vite_react_frontend_starter();
        assert!(!profile.is_active(&RuleId::new("rust:mem-forget").unwrap()));
        assert!(!profile.is_active(&RuleId::new("python:bare-except").unwrap()));
    }
}
