//! Dedicated secrets-detection ruleset (Phase 2). Extends the Phase-1
//! `owasp:hardcoded-secret` heuristic (credential-named variables holding
//! literals, plus a handful of substring provider signatures) with:
//!
//! - [`HighEntropyStringRule`]: Shannon-entropy scoring of string literals,
//!   catching random-looking tokens that don't match any known format —
//!   the generic net for private/self-hosted services.
//! - [`all_provider_rules`]: one regex rule per well-known credential
//!   format (AWS, GCP, Azure, Stripe, GitHub, Slack, npm, JWT, private
//!   keys), each with its own rule id so profiles can tune them
//!   independently.
//! - [`CustomSecretPatternRule`]: a user-supplied regex pattern, for
//!   private/internal service token formats vord has no built-in rule for.
//!   Not included in [`all_rules`] since it needs a pattern parameter —
//!   construct it from configuration and add it to the rule set alongside
//!   these.
//!
//! Each rule is an independent plugin implementing
//! [`vord_rules_engine::Rule`]; the engine never changes when rules are
//! added (Open/Closed) — same architecture as `rulesets/owasp`.

mod custom_pattern;
mod dotenv_committed;
mod entropy;
mod provider_patterns;
mod secret_in_config_example;
mod secret_in_documentation_snippet;
mod secret_in_exception_message;
mod secret_in_log_message;
mod secret_in_test_fixture;
mod secret_literal;

pub use custom_pattern::CustomSecretPatternRule;
pub use dotenv_committed::DotenvFileCommittedRule;
pub use entropy::{HighEntropyStringRule, shannon_entropy};
pub use provider_patterns::{RegexSecretRule, all_provider_rules};
pub use secret_in_config_example::SecretInConfigExampleRule;
pub use secret_in_documentation_snippet::SecretInDocumentationSnippetRule;
pub use secret_in_exception_message::SecretInExceptionMessageRule;
pub use secret_in_log_message::SecretInLogMessageRule;
pub use secret_in_test_fixture::SecretInTestFixtureRule;

use vord_rules_engine::Rule;

/// Every built-in rule in this ruleset, for composition roots. Excludes
/// [`CustomSecretPatternRule`], which requires a user-supplied pattern.
pub fn all_rules() -> Vec<Box<dyn Rule>> {
    let mut rules: Vec<Box<dyn Rule>> = vec![
        Box::new(HighEntropyStringRule::new()),
        Box::new(DotenvFileCommittedRule::new()),
        Box::new(SecretInLogMessageRule::new()),
        Box::new(SecretInExceptionMessageRule::new()),
        Box::new(SecretInTestFixtureRule::new()),
        Box::new(SecretInConfigExampleRule::new()),
        Box::new(SecretInDocumentationSnippetRule::new()),
    ];
    rules.extend(all_provider_rules());
    rules
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_rules_have_unique_ids() {
        let rules = all_rules();
        let mut ids: Vec<&str> = rules.iter().map(|r| r.id().as_str()).collect();
        ids.sort_unstable();
        let mut deduped = ids.clone();
        deduped.dedup();
        assert_eq!(
            ids.len(),
            deduped.len(),
            "duplicate rule ids in secrets ruleset"
        );
        assert!(
            ids.len() >= 18,
            "expected at least 18 built-in secrets rules, got {}",
            ids.len()
        );
    }
}
