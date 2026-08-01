//! OWASP-oriented security rules. Each rule is an independent plugin
//! implementing [`yunq_rules_engine::Rule`]; the engine never changes when
//! rules are added (Open/Closed).

mod command_exec;
mod cross_file_injection;
mod custom_pattern;
mod disabled_cert_validation;
mod dockerfile_root;
mod eval_usage;
mod hardcoded_jwt_secret;
mod hardcoded_secret;
mod injection;
mod insecure_deserialization;
mod insecure_file_permissions;
mod insecure_random;
mod nosql_injection;
mod path_traversal;
mod path_traversal_java;
mod permissive_cors;
mod post_message_wildcard;
mod prototype_pollution;
mod sql_injection_concat;
mod ssrf;
mod ssrf_unvalidated_url;
mod timing_attack;
mod unverified_jwt;
mod weak_crypto;
mod weak_crypto_hash;
mod xss;
mod xss_java;

pub use command_exec::CommandExecHotspotRule;
pub use cross_file_injection::CrossFileInjectionRule;
pub use custom_pattern::CustomPatternRule;
pub use disabled_cert_validation::DisabledCertValidationRule;
pub use dockerfile_root::DockerfileRootUserRule;
pub use eval_usage::EvalUsageRule;
pub use hardcoded_jwt_secret::HardcodedJwtSecretRule;
pub use hardcoded_secret::HardcodedSecretRule;
pub use injection::InjectionRule;
pub use insecure_deserialization::InsecureDeserializationRule;
pub use insecure_file_permissions::InsecureFilePermissionsRule;
pub use insecure_random::InsecureRandomRule;
pub use nosql_injection::NoSqlInjectionRule;
pub use path_traversal::PathTraversalRule;
pub use path_traversal_java::PathTraversalJavaRule;
pub use permissive_cors::PermissiveCorsRule;
pub use post_message_wildcard::PostMessageWildcardRule;
pub use prototype_pollution::PrototypePollutionRule;
pub use sql_injection_concat::SqlInjectionConcatRule;
pub use ssrf::SsrfRule;
pub use ssrf_unvalidated_url::SsrfUnvalidatedUrlRule;
pub use timing_attack::TimingAttackRule;
pub use unverified_jwt::UnverifiedJwtRule;
pub use weak_crypto::WeakCryptoRule;
pub use weak_crypto_hash::WeakCryptoHashRule;
pub use xss::XssRule;
pub use xss_java::XssJavaRule;

use yunq_rules_engine::{CrossFileRule, Rule};

/// Every rule in this ruleset, for composition roots.
pub fn all_rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(HardcodedSecretRule::new()),
        Box::new(EvalUsageRule::new()),
        Box::new(InjectionRule::new()),
        Box::new(CommandExecHotspotRule::new()),
        Box::new(DockerfileRootUserRule::new()),
        Box::new(WeakCryptoRule::new()),
        Box::new(InsecureDeserializationRule::new()),
        Box::new(InsecureRandomRule::new()),
        Box::new(DisabledCertValidationRule::new()),
        Box::new(XssRule::new()),
        Box::new(XssJavaRule::new()),
        Box::new(PermissiveCorsRule::new()),
        Box::new(PostMessageWildcardRule::new()),
        Box::new(PathTraversalRule::new()),
        Box::new(PathTraversalJavaRule::new()),
        Box::new(UnverifiedJwtRule::new()),
        Box::new(SsrfRule::new()),
        Box::new(SsrfUnvalidatedUrlRule::new()),
        Box::new(InsecureFilePermissionsRule::new()),
        Box::new(NoSqlInjectionRule::new()),
        Box::new(PrototypePollutionRule::new()),
        Box::new(TimingAttackRule::new()),
        Box::new(SqlInjectionConcatRule::new()),
        Box::new(HardcodedJwtSecretRule::new()),
        Box::new(WeakCryptoHashRule::new()),
    ]
}

/// Every cross-file rule in this ruleset, for composition roots.
pub fn all_cross_rules() -> Vec<Box<dyn CrossFileRule>> {
    vec![Box::new(CrossFileInjectionRule::new())]
}
