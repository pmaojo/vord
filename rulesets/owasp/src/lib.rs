//! OWASP-oriented security rules. Each rule is an independent plugin
//! implementing [`yunq_rules_engine::Rule`]; the engine never changes when
//! rules are added (Open/Closed).

mod command_exec;
mod cross_file_injection;
mod custom_pattern;
mod disabled_cert_validation;
mod dockerfile_root;
mod eval_usage;
mod hardcoded_secret;
mod injection;
mod insecure_deserialization;
mod insecure_random;
mod path_traversal;
mod permissive_cors;
mod ssrf;
mod weak_crypto;
mod xss;

pub use command_exec::CommandExecHotspotRule;
pub use cross_file_injection::CrossFileInjectionRule;
pub use custom_pattern::CustomPatternRule;
pub use disabled_cert_validation::DisabledCertValidationRule;
pub use dockerfile_root::DockerfileRootUserRule;
pub use eval_usage::EvalUsageRule;
pub use hardcoded_secret::HardcodedSecretRule;
pub use injection::InjectionRule;
pub use insecure_deserialization::InsecureDeserializationRule;
pub use insecure_random::InsecureRandomRule;
pub use path_traversal::PathTraversalRule;
pub use permissive_cors::PermissiveCorsRule;
pub use ssrf::SsrfRule;
pub use weak_crypto::WeakCryptoRule;
pub use xss::XssRule;

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
        Box::new(PermissiveCorsRule::new()),
        Box::new(PathTraversalRule::new()),
        Box::new(SsrfRule::new()),
    ]
}

/// Every whole-program rule in this ruleset, for composition roots.
pub fn all_cross_rules() -> Vec<Box<dyn CrossFileRule>> {
    vec![Box::new(CrossFileInjectionRule::new())]
}
