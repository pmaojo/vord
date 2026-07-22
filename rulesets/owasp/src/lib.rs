//! OWASP-oriented security rules. Each rule is an independent plugin
//! implementing [`yunq_rules_engine::Rule`]; the engine never changes when
//! rules are added (Open/Closed).

mod command_exec;
mod cross_file_injection;
mod eval_usage;
mod hardcoded_secret;
mod injection;

pub use command_exec::CommandExecHotspotRule;
pub use cross_file_injection::CrossFileInjectionRule;
pub use eval_usage::EvalUsageRule;
pub use hardcoded_secret::HardcodedSecretRule;
pub use injection::InjectionRule;

use yunq_rules_engine::{CrossFileRule, Rule};

/// Every rule in this ruleset, for composition roots.
pub fn all_rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(HardcodedSecretRule::new()),
        Box::new(EvalUsageRule::new()),
        Box::new(InjectionRule::new()),
        Box::new(CommandExecHotspotRule::new()),
    ]
}

/// Every whole-program rule in this ruleset, for composition roots.
pub fn all_cross_rules() -> Vec<Box<dyn CrossFileRule>> {
    vec![Box::new(CrossFileInjectionRule::new())]
}
