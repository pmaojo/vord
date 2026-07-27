//! Python-specific rules: idioms and anti-patterns that only make sense
//! for this language (mutable default arguments, bare `except:`, unsafe
//! `yaml.load`, `subprocess` shell injection, XXE-prone XML parsing, …).
//! Language-neutral checks (long functions, complexity, TODO comments, …)
//! that also apply to Python live in `rulesets/code-smells`.

mod assert_used;
mod bare_except;
mod broad_exception_swallowed;
mod eager_logging_interpolation;
mod global_statement;
mod insecure_tempfile;
mod mutable_default_argument;
mod subprocess_shell_true;
mod type_comparison;
mod unsafe_yaml_load;
mod wildcard_import;
mod xml_xxe;

pub use assert_used::AssertUsedRule;
pub use bare_except::BareExceptRule;
pub use broad_exception_swallowed::BroadExceptionSwallowedRule;
pub use eager_logging_interpolation::EagerLoggingInterpolationRule;
pub use global_statement::GlobalStatementRule;
pub use insecure_tempfile::InsecureTempfileRule;
pub use mutable_default_argument::MutableDefaultArgumentRule;
pub use subprocess_shell_true::SubprocessShellTrueRule;
pub use type_comparison::TypeComparisonRule;
pub use unsafe_yaml_load::UnsafeYamlLoadRule;
pub use wildcard_import::WildcardImportRule;
pub use xml_xxe::XmlXxeRule;

use yunq_rules_engine::Rule;

/// Every rule in this ruleset, for composition roots.
pub fn all_rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(MutableDefaultArgumentRule::new()),
        Box::new(BareExceptRule::new()),
        Box::new(BroadExceptionSwallowedRule::new()),
        Box::new(AssertUsedRule::new()),
        Box::new(SubprocessShellTrueRule::new()),
        Box::new(UnsafeYamlLoadRule::new()),
        Box::new(XmlXxeRule::new()),
        Box::new(InsecureTempfileRule::new()),
        Box::new(WildcardImportRule::new()),
        Box::new(TypeComparisonRule::new()),
        Box::new(GlobalStatementRule::new()),
        Box::new(EagerLoggingInterpolationRule::new()),
    ]
}
