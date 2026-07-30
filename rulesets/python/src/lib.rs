//! Python-specific rules: idioms and anti-patterns that only make sense
//! for this language (mutable default arguments, bare `except:`, unsafe
//! `yaml.load`, `subprocess` shell injection, XXE-prone XML parsing, …).
//! Language-neutral checks (long functions, complexity, TODO comments, …)
//! that also apply to Python live in `rulesets/code-smells`.

mod assert_used;
mod bare_except;
mod bind_all_interfaces;
mod bool_comparison;
mod broad_exception_swallowed;
mod debugger_left_in_code;
mod eager_logging_interpolation;
mod flask_debug_true;
mod global_statement;
mod insecure_tempfile;
mod len_as_condition;
mod literal_identity_comparison;
mod mutable_class_attribute;
mod mutable_default_argument;
mod naive_utcnow;
mod nested_comprehension;
mod none_comparison;
mod open_without_encoding;
mod raise_generic_exception;
mod raise_without_from;
mod requests_missing_timeout;
mod sql_injection;
mod subprocess_shell_true;
mod tarfile_unsafe_extraction;
mod type_comparison;
mod unsafe_yaml_load;
mod unused_loop_variable;
mod wildcard_import;
mod xml_xxe;

pub use assert_used::AssertUsedRule;
pub use bare_except::BareExceptRule;
pub use bind_all_interfaces::BindAllInterfacesRule;
pub use bool_comparison::BoolComparisonRule;
pub use broad_exception_swallowed::BroadExceptionSwallowedRule;
pub use debugger_left_in_code::DebuggerLeftInCodeRule;
pub use eager_logging_interpolation::EagerLoggingInterpolationRule;
pub use flask_debug_true::FlaskDebugTrueRule;
pub use global_statement::GlobalStatementRule;
pub use insecure_tempfile::InsecureTempfileRule;
pub use len_as_condition::LenAsConditionRule;
pub use literal_identity_comparison::LiteralIdentityComparisonRule;
pub use mutable_class_attribute::MutableClassAttributeRule;
pub use mutable_default_argument::MutableDefaultArgumentRule;
pub use naive_utcnow::NaiveUtcnowRule;
pub use nested_comprehension::NestedComprehensionRule;
pub use none_comparison::NoneComparisonRule;
pub use open_without_encoding::OpenWithoutEncodingRule;
pub use raise_generic_exception::RaiseGenericExceptionRule;
pub use raise_without_from::RaiseWithoutFromRule;
pub use requests_missing_timeout::RequestsMissingTimeoutRule;
pub use sql_injection::SqlInjectionRule;
pub use subprocess_shell_true::SubprocessShellTrueRule;
pub use tarfile_unsafe_extraction::TarfileUnsafeExtractionRule;
pub use type_comparison::TypeComparisonRule;
pub use unsafe_yaml_load::UnsafeYamlLoadRule;
pub use unused_loop_variable::UnusedLoopVariableRule;
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
        Box::new(TarfileUnsafeExtractionRule::new()),
        Box::new(UnsafeYamlLoadRule::new()),
        Box::new(XmlXxeRule::new()),
        Box::new(InsecureTempfileRule::new()),
        Box::new(WildcardImportRule::new()),
        Box::new(TypeComparisonRule::new()),
        Box::new(GlobalStatementRule::new()),
        Box::new(EagerLoggingInterpolationRule::new()),
        Box::new(NoneComparisonRule::new()),
        Box::new(BoolComparisonRule::new()),
        Box::new(LiteralIdentityComparisonRule::new()),
        Box::new(LenAsConditionRule::new()),
        Box::new(RequestsMissingTimeoutRule::new()),
        Box::new(FlaskDebugTrueRule::new()),
        Box::new(BindAllInterfacesRule::new()),
        Box::new(SqlInjectionRule::new()),
        Box::new(DebuggerLeftInCodeRule::new()),
        Box::new(OpenWithoutEncodingRule::new()),
        Box::new(NaiveUtcnowRule::new()),
        Box::new(MutableClassAttributeRule::new()),
        Box::new(NestedComprehensionRule::new()),
        Box::new(RaiseGenericExceptionRule::new()),
        Box::new(RaiseWithoutFromRule::new()),
        Box::new(UnusedLoopVariableRule::new()),
    ]
}
