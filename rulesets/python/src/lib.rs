//! Python-specific rules: idioms and anti-patterns that only make sense
//! for this language.

mod common;

mod assert_used;
mod async_function_with_sync_blocking_call;
mod bare_except;
mod bind_all_interfaces;
mod bool_comparison;
mod broad_exception_swallowed;
mod celery_task_missing_timeout;
mod debugger_left_in_code;
mod django_debug_true;
mod django_queryset_evaluated_in_loop;
mod eager_logging_interpolation;
mod exception_swallowed_pass_only;
mod flask_debug_true;
mod flask_secret_key_hardcoded;
mod global_mutable_singleton;
mod global_statement;
mod hardcoded_local_path;
mod insecure_tempfile;
mod len_as_condition;
mod literal_identity_comparison;
mod logging_logger_root_usage;
mod missing_docstring_on_public_api;
mod missing_type_annotations;
mod modern_type_syntax;
mod mutable_class_attribute;
mod mutable_default_argument;
mod mutable_default_in_dataclass_field;
mod naive_utcnow;
mod nested_comprehension;
mod none_comparison;
mod numpy_float_comparison_eq;
mod open_without_encoding;
mod os_system_usage;
mod pandas_chained_assignment;
mod paramiko_insecure_host_key_policy;
mod pickle_load_untrusted_data;
mod print_debug_left_in_code;
mod raise_generic_exception;
mod raise_without_from;
mod requests_missing_timeout;
mod requests_verify_false;
mod resource_opened_without_context_manager;
mod ruff_adapter;
mod sql_injection;
mod sqlalchemy_text_without_bind;
mod subprocess_popen_without_close;
mod subprocess_shell_true;
mod tarfile_unsafe_extraction;
mod temporary_file_with_static_name;
mod threading_mixed_with_asyncio;
mod type_comparison;
mod type_hint_none_return_mismatch;
mod unclosed_open_file;
mod unsafe_random_module_for_security;
mod unsafe_yaml_load;
mod unused_loop_variable;
mod wildcard_import;
mod xml_xxe;

pub use common::is_test_file;
pub use common::other_kind_name;
pub use assert_used::AssertUsedRule;
pub use async_function_with_sync_blocking_call::AsyncFunctionWithSyncBlockingCallRule;
pub use bare_except::BareExceptRule;
pub use bind_all_interfaces::BindAllInterfacesRule;
pub use bool_comparison::BoolComparisonRule;
pub use broad_exception_swallowed::BroadExceptionSwallowedRule;
pub use celery_task_missing_timeout::CeleryTaskMissingTimeoutRule;
pub use debugger_left_in_code::DebuggerLeftInCodeRule;
pub use django_debug_true::DjangoDebugTrueRule;
pub use django_queryset_evaluated_in_loop::DjangoQuerysetEvaluatedInLoopRule;
pub use eager_logging_interpolation::EagerLoggingInterpolationRule;
pub use exception_swallowed_pass_only::ExceptionSwallowedPassOnlyRule;
pub use flask_debug_true::FlaskDebugTrueRule;
pub use flask_secret_key_hardcoded::FlaskSecretKeyHardcodedRule;
pub use global_mutable_singleton::GlobalMutableSingletonRule;
pub use global_statement::GlobalStatementRule;
pub use hardcoded_local_path::HardcodedLocalPathRule;
pub use insecure_tempfile::InsecureTempfileRule;
pub use len_as_condition::LenAsConditionRule;
pub use literal_identity_comparison::LiteralIdentityComparisonRule;
pub use logging_logger_root_usage::LoggingLoggerRootUsageRule;
pub use missing_docstring_on_public_api::MissingDocstringOnPublicApiRule;
pub use missing_type_annotations::MissingTypeAnnotationsRule;
pub use modern_type_syntax::ModernTypeSyntaxRule;
pub use mutable_class_attribute::MutableClassAttributeRule;
pub use mutable_default_argument::MutableDefaultArgumentRule;
pub use mutable_default_in_dataclass_field::MutableDefaultInDataclassFieldRule;
pub use naive_utcnow::NaiveUtcnowRule;
pub use nested_comprehension::NestedComprehensionRule;
pub use none_comparison::NoneComparisonRule;
pub use numpy_float_comparison_eq::NumpyFloatComparisonEqRule;
pub use open_without_encoding::OpenWithoutEncodingRule;
pub use os_system_usage::OsSystemUsageRule;
pub use pandas_chained_assignment::PandasChainedAssignmentRule;
pub use paramiko_insecure_host_key_policy::ParamikoInsecureHostKeyPolicyRule;
pub use pickle_load_untrusted_data::PickleLoadUntrustedDataRule;
pub use print_debug_left_in_code::PrintDebugLeftInCodeRule;
pub use raise_generic_exception::RaiseGenericExceptionRule;
pub use raise_without_from::RaiseWithoutFromRule;
pub use requests_missing_timeout::RequestsMissingTimeoutRule;
pub use requests_verify_false::RequestsVerifyFalseRule;
pub use resource_opened_without_context_manager::ResourceOpenedWithoutContextManagerRule;
pub use ruff_adapter::RuffAdapterRule;
pub use sql_injection::SqlInjectionRule;
pub use sqlalchemy_text_without_bind::SqlalchemyTextWithoutBindRule;
pub use subprocess_popen_without_close::SubprocessPopenWithoutCloseRule;
pub use subprocess_shell_true::SubprocessShellTrueRule;
pub use tarfile_unsafe_extraction::TarfileUnsafeExtractionRule;
pub use temporary_file_with_static_name::TemporaryFileWithStaticNameRule;
pub use threading_mixed_with_asyncio::ThreadingMixedWithAsyncioRule;
pub use type_comparison::TypeComparisonRule;
pub use type_hint_none_return_mismatch::TypeHintNoneReturnMismatchRule;
pub use unclosed_open_file::UnclosedOpenFileRule;
pub use unsafe_random_module_for_security::UnsafeRandomModuleForSecurityRule;
pub use unsafe_yaml_load::UnsafeYamlLoadRule;
pub use unused_loop_variable::UnusedLoopVariableRule;
pub use wildcard_import::WildcardImportRule;
pub use xml_xxe::XmlXxeRule;

use vord_rules_engine::Rule;

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
        Box::new(FlaskDebugTrueRule::new()),
        Box::new(BindAllInterfacesRule::new()),
        Box::new(SqlInjectionRule::new()),
        Box::new(DebuggerLeftInCodeRule::new()),
        Box::new(GlobalStatementRule::new()),
        Box::new(WildcardImportRule::new()),
        Box::new(RaiseGenericExceptionRule::new()),
        Box::new(RaiseWithoutFromRule::new()),
        Box::new(NoneComparisonRule::new()),
        Box::new(BoolComparisonRule::new()),
        Box::new(TypeComparisonRule::new()),
        Box::new(LiteralIdentityComparisonRule::new()),
        Box::new(OpenWithoutEncodingRule::new()),
        Box::new(NaiveUtcnowRule::new()),
        Box::new(RequestsMissingTimeoutRule::new()),
        Box::new(EagerLoggingInterpolationRule::new()),
        Box::new(LenAsConditionRule::new()),
        Box::new(NestedComprehensionRule::new()),
        Box::new(UnusedLoopVariableRule::new()),
        Box::new(MutableClassAttributeRule::new()),
        Box::new(MissingTypeAnnotationsRule::new()),
        Box::new(ModernTypeSyntaxRule::new()),
        Box::new(RuffAdapterRule::new()),
        Box::new(UnclosedOpenFileRule::new()),
        Box::new(PrintDebugLeftInCodeRule::new()),
        Box::new(LoggingLoggerRootUsageRule::new()),
        Box::new(DjangoDebugTrueRule::new()),
        Box::new(FlaskSecretKeyHardcodedRule::new()),
        Box::new(SqlalchemyTextWithoutBindRule::new()),
        Box::new(ParamikoInsecureHostKeyPolicyRule::new()),
        Box::new(RequestsVerifyFalseRule::new()),
        Box::new(PickleLoadUntrustedDataRule::new()),
        Box::new(AsyncFunctionWithSyncBlockingCallRule::new()),
        Box::new(ThreadingMixedWithAsyncioRule::new()),
        Box::new(MutableDefaultInDataclassFieldRule::new()),
        Box::new(GlobalMutableSingletonRule::new()),
        Box::new(CeleryTaskMissingTimeoutRule::new()),
        Box::new(OsSystemUsageRule::new()),
        Box::new(SubprocessPopenWithoutCloseRule::new()),
        Box::new(ResourceOpenedWithoutContextManagerRule::new()),
        Box::new(TemporaryFileWithStaticNameRule::new()),
        Box::new(DjangoQuerysetEvaluatedInLoopRule::new()),
        Box::new(HardcodedLocalPathRule::new()),
        Box::new(UnsafeRandomModuleForSecurityRule::new()),
        Box::new(TypeHintNoneReturnMismatchRule::new()),
        Box::new(ExceptionSwallowedPassOnlyRule::new()),
        Box::new(MissingDocstringOnPublicApiRule::new()),
        Box::new(NumpyFloatComparisonEqRule::new()),
        Box::new(PandasChainedAssignmentRule::new()),
    ]
}
