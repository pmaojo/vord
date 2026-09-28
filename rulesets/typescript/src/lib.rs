//! Vanilla TypeScript/JavaScript rules: language idioms and DOM/browser
//! anti-patterns.

mod async_function_without_await;
mod boolean_naming;
mod broad_catch_with_unknown_error_type;
mod buffer_noassert;
mod business_logic_in_type_guards;
mod common;
mod constant_return_value;
mod dynamic_regexp_source;
mod enum_stringly_typed;
mod generic_type_unused_parameter;
mod implicit_any_on_rest_params;
mod implicit_any_return_in_arrow_function;
mod index_signature_overuse;
mod innerhtml_assignment;
mod interface_duplicated_structure;
mod json_parse_unguarded;
mod leftover_debug_statement;
mod long_if_else_chain;
mod loose_equality;
mod mass_assignment_from_request_body;
mod math_random_for_token;
mod max_function_nesting_depth;
mod missing_exhaustive_switch;
mod namespace_usage_in_module_code;
mod negated_ternary_condition;
mod nested_ternary;
mod no_explicit_any;
mod non_null_assertion_overuse;
mod open_redirect_location_assignment;
mod optional_chaining_on_definite_values;
mod oxlint_adapter;
mod prefer_array_at;
mod prefer_default_parameters;
mod prefer_export_from;
mod prefer_globalthis_over_window;
mod prefer_regexp_exec;
mod prefer_replaceall;
mod promise_not_awaited;
mod promise_return_type_mismatch;
mod promise_then_without_catch;
mod redos_nested_quantifier;
mod redundant_type_alias;
mod redundant_type_assertion;
mod sensitive_data_in_web_storage;
mod sort_without_compare;
mod swallowed_exception;
mod ts_ignore_without_justification;
mod type_alias_overused_for_naming_only;
mod type_level_logic_too_complex;
mod unbound_this_in_method;
mod unguarded_last_element_access;
mod unknown_not_narrowed_before_use;
mod var_declaration;

pub use async_function_without_await::AsyncFunctionWithoutAwaitRule;
pub use boolean_naming::BooleanNamingRule;
pub use broad_catch_with_unknown_error_type::BroadCatchWithUnknownErrorTypeRule;
pub use buffer_noassert::BufferNoassertRule;
pub use business_logic_in_type_guards::BusinessLogicInTypeGuardsRule;
pub use constant_return_value::ConstantReturnValueRule;
pub use dynamic_regexp_source::DynamicRegexpSourceRule;
pub use enum_stringly_typed::EnumStringlyTypedRule;
pub use generic_type_unused_parameter::GenericTypeUnusedParameterRule;
pub use implicit_any_on_rest_params::ImplicitAnyOnRestParamsRule;
pub use implicit_any_return_in_arrow_function::ImplicitAnyReturnInArrowFunctionRule;
pub use index_signature_overuse::IndexSignatureOveruseRule;
pub use innerhtml_assignment::InnerHtmlAssignmentRule;
pub use interface_duplicated_structure::InterfaceDuplicatedStructureRule;
pub use json_parse_unguarded::JsonParseUnguardedRule;
pub use leftover_debug_statement::LeftoverDebugStatementRule;
pub use long_if_else_chain::LongIfElseChainRule;
pub use loose_equality::LooseEqualityRule;
pub use mass_assignment_from_request_body::MassAssignmentFromRequestBodyRule;
pub use math_random_for_token::MathRandomForTokenRule;
pub use max_function_nesting_depth::MaxFunctionNestingDepthRule;
pub use missing_exhaustive_switch::MissingExhaustiveSwitchRule;
pub use namespace_usage_in_module_code::NamespaceUsageInModuleCodeRule;
pub use negated_ternary_condition::NegatedTernaryConditionRule;
pub use nested_ternary::NestedTernaryRule;
pub use no_explicit_any::NoExplicitAnyRule;
pub use non_null_assertion_overuse::NonNullAssertionOveruseRule;
pub use open_redirect_location_assignment::OpenRedirectLocationAssignmentRule;
pub use optional_chaining_on_definite_values::OptionalChainingOnDefiniteValuesRule;
pub use oxlint_adapter::OxlintAdapterRule;
pub use prefer_array_at::PreferArrayAtRule;
pub use prefer_default_parameters::PreferDefaultParametersRule;
pub use prefer_export_from::PreferExportFromRule;
pub use prefer_globalthis_over_window::PreferGlobalThisOverWindowRule;
pub use prefer_regexp_exec::PreferRegExpExecRule;
pub use prefer_replaceall::PreferReplaceAllRule;
pub use promise_not_awaited::PromiseNotAwaitedRule;
pub use promise_return_type_mismatch::PromiseReturnTypeMismatchRule;
pub use promise_then_without_catch::PromiseThenWithoutCatchRule;
pub use redos_nested_quantifier::RedosNestedQuantifierRule;
pub use redundant_type_alias::RedundantTypeAliasRule;
pub use redundant_type_assertion::RedundantTypeAssertionRule;
pub use sensitive_data_in_web_storage::SensitiveDataInWebStorageRule;
pub use sort_without_compare::SortWithoutCompareRule;
pub use swallowed_exception::SwallowedExceptionRule;
pub use ts_ignore_without_justification::TsIgnoreWithoutJustificationRule;
pub use type_alias_overused_for_naming_only::TypeAliasOverusedForNamingOnlyRule;
pub use type_level_logic_too_complex::TypeLevelLogicTooComplexRule;
pub use unbound_this_in_method::UnboundThisInMethodRule;
pub use unguarded_last_element_access::UnguardedLastElementAccessRule;
pub use unknown_not_narrowed_before_use::UnknownNotNarrowedBeforeUseRule;
pub use var_declaration::VarDeclarationRule;

use vord_rules_engine::Rule;

/// Every rule in this ruleset, for composition roots.
pub fn all_rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(DynamicRegexpSourceRule::new()),
        Box::new(InnerHtmlAssignmentRule::new()),
        Box::new(JsonParseUnguardedRule::new()),
        Box::new(LeftoverDebugStatementRule::new()),
        Box::new(LooseEqualityRule::new()),
        Box::new(MassAssignmentFromRequestBodyRule::new()),
        Box::new(MathRandomForTokenRule::new()),
        Box::new(OpenRedirectLocationAssignmentRule::new()),
        Box::new(PromiseThenWithoutCatchRule::new()),
        Box::new(RedosNestedQuantifierRule::new()),
        Box::new(SensitiveDataInWebStorageRule::new()),
        Box::new(SwallowedExceptionRule::new()),
        Box::new(VarDeclarationRule::new()),
        Box::new(BooleanNamingRule::new()),
        Box::new(NoExplicitAnyRule::new()),
        Box::new(OxlintAdapterRule::new()),
        Box::new(BufferNoassertRule::new()),
        Box::new(PreferGlobalThisOverWindowRule::new()),
        Box::new(PreferReplaceAllRule::new()),
        Box::new(SortWithoutCompareRule::new()),
        Box::new(PreferDefaultParametersRule::new()),
        Box::new(NegatedTernaryConditionRule::new()),
        Box::new(RedundantTypeAliasRule::new()),
        Box::new(ConstantReturnValueRule::new()),
        Box::new(NestedTernaryRule::new()),
        Box::new(MaxFunctionNestingDepthRule::new()),
        Box::new(PreferArrayAtRule::new()),
        Box::new(PreferRegExpExecRule::new()),
        Box::new(RedundantTypeAssertionRule::new()),
        Box::new(PreferExportFromRule::new()),
        Box::new(UnguardedLastElementAccessRule::new()),
        Box::new(LongIfElseChainRule::default()),
        Box::new(MissingExhaustiveSwitchRule::new()),
        Box::new(AsyncFunctionWithoutAwaitRule::new()),
        Box::new(PromiseNotAwaitedRule::new()),
        Box::new(TsIgnoreWithoutJustificationRule::new()),
        Box::new(NonNullAssertionOveruseRule::new()),
        Box::new(BroadCatchWithUnknownErrorTypeRule::new()),
        Box::new(NamespaceUsageInModuleCodeRule::new()),
        Box::new(IndexSignatureOveruseRule::new()),
        Box::new(TypeLevelLogicTooComplexRule::new()),
        Box::new(GenericTypeUnusedParameterRule::new()),
        Box::new(ImplicitAnyOnRestParamsRule::new()),
        Box::new(ImplicitAnyReturnInArrowFunctionRule::new()),
        Box::new(EnumStringlyTypedRule::new()),
        Box::new(PromiseReturnTypeMismatchRule::new()),
        Box::new(UnknownNotNarrowedBeforeUseRule::new()),
        Box::new(BusinessLogicInTypeGuardsRule::new()),
        Box::new(InterfaceDuplicatedStructureRule::new()),
        Box::new(TypeAliasOverusedForNamingOnlyRule::new()),
        Box::new(OptionalChainingOnDefiniteValuesRule::new()),
        Box::new(UnboundThisInMethodRule::new()),
    ]
}
