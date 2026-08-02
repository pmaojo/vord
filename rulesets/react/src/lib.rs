//! React/JSX-aware rules. Each rule is an independent plugin implementing
//! [`vord_rules_engine::Rule`] over the TypeScript AST (JSX/TSX is parsed as
//! TypeScript in this analyzer's language model — see
//! `parsers/treesitter-typescript`); the engine never changes when rules are
//! added (Open/Closed).

mod common;
pub mod react_hooks;

mod array_index_key;
mod auth_token_in_web_storage;
mod bulletproof_react_folders;
mod component_pascal_case;
mod context_provider_memo;
mod dangerously_set_inner_html;
mod direct_state_mutation;
mod event_handler_prefix;
mod exhaustive_deps;
mod feature_directory_isolation;
mod hook_missing_deps_array;
mod inline_prop_function_in_component;
mod jsx_img_missing_alt;
mod jsx_no_script_url;
mod lazy_state_init;
mod missing_list_key;
mod no_async_client_component;
mod no_children_prop;
mod no_default_export_component;
mod no_fetch_in_useeffect;
mod no_nested_components;
mod no_unstable_default_props;
mod no_useless_fragment;
mod no_useless_memo;
mod rules_of_hooks_conditional;
mod rules_of_hooks_naming;
mod unsafe_target_blank;
mod unused_state;
mod zustand_fresh_selector;

pub use array_index_key::ArrayIndexKeyRule;
pub use auth_token_in_web_storage::AuthTokenInWebStorageRule;
pub use bulletproof_react_folders::BulletproofReactFolderRule;
pub use component_pascal_case::ComponentPascalCaseRule;
pub use context_provider_memo::ContextProviderMemoRule;
pub use dangerously_set_inner_html::DangerouslySetInnerHtmlRule;
pub use direct_state_mutation::DirectStateMutationRule;
pub use event_handler_prefix::EventHandlerPrefixRule;
pub use exhaustive_deps::ExhaustiveDepsRule;
pub use feature_directory_isolation::FeatureDirectoryIsolationRule;
pub use hook_missing_deps_array::HookMissingDepsArrayRule;
pub use inline_prop_function_in_component::InlinePropFunctionInComponentRule;
pub use jsx_img_missing_alt::JsxImgMissingAltRule;
pub use jsx_no_script_url::JsxNoScriptUrlRule;
pub use lazy_state_init::LazyStateInitRule;
pub use missing_list_key::MissingListKeyRule;
pub use no_async_client_component::NoAsyncClientComponentRule;
pub use no_children_prop::NoChildrenPropRule;
pub use no_default_export_component::NoDefaultExportComponentRule;
pub use no_fetch_in_useeffect::NoFetchInUseEffectRule;
pub use no_nested_components::NoNestedComponentsRule;
pub use no_unstable_default_props::NoUnstableDefaultPropsRule;
pub use no_useless_fragment::NoUselessFragmentRule;
pub use no_useless_memo::NoUselessMemoRule;
pub use react_hooks::{HookDepAnalysis, ReactHookAnalyzer};
pub use rules_of_hooks_conditional::RulesOfHooksConditionalRule;
pub use rules_of_hooks_naming::RulesOfHooksNamingRule;
pub use unsafe_target_blank::UnsafeTargetBlankRule;
pub use unused_state::UnusedStateRule;
pub use zustand_fresh_selector::ZustandFreshSelectorRule;

use vord_rules_engine::Rule;

/// Every rule in this ruleset, for composition roots.
pub fn all_rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(RulesOfHooksConditionalRule::new()),
        Box::new(RulesOfHooksNamingRule::new()),
        Box::new(HookMissingDepsArrayRule::new()),
        Box::new(DirectStateMutationRule::new()),
        Box::new(ArrayIndexKeyRule::new()),
        Box::new(MissingListKeyRule::new()),
        Box::new(DangerouslySetInnerHtmlRule::new()),
        Box::new(UnsafeTargetBlankRule::new()),
        Box::new(JsxImgMissingAltRule::new()),
        Box::new(InlinePropFunctionInComponentRule::new()),
        Box::new(ExhaustiveDepsRule::new()),
        Box::new(UnusedStateRule::new()),
        Box::new(JsxNoScriptUrlRule::new()),
        Box::new(LazyStateInitRule::new()),
        Box::new(ZustandFreshSelectorRule::new()),
        Box::new(AuthTokenInWebStorageRule::new()),
        Box::new(BulletproofReactFolderRule::new()),
        Box::new(FeatureDirectoryIsolationRule::new()),
        Box::new(NoDefaultExportComponentRule::new()),
        Box::new(NoFetchInUseEffectRule::new()),
        Box::new(ContextProviderMemoRule::new()),
        Box::new(ComponentPascalCaseRule::new()),
        Box::new(EventHandlerPrefixRule::new()),
        Box::new(NoNestedComponentsRule::new()),
        Box::new(NoUselessFragmentRule::new()),
        Box::new(NoUselessMemoRule::new()),
        Box::new(NoUnstableDefaultPropsRule::new()),
        Box::new(NoAsyncClientComponentRule::new()),
        Box::new(NoChildrenPropRule::new()),
    ]
}
