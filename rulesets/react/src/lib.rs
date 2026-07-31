//! React/JSX-aware rules. Each rule is an independent plugin implementing
//! [`yunq_rules_engine::Rule`] over the TypeScript AST (JSX/TSX is parsed as
//! TypeScript in this analyzer's language model — see
//! `parsers/treesitter-typescript`); the engine never changes when rules are
//! added (Open/Closed).
//!
//! Most of what's here is purely syntactic/structural (AST shape, naming
//! conventions, same-scope variable tracking). `react:exhaustive-deps` and
//! `react:unused-state` are the exception: they lean on `yunq_symbols` for
//! same-file scope resolution (which identifiers a hook body captures from
//! its enclosing component vs. binds locally) — the piece of symbol/type
//! resolution the neutral AST itself still doesn't provide.

mod common;
pub mod react_hooks;

mod array_index_key;
mod dangerously_set_inner_html;
mod direct_state_mutation;
mod exhaustive_deps;
mod hook_missing_deps_array;
mod inline_prop_function_in_component;
mod jsx_img_missing_alt;
mod jsx_no_script_url;
mod lazy_state_init;
mod missing_list_key;
mod rules_of_hooks_conditional;
mod rules_of_hooks_naming;
mod unsafe_target_blank;
mod unused_state;
mod zustand_fresh_selector;

pub use array_index_key::ArrayIndexKeyRule;
pub use dangerously_set_inner_html::DangerouslySetInnerHtmlRule;
pub use direct_state_mutation::DirectStateMutationRule;
pub use exhaustive_deps::ExhaustiveDepsRule;
pub use hook_missing_deps_array::HookMissingDepsArrayRule;
pub use inline_prop_function_in_component::InlinePropFunctionInComponentRule;
pub use jsx_img_missing_alt::JsxImgMissingAltRule;
pub use jsx_no_script_url::JsxNoScriptUrlRule;
pub use lazy_state_init::LazyStateInitRule;
pub use missing_list_key::MissingListKeyRule;
pub use react_hooks::{HookDepAnalysis, ReactHookAnalyzer};
pub use rules_of_hooks_conditional::RulesOfHooksConditionalRule;
pub use rules_of_hooks_naming::RulesOfHooksNamingRule;
pub use unsafe_target_blank::UnsafeTargetBlankRule;
pub use unused_state::UnusedStateRule;
pub use zustand_fresh_selector::ZustandFreshSelectorRule;

use yunq_rules_engine::Rule;

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
    ]
}
