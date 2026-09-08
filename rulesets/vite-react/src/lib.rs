//! The `vite-react-frontend-starter` profile's own ruleset: bulletproof-react's
//! *layered architecture* convention (`components/` render, `features/<f>/api/`
//! fetches, `features/<f>/hooks/` holds UI state, `infra/` is the only place
//! that knows about a transport client) enforced as import/call-shape rules,
//! plus one Tailwind-authoring convention check.
//!
//! Deliberately not folded into `rulesets/react` (that crate is generic
//! React-the-framework — hooks/JSX rules that apply to any React codebase,
//! bulletproof-react-shaped or not). This crate encodes one specific
//! starter's directory *convention*, the same reason `rulesets/architecture`
//! (hexagonal boundaries) is a separate crate from language-specific
//! rulesets: keeping the assumption "your project has `features/<f>/api` and
//! `features/<f>/hooks`" out of `rulesets/react` lets that crate stay useful
//! for React codebases that don't follow this layout at all. The
//! `vite-react-frontend-starter` profile (`core/profiles/src/starters.rs`)
//! composes this crate's rules with a subset of `rulesets/react`,
//! `rulesets/secrets`, `rulesets/owasp`, `rulesets/a11y` and
//! `rulesets/typescript` instead.

mod common;
mod data_hook_outside_api_dir;
mod hardcoded_base_url;
mod no_data_layer_import_in_view;
mod no_transport_call_in_view;
mod tailwind_redundant_size;
mod tailwind_space_between;
mod transport_client_outside_infra;

pub use data_hook_outside_api_dir::DataHookOutsideApiDirRule;
pub use hardcoded_base_url::HardcodedBaseUrlRule;
pub use no_data_layer_import_in_view::NoDataLayerImportInViewRule;
pub use no_transport_call_in_view::NoTransportCallInViewRule;
pub use tailwind_redundant_size::TailwindRedundantSizeRule;
pub use tailwind_space_between::TailwindSpaceBetweenRule;
pub use transport_client_outside_infra::TransportClientOutsideInfraRule;

use vord_rules_engine::Rule;

/// Every rule in this ruleset, for composition roots. Each is inert unless
/// a `QualityProfile` activates its `vite-react:*` id (see
/// `core/profiles/src/starters.rs`), so registering them unconditionally in
/// `bin/cli::default_service` is safe — the "vord way" profile never
/// activates any of them.
pub fn all_rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(NoDataLayerImportInViewRule::new()),
        Box::new(NoTransportCallInViewRule::new()),
        Box::new(DataHookOutsideApiDirRule::new()),
        Box::new(TransportClientOutsideInfraRule::new()),
        Box::new(HardcodedBaseUrlRule::new()),
        Box::new(TailwindSpaceBetweenRule::new()),
        Box::new(TailwindRedundantSizeRule::new()),
    ]
}
