//! WordPress-specific rules: the security and best-practice checks
//! [WPCS](https://github.com/WordPress/WordPress-Coding-Standards) enforces
//! for plugin/theme code — unescaped output (`Security.EscapeOutput`),
//! unsanitized superglobal input (`Security.ValidatedSanitizedInput`),
//! missing nonce verification (`Security.NonceVerification`), an
//! admin-menu slug built from request data (`Security.PluginMenuSlug`),
//! unprepared `$wpdb` queries (`DB.PreparedSQL`), missing i18n text
//! domains (`WP.I18n`), deprecated/discouraged core functions including
//! `wp_redirect()`/`date_default_timezone_set()` (`WP.DeprecatedFunctions`/
//! `WP.DiscouragedFunctions`/`Security.SafeRedirect`/`WP.TimezoneChange`),
//! a deprecated core constant (`WP.DiscouragedConstants`), an unversioned
//! enqueued script/style (`WP.EnqueuedResourceParameters`), reassigning a
//! WordPress core global (`WP.GlobalVariablesOverride`), and an assignment
//! standing in for a comparison in an `if` condition (the defect `WPCS`'s
//! `PHP.YodaConditions` indirectly guards against). Generic PHP checks that
//! also happen to fire on WordPress code (`eval()`, SQL built by
//! concatenation, the `@` operator, ...) live in `rulesets/php`; this crate
//! only holds checks that need WordPress's own API surface (`$wpdb`,
//! `$_POST`/nonce pairing, `esc_*()`, `__()`, WordPress's own globals) to
//! make sense at all.
//!
//! What WPCS covers that this crate deliberately doesn't: whitespace/array-
//! formatting, naming-case conventions, and inline-documentation
//! completeness (`Arrays`, `Files`, `Formatting`, `NamingConventions`,
//! `Docs`). Those are `phpcs`'s own sniff categories doing exactly what
//! `phpcs` is for — this workspace's rules read the AST to find defects,
//! not to re-implement a formatter (see the README's "Structure, not
//! string matching" section), and a wrong variable name or a misaligned
//! array key isn't a defect a scan should block a merge over.

mod common;

mod assignment_in_condition;
mod discouraged_constant;
mod discouraged_function;
mod enqueued_resource_version;
mod global_variable_override;
mod i18n_missing_text_domain;
mod nonce_verification_missing;
mod unescaped_output;
mod unprepared_wpdb_query;
mod unsafe_plugin_menu_slug;
mod unsanitized_input;

pub use assignment_in_condition::AssignmentInConditionRule;
pub use discouraged_constant::DiscouragedConstantRule;
pub use discouraged_function::DiscouragedFunctionRule;
pub use enqueued_resource_version::EnqueuedResourceVersionRule;
pub use global_variable_override::GlobalVariableOverrideRule;
pub use i18n_missing_text_domain::I18nMissingTextDomainRule;
pub use nonce_verification_missing::NonceVerificationMissingRule;
pub use unescaped_output::UnescapedOutputRule;
pub use unprepared_wpdb_query::UnpreparedWpdbQueryRule;
pub use unsafe_plugin_menu_slug::UnsafePluginMenuSlugRule;
pub use unsanitized_input::UnsanitizedInputRule;

use vord_rules_engine::Rule;

/// Every rule in this ruleset, for composition roots.
pub fn all_rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(UnescapedOutputRule::new()),
        Box::new(UnsanitizedInputRule::new()),
        Box::new(NonceVerificationMissingRule::new()),
        Box::new(UnpreparedWpdbQueryRule::new()),
        Box::new(I18nMissingTextDomainRule::new()),
        Box::new(DiscouragedFunctionRule::new()),
        Box::new(GlobalVariableOverrideRule::new()),
        Box::new(UnsafePluginMenuSlugRule::new()),
        Box::new(EnqueuedResourceVersionRule::new()),
        Box::new(DiscouragedConstantRule::new()),
        Box::new(AssignmentInConditionRule::new()),
    ]
}
