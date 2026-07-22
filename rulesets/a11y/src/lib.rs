//! Frontend accessibility (a11y) rules for HTML markup. Each rule is an
//! independent plugin implementing [`yunq_rules_engine::Rule`]; the engine
//! never changes when rules are added (Open/Closed).

mod img_missing_alt;
mod missing_lang_attribute;

pub use img_missing_alt::ImgMissingAltRule;
pub use missing_lang_attribute::MissingLangAttributeRule;

use yunq_rules_engine::Rule;

/// Every rule in this ruleset, for composition roots.
pub fn all_rules() -> Vec<Box<dyn Rule>> {
    vec![Box::new(ImgMissingAltRule::new()), Box::new(MissingLangAttributeRule::new())]
}
