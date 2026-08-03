//! Name -> `QualityProfile` resolution for `vord scan --profile <NAME>`.
//! Additive: `default_profile()` (the "vord way" fallback every scan used
//! before this existed) is unaffected — this is purely a lookup table a CLI
//! flag consults, not a change to what happens when no name is given.

use crate::{QualityProfile, builtin, starters};

/// Resolves a `--profile` name to the `QualityProfile` it selects, or
/// `None` for an unrecognized name — the caller's job to turn that into a
/// clear CLI error rather than a silent fallback (per the plan: an unknown
/// profile name must not quietly resolve to "vord way").
pub fn profile_by_name(name: &str) -> Option<QualityProfile> {
    match name {
        builtin::DEFAULT_PROFILE_NAME => Some(builtin::default_profile()),
        starters::VITE_REACT_FRONTEND_STARTER_NAME => Some(starters::vite_react_frontend_starter()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RuleId;

    #[test]
    fn resolves_vord_way() {
        let profile = profile_by_name("vord way").expect("vord way resolves");
        assert_eq!(profile.name(), "vord way");
    }

    #[test]
    fn resolves_the_vite_react_starter() {
        let profile =
            profile_by_name("vite-react-frontend-starter").expect("starter profile resolves");
        assert!(
            profile.is_active(&RuleId::new("vite-react:no-data-layer-import-in-view").unwrap())
        );
    }

    #[test]
    fn unknown_name_resolves_to_none() {
        assert!(profile_by_name("not-a-real-profile").is_none());
    }
}
