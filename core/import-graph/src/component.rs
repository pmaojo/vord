//! Component derivation from file-path topology (roadmap D1): a component
//! per source subtree, so `boundary`'s declared-boundary check (D2) has
//! something to declare boundaries *between* without any new config to
//! first say what the components even are — the directory structure
//! already says it, same conviction as `architecture:dependency-cycle`
//! reading the import graph off the AST rather than a manually maintained
//! module list.
//!
//! Heuristic: the first two directory segments of a path
//! (`core/rules-engine/src/lib.rs` -> `"core/rules-engine"`). Deep enough to
//! separate `core/rules-engine` from `core/crap` — the crate/package tier
//! most monorepos (and yunq's own workspace) organize around — shallow
//! enough that a `src/`-nested file still resolves to its crate, not one
//! component per subdirectory.

/// The component a file belongs to, derived purely from its path.
pub fn component_of(path: &str) -> String {
    let dir = path.rsplit_once('/').map(|(dir, _)| dir).unwrap_or("");
    let segments: Vec<&str> = dir.split('/').filter(|s| !s.is_empty()).collect();
    match segments.len() {
        0 => "(root)".to_string(),
        1 => segments[0].to_string(),
        _ => format!("{}/{}", segments[0], segments[1]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_segment_path_keeps_tier_and_crate_name() {
        assert_eq!(
            component_of("core/rules-engine/src/lib.rs"),
            "core/rules-engine"
        );
    }

    #[test]
    fn deeper_nesting_still_collapses_to_the_first_two_segments() {
        assert_eq!(
            component_of("core/rules-engine/src/domain/report.rs"),
            "core/rules-engine"
        );
    }

    #[test]
    fn single_directory_path_is_its_own_component() {
        assert_eq!(component_of("src/foo.ts"), "src");
    }

    #[test]
    fn root_level_file_has_no_directory_component() {
        assert_eq!(component_of("main.rs"), "(root)");
    }

    #[test]
    fn distinct_crates_under_the_same_tier_are_distinct_components() {
        assert_ne!(
            component_of("core/crap/src/lib.rs"),
            component_of("core/rules-engine/src/lib.rs")
        );
    }
}
