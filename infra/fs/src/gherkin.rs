//! Gherkin `.feature` file scanning for the agent-evidence gate (inbound
//! adapter) — extracts `@covers(<glob>)` tags so `vord hook` can tell
//! whether a path already has at least one BDD scenario claiming to
//! exercise it, before denying an agent's write to a path the repository's
//! `[[gherkin_required]]` policy opted into requiring evidence for.
//!
//! Deliberately not a full Gherkin parser: only tag lines (`@...`) are
//! meaningful here, and Gherkin's own grammar makes them mechanically easy
//! to find without one — a tag line is one or more `@name`/`@name(value)`
//! tokens and nothing else, always immediately preceding a
//! `Feature:`/`Scenario:`/`Scenario Outline:`/`Examples:` line (or another
//! tag line). Every other line is a description, a step or a table row,
//! none of which vord needs to read to answer "is this path covered". A tag
//! anywhere in a `.feature` file counts — feature-level or scenario-level —
//! since the gate only needs "does at least one scenario in the repository
//! claim this path", not which specific scenario.

use std::path::Path;

use globset::{Glob, GlobSet, GlobSetBuilder};
use ignore::WalkBuilder;

/// The tag name this module looks for: `@covers(<glob>)`.
pub const COVERS_TAG: &str = "covers";

#[derive(Debug, thiserror::Error)]
pub enum GherkinCoverageError {
    #[error("invalid @covers glob {pattern:?} in a .feature file: {source}")]
    Glob {
        pattern: String,
        #[source]
        source: globset::Error,
    },
    #[error("failed to walk {0}")]
    Walk(String),
}

/// Extracts every `@covers(<glob>)` argument from a `.feature` file's
/// content, wherever it appears. Malformed tags (`@covers` with no
/// parenthesised argument, or an empty one) are silently skipped rather than
/// rejected — a typo in a tag should not make an unrelated agent write
/// harder to reason about than the missing-evidence denial it would
/// otherwise get.
pub fn extract_covers_patterns(content: &str) -> Vec<String> {
    let mut patterns = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with('@') {
            continue;
        }
        for token in trimmed.split_whitespace() {
            let Some(rest) = token.strip_prefix('@') else {
                continue;
            };
            let Some(rest) = rest.strip_prefix(COVERS_TAG) else {
                continue;
            };
            let Some(inner) = rest.strip_prefix('(').and_then(|s| s.strip_suffix(')')) else {
                continue;
            };
            if !inner.is_empty() {
                patterns.push(inner.to_string());
            }
        }
    }
    patterns
}

/// A compiled index of every `@covers(...)` glob declared across a set of
/// `.feature` files — answers "does any scenario in this repository claim to
/// cover this path" via glob-set matching instead of re-scanning text on
/// every query.
#[derive(Debug)]
pub struct GherkinCoverageIndex {
    globs: GlobSet,
}

impl GherkinCoverageIndex {
    /// Builds an index directly from raw `.feature` file contents, for
    /// callers that already have them (e.g. tests, or a caller with its own
    /// file-collection strategy). Use [`Self::build_from_repo`] to also do
    /// the filesystem walk.
    pub fn build<'a>(
        feature_file_contents: impl IntoIterator<Item = &'a str>,
    ) -> Result<Self, GherkinCoverageError> {
        let mut builder = GlobSetBuilder::new();
        for content in feature_file_contents {
            for pattern in extract_covers_patterns(content) {
                let glob = Glob::new(&pattern).map_err(|source| GherkinCoverageError::Glob {
                    pattern: pattern.clone(),
                    source,
                })?;
                builder.add(glob);
            }
        }
        let globs = builder
            .build()
            .map_err(|source| GherkinCoverageError::Glob {
                pattern: "<set>".to_string(),
                source,
            })?;
        Ok(Self { globs })
    }

    /// Walks `root` (gitignore-aware, same walker `collect_sources` uses)
    /// for every `.feature` file, reads it, and builds the index from their
    /// combined `@covers(...)` tags. An empty or unreadable repository (no
    /// `.feature` files at all) yields an index that covers nothing, not an
    /// error — the caller's policy already decided evidence is required;
    /// finding none of it is the expected "deny" case, not a tool failure.
    pub fn build_from_repo(root: &Path) -> Result<Self, GherkinCoverageError> {
        let mut contents = Vec::new();
        for entry in WalkBuilder::new(root).build() {
            let entry = entry.map_err(|e| GherkinCoverageError::Walk(e.to_string()))?;
            if !entry.file_type().is_some_and(|t| t.is_file()) {
                continue;
            }
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("feature") {
                continue;
            }
            if let Ok(content) = std::fs::read_to_string(path) {
                contents.push(content);
            }
        }
        Self::build(contents.iter().map(String::as_str))
    }

    /// Whether any `@covers(...)` glob in this index matches `path`
    /// (repository-relative; backslashes are normalised, same convention
    /// `AgentPolicy` uses for every other glob it matches).
    pub fn covers(&self, path: &str) -> bool {
        let normalised = path.replace('\\', "/");
        self.globs.is_match(normalised)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_a_single_covers_tag_on_a_feature_line() {
        let content = "@covers(core/domain/order.rs)\nFeature: Order placement\n";
        assert_eq!(
            extract_covers_patterns(content),
            vec!["core/domain/order.rs".to_string()]
        );
    }

    #[test]
    fn extracts_multiple_tags_sharing_one_line() {
        let content = "@covers(core/domain/order.rs) @slow @covers(core/domain/cart.rs)\nScenario: Checkout\n";
        let patterns = extract_covers_patterns(content);
        assert_eq!(
            patterns,
            vec![
                "core/domain/order.rs".to_string(),
                "core/domain/cart.rs".to_string()
            ]
        );
    }

    #[test]
    fn extracts_tags_from_both_feature_and_scenario_level() {
        let content = "\
@covers(core/domain/**)
Feature: Orders

  @covers(core/domain/refund.rs)
  Scenario: Refund a paid order
    Given a paid order
";
        let patterns = extract_covers_patterns(content);
        assert_eq!(
            patterns,
            vec![
                "core/domain/**".to_string(),
                "core/domain/refund.rs".to_string()
            ]
        );
    }

    #[test]
    fn a_bare_covers_tag_with_no_argument_is_skipped() {
        assert!(extract_covers_patterns("@covers\nFeature: x\n").is_empty());
    }

    #[test]
    fn an_empty_covers_argument_is_skipped() {
        assert!(extract_covers_patterns("@covers()\nFeature: x\n").is_empty());
    }

    #[test]
    fn an_unrelated_tag_is_ignored() {
        assert!(extract_covers_patterns("@slow @wip\nFeature: x\n").is_empty());
    }

    #[test]
    fn non_tag_lines_are_ignored_even_if_they_mention_covers() {
        let content = "Feature: x\n  # covers(core/domain/order.rs) in a comment, not a tag\n";
        assert!(extract_covers_patterns(content).is_empty());
    }

    #[test]
    fn an_index_built_from_tags_matches_a_covered_path() {
        let index = GherkinCoverageIndex::build(["@covers(core/domain/order.rs)\nFeature: x\n"])
            .expect("builds");
        assert!(index.covers("core/domain/order.rs"));
        assert!(!index.covers("core/domain/cart.rs"));
    }

    #[test]
    fn an_index_built_from_a_glob_tag_matches_the_whole_subtree() {
        let index =
            GherkinCoverageIndex::build(["@covers(core/domain/**)\nFeature: x\n"]).expect("builds");
        assert!(index.covers("core/domain/order.rs"));
        assert!(index.covers("core/domain/nested/refund.rs"));
        assert!(!index.covers("core/other/order.rs"));
    }

    #[test]
    fn an_empty_repository_covers_nothing_without_erroring() {
        let index = GherkinCoverageIndex::build(Vec::<&str>::new()).expect("builds");
        assert!(!index.covers("core/domain/order.rs"));
    }

    #[test]
    fn an_invalid_covers_glob_is_an_error() {
        let err = GherkinCoverageIndex::build(["@covers([)\nFeature: x\n"]).unwrap_err();
        assert!(matches!(err, GherkinCoverageError::Glob { .. }));
    }

    #[test]
    fn build_from_repo_finds_a_feature_file_and_matches_its_covers_tag() {
        let dir = std::env::temp_dir().join(format!("vord-gherkin-test-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("features")).expect("mkdir");
        std::fs::write(
            dir.join("features/orders.feature"),
            "@covers(core/domain/order.rs)\nFeature: Orders\n  Scenario: Place an order\n    Given a cart\n",
        )
        .expect("write");

        let index = GherkinCoverageIndex::build_from_repo(&dir).expect("builds");
        assert!(index.covers("core/domain/order.rs"));
        assert!(!index.covers("core/domain/cart.rs"));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn build_from_repo_with_no_feature_files_covers_nothing() {
        let dir =
            std::env::temp_dir().join(format!("vord-gherkin-empty-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        std::fs::write(dir.join("main.rs"), "fn main() {}\n").expect("write");

        let index = GherkinCoverageIndex::build_from_repo(&dir).expect("builds");
        assert!(!index.covers("core/domain/order.rs"));

        std::fs::remove_dir_all(&dir).ok();
    }
}
