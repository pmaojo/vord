//! Gherkin `.feature` file scanning for the agent-evidence gate (inbound
//! adapter) — extracts `@covers(<glob>)` tags so `vord hook` can tell
//! whether a path already has at least one BDD scenario claiming to
//! exercise it, before denying an agent's write to a path the repository's
//! `[[gherkin_required]]` policy opted into requiring evidence for.
//!
//! Deliberately not a full Gherkin parser and deliberately not a Gherkin
//! *runner*: vord never executes a scenario, it reads the structure. But
//! reading tag lines alone is not enough, because the gate they feed is one
//! an agent has an obvious incentive to game. A tag line costs one line of
//! text; the scenario it claims costs real work. An agent denied by
//! `[[gherkin_required]]` can lift the denial forever by writing
//!
//! ```gherkin
//! @covers(core/domain/**)
//! Feature: Domain
//! ```
//!
//! — a file with no scenario, no steps, and no behaviour described in it at
//! all. So this module credits a `@covers(...)` claim only when the block it
//! is attached to is a *scenario that says something*: at least one `When`
//! and at least one `Then` step (a `Scenario Outline` additionally needs an
//! `Examples:` table with at least one data row). `Given` is not required —
//! plenty of honest scenarios are pure `When`/`Then`, and a `Background:`
//! commonly supplies the setup for every scenario in a feature — but a claim
//! with no `When`/`Then` pair describes no behaviour, and crediting it would
//! make the gate a formality.
//!
//! Two further limits, both deliberate:
//!
//! - An **over-broad** glob (`@covers(**)` and friends) is not credited
//!   either. One scenario cannot honestly claim every path in a repository,
//!   and a `**` claim is the same one-line bypass as the empty feature file
//!   wearing a scenario.
//! - Keywords are matched in **English only**. Gherkin's `# language:` header
//!   supports dozens of translations; a repository using one gets no evidence
//!   credit rather than a wrong one, which fails toward denial (the safe
//!   direction for a gate) and is fixed by writing the tag on an
//!   English-keyword scenario.
//!
//! Everything else in a `.feature` file — descriptions, table rows, doc
//! strings — is skipped. Doc strings are tracked precisely enough not to
//! mistake prose *inside* one for a step.

use std::path::Path;

use globset::{Glob, GlobSet, GlobSetBuilder};
use ignore::WalkBuilder;

/// The tag name this module looks for: `@covers(<glob>)`.
pub const COVERS_TAG: &str = "covers";

/// Globs that claim so much of a repository that no single scenario could
/// honestly exercise them — the one-line bypass of an evidence gate. Matched
/// literally after trimming; a genuinely broad but *scoped* claim like
/// `core/domain/**` is fine and stays credited.
const OVERBROAD_PATTERNS: &[&str] = &["*", "**", "*/**", "**/*", "**/**", "/**", "./**", "./*"];

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

/// One `@covers(<glob>)` tag found in a `.feature` file, together with the
/// verdict on whether the block carrying it actually earns the coverage it
/// claims. `vord hook` uses the rejected ones to tell an agent *why* a
/// `.feature` file it just wrote buys it nothing, instead of leaving it to
/// infer that from a denial on an unrelated source path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoversClaim {
    /// The glob inside the parentheses, verbatim.
    pub pattern: String,
    /// 1-based line of the tag line the claim appeared on.
    pub line: usize,
    /// Whether the scenario carrying this claim has at least one `When` and
    /// one `Then` step (and, for a `Scenario Outline`, at least one
    /// `Examples:` data row). A feature-level tag is verified when any
    /// scenario in the file qualifies.
    pub verified: bool,
    /// Whether the glob is one of the [`OVERBROAD_PATTERNS`].
    pub overbroad: bool,
}

impl CoversClaim {
    /// Whether this claim may be credited as evidence: it describes real
    /// behaviour and it does not claim the whole repository.
    pub fn is_credited(&self) -> bool {
        self.verified && !self.overbroad
    }
}

/// Whether `pattern` claims essentially everything.
fn is_overbroad(pattern: &str) -> bool {
    OVERBROAD_PATTERNS.contains(&pattern.trim())
}

/// The `@covers(...)` arguments on one line, if that line is a tag line.
/// Returns an empty vector for every other kind of line, so the caller can
/// use "no tags" and "not a tag line" interchangeably — the distinction does
/// not matter to a scanner that only accumulates `@covers`.
fn covers_tags_on_line(trimmed: &str) -> Vec<String> {
    if !trimmed.starts_with('@') {
        return Vec::new();
    }
    let mut patterns = Vec::new();
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
    patterns
}

/// The Gherkin step keyword a line opens with, normalised: `And`, `But` and
/// `*` carry the previous step's meaning rather than one of their own, so
/// they resolve to `None` here and the caller substitutes what it last saw.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StepKeyword {
    Given,
    When,
    Then,
}

/// Splits a step line into its keyword (`None` for a continuation) if it is a
/// step at all. `Some((keyword, ...))` where keyword is `None` means "a
/// continuation of whatever came before".
fn step_keyword(trimmed: &str) -> Option<Option<StepKeyword>> {
    for (prefix, keyword) in [
        ("Given ", Some(StepKeyword::Given)),
        ("When ", Some(StepKeyword::When)),
        ("Then ", Some(StepKeyword::Then)),
        ("And ", None),
        ("But ", None),
        ("* ", None),
    ] {
        if trimmed.starts_with(prefix) {
            return Some(keyword);
        }
    }
    None
}

/// The block keywords that open a scenario, and whether the block is an
/// outline (which needs an `Examples:` table before it proves anything).
fn scenario_opener(trimmed: &str) -> Option<bool> {
    for (prefix, is_outline) in [
        ("Scenario Outline:", true),
        ("Scenario Template:", true),
        ("Scenario:", false),
        ("Example:", false),
    ] {
        if trimmed.starts_with(prefix) {
            return Some(is_outline);
        }
    }
    None
}

/// One scenario block's accumulated evidence.
#[derive(Debug, Default)]
struct ScenarioState {
    claims: Vec<(String, usize)>,
    is_outline: bool,
    has_when: bool,
    has_then: bool,
    example_rows: usize,
    last_keyword: Option<StepKeyword>,
    in_examples: bool,
    /// Whether the current `Examples:` block has already consumed its
    /// column-name row. Reset per block, since an outline may carry several.
    examples_header_seen: bool,
}

impl ScenarioState {
    /// Whether this block describes behaviour concretely enough to be worth
    /// crediting: a stimulus, an assertion, and — for an outline — at least
    /// one row of data to run them against.
    fn is_complete(&self) -> bool {
        self.has_when && self.has_then && (!self.is_outline || self.example_rows > 0)
    }

    fn record_step(&mut self, keyword: Option<StepKeyword>) {
        let resolved = keyword.or(self.last_keyword);
        match resolved {
            Some(StepKeyword::When) => self.has_when = true,
            Some(StepKeyword::Then) => self.has_then = true,
            Some(StepKeyword::Given) | None => {}
        }
        self.last_keyword = resolved;
    }
}

/// Every `@covers(...)` claim in a `.feature` file, each carrying whether the
/// block it is attached to earns it. Malformed tags (`@covers` with no
/// parenthesised argument, or an empty one) are silently skipped rather than
/// reported — a typo in a tag should not make an unrelated agent write harder
/// to reason about than the missing-evidence denial it would otherwise get.
///
/// Claims are returned in source order, feature-level and scenario-level
/// alike; the caller distinguishes them only by `verified`.
pub fn scan_covers_claims(content: &str) -> Vec<CoversClaim> {
    let mut pending: Vec<(String, usize)> = Vec::new();
    let mut feature_claims: Vec<(String, usize)> = Vec::new();
    let mut scenarios: Vec<ScenarioState> = Vec::new();
    let mut in_doc_string = false;

    for (index, line) in content.lines().enumerate() {
        let line_number = index + 1;
        let trimmed = line.trim();

        if trimmed.starts_with("\"\"\"") || trimmed.starts_with("```") {
            in_doc_string = !in_doc_string;
            continue;
        }
        if in_doc_string || trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        if trimmed.starts_with('@') {
            for pattern in covers_tags_on_line(trimmed) {
                pending.push((pattern, line_number));
            }
            continue;
        }

        if let Some(is_outline) = scenario_opener(trimmed) {
            scenarios.push(ScenarioState {
                claims: std::mem::take(&mut pending),
                is_outline,
                ..ScenarioState::default()
            });
            continue;
        }

        if trimmed.starts_with("Feature:") {
            feature_claims.append(&mut pending);
            continue;
        }

        // `Background:` and `Rule:` open a block that is not itself a
        // scenario: any tag sitting on them is dropped, and steps inside a
        // background belong to no scenario in particular.
        if trimmed.starts_with("Background:") || trimmed.starts_with("Rule:") {
            pending.clear();
            scenarios.push(ScenarioState::default());
            continue;
        }

        let Some(current) = scenarios.last_mut() else {
            pending.clear();
            continue;
        };

        if trimmed.starts_with("Examples:") || trimmed.starts_with("Scenarios:") {
            current.in_examples = true;
            current.examples_header_seen = false;
            continue;
        }

        if let Some(keyword) = step_keyword(trimmed) {
            current.in_examples = false;
            current.record_step(keyword);
            continue;
        }

        // An `Examples:` table's first row names the columns; only the rows
        // below it are data an outline actually runs against.
        if current.in_examples && trimmed.starts_with('|') {
            if current.examples_header_seen {
                current.example_rows += 1;
            } else {
                current.examples_header_seen = true;
            }
        }
    }

    let any_complete = scenarios.iter().any(ScenarioState::is_complete);
    let mut claims: Vec<CoversClaim> = Vec::new();
    for (pattern, line) in feature_claims {
        claims.push(CoversClaim {
            overbroad: is_overbroad(&pattern),
            pattern,
            line,
            verified: any_complete,
        });
    }
    for scenario in &scenarios {
        let verified = scenario.is_complete();
        for (pattern, line) in &scenario.claims {
            claims.push(CoversClaim {
                pattern: pattern.clone(),
                line: *line,
                verified,
                overbroad: is_overbroad(pattern),
            });
        }
    }
    claims.sort_by_key(|c| c.line);
    claims
}

/// Every `@covers(<glob>)` argument in a `.feature` file, wherever it
/// appears and whether or not the scenario carrying it is real. This is the
/// raw tag reading; the evidence gate uses [`scan_covers_claims`] instead,
/// which also says which of these may be credited.
pub fn extract_covers_patterns(content: &str) -> Vec<String> {
    scan_covers_claims(content)
        .into_iter()
        .map(|claim| claim.pattern)
        .collect()
}

/// A compiled index of every *credited* `@covers(...)` glob declared across a
/// set of `.feature` files — answers "does any scenario in this repository
/// claim to cover this path, and back the claim with steps" via glob-set
/// matching instead of re-scanning text on every query.
#[derive(Debug)]
pub struct GherkinCoverageIndex {
    globs: GlobSet,
}

impl GherkinCoverageIndex {
    /// Builds an index directly from raw `.feature` file contents, for
    /// callers that already have them (e.g. tests, or a caller with its own
    /// file-collection strategy). Use [`Self::build_from_repo`] to also do
    /// the filesystem walk. Claims [`scan_covers_claims`] rejects — an empty
    /// feature file, a scenario with no `When`/`Then`, an over-broad glob —
    /// are skipped, so an index is only ever as wide as the behaviour
    /// actually described in the repository.
    pub fn build<'a>(
        feature_file_contents: impl IntoIterator<Item = &'a str>,
    ) -> Result<Self, GherkinCoverageError> {
        let mut builder = GlobSetBuilder::new();
        for content in feature_file_contents {
            for claim in scan_covers_claims(content) {
                if !claim.is_credited() {
                    continue;
                }
                let glob =
                    Glob::new(&claim.pattern).map_err(|source| GherkinCoverageError::Glob {
                        pattern: claim.pattern.clone(),
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

    /// Whether any credited `@covers(...)` glob in this index matches `path`
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

    /// A complete scenario body, so a test about *tags* does not have to
    /// restate what makes a scenario count.
    const STEPS: &str = "    Given a cart\n    When I check out\n    Then the order is placed\n";

    fn feature_with(tag_line: &str) -> String {
        format!("{tag_line}\nFeature: Orders\n\n  Scenario: Checkout\n{STEPS}")
    }

    #[test]
    fn extracts_a_single_covers_tag_on_a_feature_line() {
        let content = feature_with("@covers(core/domain/order.rs)");
        assert_eq!(
            extract_covers_patterns(&content),
            vec!["core/domain/order.rs".to_string()]
        );
    }

    #[test]
    fn extracts_multiple_tags_sharing_one_line() {
        let content = format!(
            "Feature: Orders\n\n  @covers(core/domain/order.rs) @slow @covers(core/domain/cart.rs)\n  Scenario: Checkout\n{STEPS}"
        );
        let patterns = extract_covers_patterns(&content);
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
        let content = format!(
            "\
@covers(core/domain/**)
Feature: Orders

  @covers(core/domain/refund.rs)
  Scenario: Refund a paid order
{STEPS}"
        );
        let patterns = extract_covers_patterns(&content);
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
        let content = feature_with("@covers(core/domain/order.rs)");
        let index = GherkinCoverageIndex::build([content.as_str()]).expect("builds");
        assert!(index.covers("core/domain/order.rs"));
        assert!(!index.covers("core/domain/cart.rs"));
    }

    #[test]
    fn an_index_built_from_a_glob_tag_matches_the_whole_subtree() {
        let content = feature_with("@covers(core/domain/**)");
        let index = GherkinCoverageIndex::build([content.as_str()]).expect("builds");
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
        let content = feature_with("@covers([)");
        let err = GherkinCoverageIndex::build([content.as_str()]).unwrap_err();
        assert!(matches!(err, GherkinCoverageError::Glob { .. }));
    }

    #[test]
    fn an_invalid_glob_on_an_unverified_claim_is_not_an_error() {
        // Rejected before it ever reaches the glob compiler: a claim that
        // buys nothing should not also break the scan for every other file.
        let index = GherkinCoverageIndex::build(["@covers([)\nFeature: Orders\n"]).expect("builds");
        assert!(!index.covers("core/domain/order.rs"));
    }

    #[test]
    fn build_from_repo_finds_a_feature_file_and_matches_its_covers_tag() {
        let dir = std::env::temp_dir().join(format!("vord-gherkin-test-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("features")).expect("mkdir");
        std::fs::write(
            dir.join("features/orders.feature"),
            format!(
                "@covers(core/domain/order.rs)\nFeature: Orders\n  Scenario: Place an order\n{STEPS}"
            ),
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

    // --- evidence quality: the one-line bypass this gate exists to refuse ---

    #[test]
    fn a_tag_on_a_feature_with_no_scenario_at_all_is_not_credited() {
        let claims = scan_covers_claims("@covers(core/domain/**)\nFeature: Domain\n");
        assert_eq!(claims.len(), 1, "the tag is still reported");
        assert!(!claims[0].verified);
        assert!(!claims[0].is_credited());

        let index = GherkinCoverageIndex::build(["@covers(core/domain/**)\nFeature: Domain\n"])
            .expect("builds");
        assert!(
            !index.covers("core/domain/order.rs"),
            "an empty feature file must not unlock the gate"
        );
    }

    #[test]
    fn a_scenario_with_a_given_but_no_when_or_then_is_not_credited() {
        let content = "\
Feature: Orders

  @covers(core/domain/order.rs)
  Scenario: Something
    Given a cart
";
        let claims = scan_covers_claims(content);
        assert_eq!(claims.len(), 1);
        assert!(!claims[0].verified);
    }

    #[test]
    fn a_scenario_with_a_when_but_no_then_is_not_credited() {
        let content = "\
Feature: Orders

  @covers(core/domain/order.rs)
  Scenario: Something
    Given a cart
    When I check out
";
        assert!(!scan_covers_claims(content)[0].verified);
    }

    #[test]
    fn a_when_then_scenario_with_no_given_is_credited() {
        // A `Given` is optional in honest Gherkin — a `Background:` often
        // supplies it, and plenty of scenarios need no setup at all.
        let content = "\
Feature: Orders

  Background:
    Given a cart

  @covers(core/domain/order.rs)
  Scenario: Checkout
    When I check out
    Then the order is placed
";
        assert!(scan_covers_claims(content)[0].verified);
    }

    #[test]
    fn and_and_but_continuations_inherit_the_previous_keyword() {
        let content = "\
Feature: Orders

  @covers(core/domain/order.rs)
  Scenario: Checkout
    Given a cart
    And an address
    When I check out
    Then the order is placed
    But no email is sent
";
        assert!(scan_covers_claims(content)[0].verified);
    }

    #[test]
    fn a_bullet_step_inherits_the_previous_keyword_too() {
        let content = "\
Feature: Orders

  @covers(core/domain/order.rs)
  Scenario: Checkout
    When I check out
    Then the order is placed
    * an invoice exists
";
        assert!(scan_covers_claims(content)[0].verified);
    }

    #[test]
    fn a_scenario_outline_without_examples_rows_is_not_credited() {
        let content = "\
Feature: Orders

  @covers(core/domain/order.rs)
  Scenario Outline: Checkout
    When I check out with <card>
    Then the order is placed
    Examples:
      | card |
";
        assert!(
            !scan_covers_claims(content)[0].verified,
            "a header row alone runs the outline zero times"
        );
    }

    #[test]
    fn a_scenario_outline_with_one_examples_row_is_credited() {
        let content = "\
Feature: Orders

  @covers(core/domain/order.rs)
  Scenario Outline: Checkout
    When I check out with <card>
    Then the order is placed
    Examples:
      | card |
      | visa |
";
        assert!(scan_covers_claims(content)[0].verified);
    }

    #[test]
    fn a_feature_tag_is_credited_when_any_scenario_in_the_file_is_complete() {
        let content = format!(
            "\
@covers(core/domain/**)
Feature: Orders

  Scenario: A stub
    Given a cart

  Scenario: A real one
{STEPS}"
        );
        assert!(scan_covers_claims(&content)[0].verified);
    }

    #[test]
    fn steps_named_inside_a_doc_string_do_not_complete_a_scenario() {
        let content = "\
Feature: Orders

  @covers(core/domain/order.rs)
  Scenario: Checkout
    Given a payload
      \"\"\"
      When I check out
      Then the order is placed
      \"\"\"
";
        assert!(
            !scan_covers_claims(content)[0].verified,
            "prose inside a doc string is data, not steps"
        );
    }

    #[test]
    fn steps_in_a_different_scenario_do_not_complete_a_tagged_one() {
        let content = format!(
            "\
Feature: Orders

  @covers(core/domain/order.rs)
  Scenario: A stub
    Given a cart

  Scenario: A real one
{STEPS}"
        );
        let claims = scan_covers_claims(&content);
        assert_eq!(claims.len(), 1);
        assert!(
            !claims[0].verified,
            "a scenario-level tag is earned by its own scenario, not its neighbour"
        );
    }

    #[test]
    fn an_overbroad_glob_is_flagged_and_never_credited() {
        for pattern in ["*", "**", "**/*", "./**"] {
            let content = feature_with(&format!("@covers({pattern})"));
            let claims = scan_covers_claims(&content);
            assert!(claims[0].verified, "{pattern}: the scenario itself is real");
            assert!(claims[0].overbroad, "{pattern}: but the claim is not");
            assert!(!claims[0].is_credited(), "{pattern}");
        }

        let content = feature_with("@covers(**)");
        let index = GherkinCoverageIndex::build([content.as_str()]).expect("builds");
        assert!(!index.covers("core/domain/order.rs"));
    }

    #[test]
    fn a_broad_but_scoped_glob_is_still_credited() {
        let content = feature_with("@covers(core/domain/**)");
        let claims = scan_covers_claims(&content);
        assert!(!claims[0].overbroad);
        assert!(claims[0].is_credited());
    }

    #[test]
    fn claims_report_the_line_the_tag_sits_on() {
        let content = "\
Feature: Orders

  @covers(core/domain/order.rs)
  Scenario: Checkout
    When I check out
    Then the order is placed
";
        assert_eq!(scan_covers_claims(content)[0].line, 3);
    }

    #[test]
    fn a_tag_before_a_background_is_dropped_rather_than_credited() {
        // Gherkin does not allow tags on `Background:`; a tag written there
        // belongs to nothing, and must not inherit the feature's verdict.
        let content = format!(
            "\
Feature: Orders

  @covers(core/domain/order.rs)
  Background:
    Given a cart

  Scenario: Checkout
{STEPS}"
        );
        assert!(
            scan_covers_claims(&content).is_empty(),
            "a tag attached to no scenario claims nothing"
        );
    }
}
