//! Copy-paste detection (CPD) by block hashing.
//!
//! Pipeline:
//!
//! 1. Runs of consecutive statements with identical content are collapsed to
//!    their first and last occurrence, so e.g. fifty blank `println();`
//!    lines in a row don't themselves register as one giant duplicate.
//! 2. Statements are grouped into fixed-size blocks (`block_size`, default
//!    5) hashed with an incremental Rabin-Karp rolling hash using prime
//!    base 31 (`s[0]*31^(n-1) + ... + s[n-1]`), computed in O(1) per block
//!    rather than re-hashing each window from scratch.
//! 3. Blocks are indexed by hash across *all* files at once: a duplicate is
//!    found by hash lookup, never by comparing every pair of files against
//!    each other.
//! 4. Runs of adjacent matching blocks are merged into maximal line ranges,
//!    then grouped by content into [`CloneSet`]s — every place one shape
//!    occurs, rather than every pair of places sharing it. Pairs grow as
//!    `n*(n-1)/2` in how widely a shape was copied, so reporting them makes
//!    the most duplicated code the least readable finding.
//! 5. Regions that overlap another in the same set are dropped, and sets
//!    below [`DuplicationConfig::min_lines`] are discarded. Both exist
//!    because a detector with neither reports mostly noise: a periodic
//!    construct matches itself at every offset, and short matches are the
//!    shape of the language rather than copied logic.
//!
//! `duplicated_lines` counts only lines inside a *reported* set, so the
//! density metric can never disagree with the findings.
//!
//! The "statement" unit is one source line's worth of tokens, normalized by
//! whichever `AstParser` is registered for that file's language (leaf-level
//! tree-sitter walk in `yunq-treesitter-tokens`: literal values collapsed
//! to placeholders, comments dropped, intra-line whitespace insignificant —
//! see `parsers/treesitter-tokens`). [`TokenNormalization`] additionally
//! decides whether identifiers survive, which is what separates Type-1
//! (exact-but-for-literals) from Type-2 (copied-and-renamed) clones.
//! Languages without a registered parser fall back to [`fallback_tokenize`]'s
//! trimmed-line behavior. Pure core — std only, no tree-sitter dependency.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::hash::{DefaultHasher, Hash, Hasher};

use yunq_ast::SourceFile;

const PRIME_BASE: u64 = 31;

/// One file's per-line, already-normalized token text — produced by an
/// `AstParser::tokenize_for_duplication` override, or [`fallback_tokenize`]
/// when no such parser is registered. `line_number` is 1-based; blank or
/// otherwise insignificant lines (e.g. comment-only, under a real
/// tokenizer) are omitted.
#[derive(Clone, Debug)]
pub struct TokenizedFile {
    pub path: String,
    pub lines: Vec<(u32, String)>,
    /// Lines where a function/method body begins, from the file's AST.
    ///
    /// A token stream cannot tell copied logic from the shape a type's
    /// declarations happen to share — both are just matching tokens. This
    /// is the structural context that can, and it is why an AST-aware
    /// detector beats a purely lexical one here. Empty when the language
    /// has no registered parser, which simply disables the check.
    pub declaration_lines: Vec<u32>,
}

impl TokenizedFile {
    /// A tokenized file with no declaration boundaries known — the
    /// degraded form used when no parser is registered for the language.
    pub fn new(path: String, lines: Vec<(u32, String)>) -> Self {
        Self {
            path,
            lines,
            declaration_lines: Vec::new(),
        }
    }

    /// How many declaration boundaries fall inside an inclusive line range.
    fn declarations_within(&self, start_line: u32, end_line: u32) -> usize {
        self.declaration_lines
            .iter()
            .filter(|l| (start_line..=end_line).contains(l))
            .count()
    }
}

/// What a tokenizer produces for one file: the normalized token lines, and
/// the declaration boundaries the same tree walk observed. Returned
/// together because they come from one parse — computing the boundaries
/// separately would mean parsing every file twice.
#[derive(Clone, Debug, Default)]
pub struct TokenizedSource {
    pub lines: Vec<(u32, String)>,
    pub declaration_lines: Vec<u32>,
}

/// Non-language-aware fallback: each non-blank trimmed source line is its
/// own single-token "statement". Used for files whose language has no
/// registered `AstParser`, so duplication detection still degrades
/// gracefully rather than skipping the file.
pub fn fallback_tokenize(file: &SourceFile) -> Vec<(u32, String)> {
    file.content()
        .lines()
        .enumerate()
        .filter_map(|(index, raw)| {
            let trimmed = raw.trim();
            (!trimmed.is_empty()).then(|| (index as u32 + 1, trimmed.to_string()))
        })
        .collect()
}

#[derive(Clone, Copy, Debug)]
pub struct DuplicationConfig {
    /// Number of consecutive statements per hashed block — the granularity
    /// at which candidate matches are found, before they are extended into
    /// maximal runs and filtered by `min_lines`.
    pub block_size: usize,
    /// Smallest span, in source lines, worth reporting as a clone.
    ///
    /// A detector with no floor reports every incidental match: closing
    /// braces, an import list, the boilerplate seam where one construct
    /// ends and the next begins. Those are the *shape* of the language,
    /// not copied logic, and they dominate the output — on a codebase of
    /// small, uniform files they can be an order of magnitude more numerous
    /// than the real clones. Ten lines is the same floor SonarQube's CPD
    /// uses, and it is a threshold rather than a heuristic: everything at
    /// or above it is reported, whatever it looks like.
    pub min_lines: usize,
    /// How far tokens are normalized before hashing.
    pub normalization: TokenNormalization,
    /// The most declaration boundaries one reported region may span.
    ///
    /// A copied body lives inside a single declaration, so a region that
    /// straddles several is not evidence of copying — it is the shape the
    /// surrounding type imposes. A trait forces every implementer to
    /// declare the same methods in the same order, so N implementations
    /// match across their whole declaration run while sharing no logic at
    /// all; on this repo that was 204 of 324 findings, none of them
    /// actionable, because no refactoring can remove a method a trait
    /// requires. One boundary still permits a whole single function to be
    /// reported, which is the common real case. Raising this asks for
    /// multi-declaration regions back; the individual bodies inside them
    /// are reported on their own merits either way.
    pub max_declarations_spanned: usize,
    /// When `Some(d)`, a clone set whose token stream is at least fraction
    /// `d` literal placeholders (`\0STR\0`, `\0NUM\0`) is suppressed — the
    /// match is a lookup table (switch/match of string/number return
    /// values) rather than copied logic worth refactoring. `None` disables
    /// the check entirely. Default: `Some(0.25)`.
    pub max_literal_density: Option<f32>,
    /// Whether test code participates in duplication detection.
    ///
    /// Off by default, for the same reason every rule in this engine skips
    /// test code: tests are *expected* to repeat themselves — a table of
    /// near-identical cases is how a suite is meant to read, and
    /// deduplicating it usually makes it worse. Left on, test files also
    /// dominate the report on any well-tested codebase, which buries the
    /// production clones that do warrant a decision.
    pub include_test_code: bool,
}

impl Default for DuplicationConfig {
    fn default() -> Self {
        Self {
            block_size: 5,
            min_lines: 10,
            normalization: TokenNormalization::default(),
            max_declarations_spanned: 1,
            include_test_code: false,
            max_literal_density: Some(0.25),
        }
    }
}

/// What a tokenizer erases before content is hashed — the knob that decides
/// *which kind of clone* the detector can see.
///
/// Literal values and comments are always erased, so reformatting or
/// changing a constant never hides a copy (a "Type-1" clone). Identifiers
/// are the interesting choice, and it is a real trade, not an oversight
/// either way: erasing them additionally catches a block that was copied
/// and had its variables renamed ("Type-2"), at the cost that any two
/// blocks with the same *syntactic shape* now match, whether or not either
/// was copied from the other. Which is right depends on the codebase, so
/// it is configuration rather than a default anyone has to live with.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TokenNormalization {
    /// Replace identifier names with a placeholder, so a renamed copy still
    /// matches. Off by default: it is the setting that can turn unrelated
    /// code into a finding, so a codebase should opt into it knowingly.
    pub identifiers: bool,
}

/// Placeholder an erased identifier collapses to. Uses a control character
/// no source token can contain, so it can never collide with real code.
pub const IDENTIFIER_PLACEHOLDER: &str = "\u{0}ID\u{0}";

/// Placeholder a collapsed string/char/template literal becomes.
pub const STRING_PLACEHOLDER: &str = "\u{0}STR\u{0}";

/// Placeholder a collapsed numeric literal becomes.
pub const NUMBER_PLACEHOLDER: &str = "\u{0}NUM\u{0}";

/// All placeholder tokens the tokenizer may substitute, collapsed into one
/// slice for density checks — any token in this set is a literal stand-in,
/// not a structural token.
pub const ALL_LITERAL_PLACEHOLDERS: &[&str] = &[STRING_PLACEHOLDER, NUMBER_PLACEHOLDER];

/// One place a duplicated shape occurs.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct CloneRegion {
    pub file: String,
    pub start_line: u32,
    pub end_line: u32,
}

impl CloneRegion {
    /// Whether two regions of the same file cover any line in common.
    fn overlaps(&self, other: &Self) -> bool {
        self.file == other.file
            && self.start_line <= other.end_line
            && other.start_line <= self.end_line
    }
}

/// Every place one duplicated shape occurs, grouped — not the pairs
/// between them.
///
/// Pairs are the wrong unit to report: a shape occurring in `n` places
/// produces `n*(n-1)/2` of them, so one widely-copied helper buries
/// everything else under thousands of lines that all say the same thing.
/// Grouping is also what the reader wants — "these 24 files share this
/// block" is one decision, while 276 pairwise findings are not.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CloneSet {
    /// Where the shape occurs, in source order. Always at least two, and
    /// never two that overlap each other.
    pub regions: Vec<CloneRegion>,
    /// Span of one occurrence, in source lines.
    pub lines: usize,
}

/// Aggregate duplication result for one analysis.
#[derive(Clone, Debug, Default)]
pub struct DuplicationReport {
    pub clone_sets: Vec<CloneSet>,
    /// Distinct (file, line) pairs covered by a reported clone set.
    pub duplicated_lines: usize,
}

impl DuplicationReport {
    /// Total occurrences across every set — the count a reader compares
    /// against "how many places would I have to touch".
    pub fn total_regions(&self) -> usize {
        self.clone_sets.iter().map(|set| set.regions.len()).sum()
    }
}

#[derive(Clone, Copy)]
struct Statement {
    /// 1-based line number in the original file.
    line_number: u32,
    hash: u64,
}

fn statements(file: &TokenizedFile) -> Vec<Statement> {
    file.lines
        .iter()
        .map(|(line_number, text)| {
            let mut hasher = DefaultHasher::new();
            text.hash(&mut hasher);
            Statement {
                line_number: *line_number,
                hash: hasher.finish(),
            }
        })
        .collect()
}

/// Collapses runs of consecutive statements with identical content down to
/// their first and last occurrence — `BlockChunker`'s deduplication of
/// repeated statements, so a long repeated run doesn't itself inflate a
/// match.
fn collapse_repeats(statements: Vec<Statement>) -> Vec<Statement> {
    let mut out = Vec::with_capacity(statements.len());
    let mut i = 0;
    while i < statements.len() {
        let mut j = i + 1;
        while j < statements.len() && statements[j].hash == statements[i].hash {
            j += 1;
        }
        out.push(statements[i]);
        if j - 1 > i {
            out.push(statements[j - 1]);
        }
        i = j;
    }
    out
}

#[derive(Clone, Copy)]
struct Block {
    /// Index range (inclusive) into the collapsed statement array this
    /// block spans.
    stmt_start: usize,
    stmt_end: usize,
    hash: u64,
}

/// Chunks statements into fixed-size blocks with an incremental Rabin-Karp
/// rolling hash, exactly mirroring `BlockChunker`.
fn chunk_blocks(statements: &[Statement], block_size: usize) -> Vec<Block> {
    if statements.len() < block_size {
        return Vec::new();
    }
    let mut power: u64 = 1;
    for _ in 0..block_size - 1 {
        power = power.wrapping_mul(PRIME_BASE);
    }

    let mut hash: u64 = 0;
    for s in &statements[..block_size - 1] {
        hash = hash.wrapping_mul(PRIME_BASE).wrapping_add(s.hash);
    }

    let mut blocks = Vec::with_capacity(statements.len() - block_size + 1);
    for (first, last) in ((block_size - 1)..statements.len()).enumerate() {
        hash = hash
            .wrapping_mul(PRIME_BASE)
            .wrapping_add(statements[last].hash);
        blocks.push(Block {
            stmt_start: first,
            stmt_end: last,
            hash,
        });
        // Remove the outgoing statement from the rolling hash.
        hash = hash.wrapping_sub(power.wrapping_mul(statements[first].hash));
    }
    blocks
}

/// Hash -> every (file, block index) that produced it, across all files —
/// duplicates are found by hash lookup, not by comparing every pair of
/// files against each other.
fn build_hash_index(per_file_blocks: &[Vec<Block>]) -> HashMap<u64, Vec<(usize, usize)>> {
    let mut index: HashMap<u64, Vec<(usize, usize)>> = HashMap::new();
    for (file_index, blocks) in per_file_blocks.iter().enumerate() {
        for (block_index, block) in blocks.iter().enumerate() {
            index
                .entry(block.hash)
                .or_default()
                .push((file_index, block_index));
        }
    }
    index
}

/// Records one matching pair of block locations, keyed by
/// `(file_a, file_b, delta)` where `delta = block_index_b - block_index_a`
/// — grouping by delta lets consecutive matching blocks be recognized as
/// one contiguous run. `a`/`b` are order-independent (the smaller location
/// is treated as `a`); a location never matches itself.
fn record_pair(
    matches: &mut BTreeMap<(usize, usize, isize), BTreeSet<usize>>,
    a: (usize, usize),
    b: (usize, usize),
) {
    if a == b {
        return;
    }
    let (file_a, idx_a) = a;
    let (file_b, idx_b) = b;
    let delta = idx_b as isize - idx_a as isize;
    matches
        .entry((file_a, file_b, delta))
        .or_default()
        .insert(idx_b);
}

fn group_matches_by_delta(
    index: &HashMap<u64, Vec<(usize, usize)>>,
) -> BTreeMap<(usize, usize, isize), BTreeSet<usize>> {
    let mut matches = BTreeMap::new();
    for locations in index.values() {
        if locations.len() < 2 {
            continue;
        }
        for i in 0..locations.len() {
            for j in (i + 1)..locations.len() {
                let (a, b) = if locations[i] <= locations[j] {
                    (locations[i], locations[j])
                } else {
                    (locations[j], locations[i])
                };
                record_pair(&mut matches, a, b);
            }
        }
    }
    matches
}

/// Collapses a sorted set of block-index "starts" into maximal runs of
/// consecutive indices, each returned as an inclusive `(run_start, run_end)`.
fn consecutive_runs(starts: &BTreeSet<usize>) -> Vec<(usize, usize)> {
    let mut runs = Vec::new();
    let mut run_start: Option<usize> = None;
    let mut previous: Option<usize> = None;
    for &start in starts {
        match previous {
            Some(prev) if start == prev + 1 => {}
            Some(prev) => {
                runs.push((
                    run_start.expect("run_start is set on the first iteration and only cleared by this arm, which reads it first"),
                    prev,
                ));
                run_start = Some(start);
            }
            None => run_start = Some(start),
        }
        previous = Some(start);
    }
    if let (Some(rs), Some(prev)) = (run_start, previous) {
        runs.push((rs, prev));
    }
    runs
}

/// The region one matched run covers on one side, keyed by content so
/// equal regions from different pairings collapse into a single set.
fn region_of(
    files: &[TokenizedFile],
    blocks: &[Block],
    statements: &[Statement],
    file_index: usize,
    run_start: usize,
    run_end: usize,
) -> (u64, usize, CloneRegion) {
    let first_stmt = blocks[run_start].stmt_start;
    let last_stmt = blocks[run_end].stmt_end;
    // Key on the normalized content itself, so every occurrence of the same
    // shape lands in the same set no matter which pairing discovered it.
    let mut hasher = DefaultHasher::new();
    for stmt in &statements[first_stmt..=last_stmt] {
        stmt.hash.hash(&mut hasher);
    }
    let region = CloneRegion {
        file: files[file_index].path.clone(),
        start_line: statements[first_stmt].line_number,
        end_line: statements[last_stmt].line_number,
    };
    (hasher.finish(), first_stmt, region)
}

/// Drops regions that overlap one already kept, scanning in source order.
///
/// A periodic construct — a table of like-shaped records, a long `match`
/// of parallel arms — matches itself at every offset, so the raw runs
/// contain the same lines shifted by one record over and over. Those are
/// one repetitive region, not many clones, and reporting each shift
/// separately says nothing new. Keeping only non-overlapping occurrences
/// leaves exactly the distinct places a reader would have to edit.
fn without_overlaps(mut regions: Vec<CloneRegion>) -> Vec<CloneRegion> {
    regions.sort();
    let mut kept: Vec<CloneRegion> = Vec::with_capacity(regions.len());
    for region in regions {
        if !kept.iter().any(|k| k.overlaps(&region)) {
            kept.push(region);
        }
    }
    kept
}

/// Fraction of tokens in the duplicated region that are literal
/// placeholders — the higher the ratio, the more the match is driven by
/// collapsed string/number values rather than shared structural logic.
fn literal_density_in_region(file: &TokenizedFile, start_line: u32, end_line: u32) -> f32 {
    let mut placeholder_count = 0usize;
    let mut total_tokens = 0usize;
    for (line_num, text) in &file.lines {
        if *line_num >= start_line && *line_num <= end_line {
            for token in text.split(' ') {
                total_tokens += 1;
                if token == STRING_PLACEHOLDER || token == NUMBER_PLACEHOLDER {
                    placeholder_count += 1;
                }
            }
        }
    }
    if total_tokens == 0 {
        return 0.0;
    }
    placeholder_count as f32 / total_tokens as f32
}

pub fn find_duplicates(files: &[TokenizedFile], config: DuplicationConfig) -> DuplicationReport {
    let block_size = config.block_size.max(2);
    let per_file_statements: Vec<Vec<Statement>> = files
        .iter()
        .map(|f| collapse_repeats(statements(f)))
        .collect();
    let per_file_blocks: Vec<Vec<Block>> = per_file_statements
        .iter()
        .map(|s| chunk_blocks(s, block_size))
        .collect();

    let index = build_hash_index(&per_file_blocks);
    let matches = group_matches_by_delta(&index);

    // Content hash -> every region carrying that content, deduplicated.
    let mut by_content: BTreeMap<u64, BTreeSet<CloneRegion>> = BTreeMap::new();
    for ((file_a, file_b, delta), starts) in matches {
        for (run_start, run_end) in consecutive_runs(&starts) {
            let a_start = (run_start as isize - delta) as usize;
            let a_end = (run_end as isize - delta) as usize;
            for (file, blocks_start, blocks_end) in
                [(file_a, a_start, a_end), (file_b, run_start, run_end)]
            {
                let (key, _, region) = region_of(
                    files,
                    &per_file_blocks[file],
                    &per_file_statements[file],
                    file,
                    blocks_start,
                    blocks_end,
                );
                if files[file].declarations_within(region.start_line, region.end_line)
                    > config.max_declarations_spanned
                {
                    continue;
                }
                by_content.entry(key).or_default().insert(region);
            }
        }
    }

    let mut clone_sets: Vec<CloneSet> = by_content
        .into_values()
        .filter_map(|regions| {
            let regions = without_overlaps(regions.into_iter().collect());
            // A shape needs at least two surviving places to be a clone at
            // all, and must clear the reporting floor.
            let lines = regions
                .iter()
                .map(|r| (r.end_line - r.start_line + 1) as usize)
                .max()
                .unwrap_or(0);
            (regions.len() >= 2 && lines >= config.min_lines).then_some(CloneSet { regions, lines })
        })
        .collect();

    // Suppress clone sets whose token stream is dominated by literal
    // placeholders — a match driven almost entirely by collapsed
    // string/number values is a lookup table, not copied logic.
    if let Some(max_density) = config.max_literal_density {
        clone_sets.retain(|set| {
            let region = &set.regions[0];
            let Some(file) = files.iter().find(|f| f.path == region.file) else {
                return true;
            };
            literal_density_in_region(file, region.start_line, region.end_line) <= max_density
        });
    }

    // Largest first: the widest-reaching duplication is the one worth
    // reading, and it is what a reader should meet at the top of a report.
    clone_sets.sort_by(|a, b| {
        (b.lines * b.regions.len())
            .cmp(&(a.lines * a.regions.len()))
            .then_with(|| a.regions.cmp(&b.regions))
    });

    // Density counts only what is actually reported, so the metric and the
    // findings can never disagree.
    let duplicated: BTreeSet<(&str, u32)> = clone_sets
        .iter()
        .flat_map(|set| &set.regions)
        .flat_map(|r| (r.start_line..=r.end_line).map(move |line| (r.file.as_str(), line)))
        .collect();

    DuplicationReport {
        duplicated_lines: duplicated.len(),
        clone_sets,
    }
}

#[cfg(test)]
mod tests {
    use yunq_ast::LanguageIdentifier;

    use super::*;

    fn file(path: &str, content: &str) -> TokenizedFile {
        let source = SourceFile::new(path, content, LanguageIdentifier::rust()).unwrap();
        TokenizedFile::new(source.path().to_string(), fallback_tokenize(&source))
    }

    fn block_body(prefix: &str) -> String {
        (0..6)
            .map(|i| format!("    let {prefix}_{i} = compute({i});\n"))
            .collect()
    }

    #[test]
    fn detects_cross_file_duplicates_and_merges_windows() {
        let shared: String = (0..8)
            .map(|i| format!("    total += weights[{i}] * {i};\n"))
            .collect();
        let a = format!("fn a() {{\n{shared}}}\n");
        let b = format!("fn b() {{\n\n{shared}}}\n");
        let files = [file("a.rs", &a), file("b.rs", &b)];

        let report = find_duplicates(
            &files,
            DuplicationConfig {
                block_size: 5,
                min_lines: 5,
                ..Default::default()
            },
        );
        assert_eq!(report.clone_sets.len(), 1);
        let set = &report.clone_sets[0];
        // 8 shared body lines + the identical closing brace line.
        assert_eq!(set.lines, 9);
        assert_eq!(set.regions.len(), 2);
        assert_eq!(set.regions[0].file, "a.rs");
        assert_eq!(set.regions[1].file, "b.rs");
        assert_eq!(report.duplicated_lines, 18);
    }

    #[test]
    fn distinct_content_produces_no_blocks() {
        let files = [
            file("a.rs", &format!("fn a() {{\n{}}}\n", block_body("alpha"))),
            file("b.rs", &format!("fn b() {{\n{}}}\n", block_body("beta"))),
        ];
        let report = find_duplicates(
            &files,
            DuplicationConfig {
                block_size: 5,
                min_lines: 5,
                ..Default::default()
            },
        );
        assert!(report.clone_sets.is_empty());
        assert_eq!(report.duplicated_lines, 0);
    }

    #[test]
    fn short_files_are_ignored() {
        let files = [file("a.rs", "let x = 1;\n"), file("b.rs", "let x = 1;\n")];
        let report = find_duplicates(&files, DuplicationConfig::default());
        assert!(report.clone_sets.is_empty());
    }

    #[test]
    fn repeated_identical_statements_do_not_inflate_a_match_on_their_own() {
        // Fifty identical lines in both files: BlockChunker's repetition
        // filter collapses each run to first+last, so this alone must not
        // register as an (identical-content) duplicate the way a naive
        // per-line/window hash would.
        let repeated: String = (0..50).map(|_| "    noop();\n".to_string()).collect();
        let a = format!("fn a() {{\n{repeated}}}\n");
        let b = format!("fn b() {{\n{repeated}}}\n");
        let files = [file("a.rs", &a), file("b.rs", &b)];
        let report = find_duplicates(&files, DuplicationConfig::default());
        assert!(report.clone_sets.is_empty(), "{:?}", report.clone_sets);
    }

    #[test]
    fn three_way_duplicate_is_one_set_with_three_occurrences() {
        let shared: String = (0..6)
            .map(|i| format!("    acc += items[{i}];\n"))
            .collect();
        let files = [
            file("a.rs", &format!("fn a() {{\n{shared}}}\n")),
            file("b.rs", &format!("fn b() {{\n{shared}}}\n")),
            file("c.rs", &format!("fn c() {{\n{shared}}}\n")),
        ];
        let report = find_duplicates(
            &files,
            DuplicationConfig {
                block_size: 5,
                min_lines: 5,
                ..Default::default()
            },
        );
        // One shape in three places — one finding, not the a-b/a-c/b-c
        // pairs. This is the whole point of grouping: the pair count grows
        // quadratically with how widely a shape was copied, so the most
        // duplicated code produced the most unreadable report.
        assert_eq!(report.clone_sets.len(), 1);
        let files_listed: Vec<&str> = report.clone_sets[0]
            .regions
            .iter()
            .map(|r| r.file.as_str())
            .collect();
        assert_eq!(files_listed, ["a.rs", "b.rs", "c.rs"]);
        assert_eq!(report.total_regions(), 3);
    }

    #[test]
    fn a_match_below_the_line_floor_is_not_reported() {
        // Six identical lines, floor of ten. Short incidental matches are
        // what a floor exists to exclude: they are the shape of the
        // language, not copied logic, and they outnumber real clones by an
        // order of magnitude on a codebase of small uniform files.
        let shared: String = (0..6)
            .map(|i| format!("    acc += items[{i}];\n"))
            .collect();
        let files = [
            file("a.rs", &format!("fn a() {{\n{shared}}}\n")),
            file("b.rs", &format!("fn b() {{\n{shared}}}\n")),
        ];
        let report = find_duplicates(
            &files,
            DuplicationConfig {
                min_lines: 10,
                ..Default::default()
            },
        );
        assert!(report.clone_sets.is_empty());
        // Density has to agree with the findings: a line nobody is told
        // about must not count as duplicated.
        assert_eq!(report.duplicated_lines, 0);
    }

    #[test]
    fn a_periodic_construct_is_not_reported_against_every_shift_of_itself() {
        // A table of like-shaped records matches itself at every offset, so
        // the raw runs are the same lines shifted by one record over and
        // over. That is one repetitive region, not many clones; reporting
        // each shift said nothing new and buried everything else.
        let record: String = "    Spec { id: NAME, value: NUM },\n".to_string();
        let table: String = record.repeat(30);
        let files = [file("a.rs", &format!("const T: &[Spec] = &[\n{table}];\n"))];
        let report = find_duplicates(&files, DuplicationConfig::default());
        for set in &report.clone_sets {
            for (i, left) in set.regions.iter().enumerate() {
                for right in &set.regions[i + 1..] {
                    assert!(
                        !left.overlaps(right),
                        "reported a region against an overlapping shift of itself: {left:?} vs {right:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn a_run_of_separate_declarations_is_not_reported_as_a_clone() {
        // The regression this guards: a trait forces every implementer to
        // declare the same methods, so N implementations match across their
        // whole declaration run while sharing no logic — nothing anyone can
        // act on, since the methods cannot be removed. On this repo that
        // was 204 of 324 findings. A token stream cannot tell this from a
        // copied body; the declaration boundaries from the AST can.
        let decls = |a: &str, b: &str| -> Vec<(u32, String)> {
            vec![
                (1, "fn id ( & self ) -> & RuleId {".into()),
                (2, "& self . id".into()),
                (3, "}".into()),
                (4, "fn severity ( & self ) -> Severity {".into()),
                (5, format!("Severity :: {a}")),
                (6, "}".into()),
                (7, "fn metadata ( & self ) -> Meta {".into()),
                (8, format!("Meta {{ text : {b} }}")),
                (9, "}".into()),
                (10, "}".into()),
                (11, "impl X {".into()),
                (12, "fn other ( ) { }".into()),
            ]
        };
        let with_bounds = |path: &str| TokenizedFile {
            path: path.into(),
            lines: decls("Major", "STR"),
            declaration_lines: vec![1, 4, 7, 12],
        };
        let files = [with_bounds("a.rs"), with_bounds("b.rs")];
        let config = DuplicationConfig {
            min_lines: 5,
            ..Default::default()
        };
        assert!(
            find_duplicates(&files, config).clone_sets.is_empty(),
            "a run of separate declarations must not be reported as copied code"
        );

        // The guard on that: the identical tokens *inside one* declaration
        // are still a clone, so the filter cannot be hiding real copies.
        let one_body = |path: &str| TokenizedFile {
            path: path.into(),
            lines: decls("Major", "STR"),
            declaration_lines: vec![1],
        };
        let inside = [one_body("a.rs"), one_body("b.rs")];
        assert_eq!(find_duplicates(&inside, config).clone_sets.len(), 1);
    }

    #[test]
    fn identifier_normalization_is_what_catches_a_renamed_copy() {
        // The Type-1/Type-2 boundary, asserted from both sides so neither
        // can silently change: with identifiers intact a renamed copy is
        // invisible, and erasing them is precisely what reveals it.
        let body = |name: &str| -> String {
            (0..10)
                .map(|i| format!("    let {name}_{i} = {name}.compute(step);\n"))
                .collect()
        };
        let tokenize = |path: &str, prefix: &str, normalize: bool| {
            let lines: Vec<(u32, String)> = (0..10)
                .map(|i| {
                    let name = if normalize {
                        IDENTIFIER_PLACEHOLDER
                    } else {
                        prefix
                    };
                    (
                        i + 1,
                        format!("let {name} {i} = {name} . compute ( step ) ;"),
                    )
                })
                .collect();
            let _ = body(prefix);
            TokenizedFile::new(path.into(), lines)
        };

        let type_1 = [
            tokenize("a.rs", "alpha", false),
            tokenize("b.rs", "beta", false),
        ];
        assert!(
            find_duplicates(&type_1, DuplicationConfig::default())
                .clone_sets
                .is_empty(),
            "renamed copy must be invisible while identifiers are preserved"
        );

        let type_2 = [
            tokenize("a.rs", "alpha", true),
            tokenize("b.rs", "beta", true),
        ];
        assert_eq!(
            find_duplicates(&type_2, DuplicationConfig::default())
                .clone_sets
                .len(),
            1,
            "erasing identifiers must reveal the renamed copy"
        );
    }

    #[test]
    fn tokenized_input_matches_statements_that_differ_only_in_literal_values() {
        // Simulates what a real per-language tokenizer (yunq-treesitter-tokens)
        // produces: literal values collapsed to a shared placeholder, so two
        // statements differing only in a literal are the same "statement" for
        // duplication purposes — the fallback line-trim tokenizer cannot do
        // this, since it hashes the literal's own text.
        let body: Vec<(u32, String)> = (0..6)
            .map(|i| (i + 2, format!("total += weights [ {i} ] * LIT ;")))
            .collect();
        let a = TokenizedFile::new("a.rs".into(), body.clone());
        let b = TokenizedFile::new("b.rs".into(), body);
        let report = find_duplicates(
            &[a, b],
            DuplicationConfig {
                block_size: 5,
                min_lines: 5,
                ..Default::default()
            },
        );
        assert_eq!(report.clone_sets.len(), 1);
        assert_eq!(report.clone_sets[0].lines, 6);
    }

    #[test]
    fn suppresses_lookup_table_duplication_when_literal_density_is_high() {
        // Five switch arms returning string values — structurally identical
        // after tokenization because every varying value is a STR
        // placeholder. Use a lowered threshold (0.20) rather than the
        // default (0.25) to avoid requiring an unrealistically large
        // number of switch arms; the test proves the mechanism works,
        // while the default threshold is calibrated on real-world inputs.
        let arm = |i: u32| -> (u32, String) {
            (
                i,
                format!(
                    "case {} : return {} ;",
                    STRING_PLACEHOLDER, STRING_PLACEHOLDER
                ),
            )
        };
        let switch_body: Vec<(u32, String)> = vec![
            (1, "function lookup ( x ) {".into()),
            (2, "switch ( x ) {".into()),
            arm(3),
            arm(4),
            arm(5),
            arm(6),
            arm(7),
            (8, "}".into()),
            (9, "}".into()),
        ];
        let a = TokenizedFile::new("a.ts".into(), switch_body.clone());
        let b = TokenizedFile::new("b.ts".into(), switch_body.clone());
        let c = TokenizedFile::new("c.ts".into(), switch_body);
        let report = find_duplicates(
            &[a, b, c],
            DuplicationConfig {
                block_size: 5,
                min_lines: 5,
                max_literal_density: Some(0.20),
                ..Default::default()
            },
        );
        // 10 STR placeholders / ~43 tokens ≈ 23% > 20% threshold.
        assert!(
            report.clone_sets.is_empty(),
            "lookup-table switch should be suppressed: {:?}",
            report.clone_sets
        );
    }

    #[test]
    fn does_not_suppress_logic_with_few_literals() {
        // Real logic with one error message string per function — low
        // literal density should not trigger suppression.
        let body: Vec<(u32, String)> = (0..6)
            .map(|i| {
                let tokens = if i == 2 {
                    format!(
                        "if ( ! name ) {{ throw new Error ( {} ) ; }}",
                        STRING_PLACEHOLDER
                    )
                } else {
                    format!("let x{i} = compute ( step ) ;")
                };
                (i as u32 + 2, tokens)
            })
            .collect();
        let a = TokenizedFile::new("a.rs".into(), body.clone());
        let b = TokenizedFile::new("b.rs".into(), body);
        let report = find_duplicates(
            &[a, b],
            DuplicationConfig {
                block_size: 5,
                min_lines: 5,
                ..Default::default()
            },
        );
        assert_eq!(
            report.clone_sets.len(),
            1,
            "logic-dominated duplication should not be suppressed"
        );
    }

    #[test]
    fn literal_density_can_be_disabled() {
        // max_literal_density = None disables the filter entirely.
        let arm = |i: u32| -> (u32, String) {
            (
                i,
                format!(
                    "case {} : return {} ;",
                    STRING_PLACEHOLDER, STRING_PLACEHOLDER
                ),
            )
        };
        let switch_body: Vec<(u32, String)> = vec![
            (1, "function lookup ( x ) {".into()),
            (2, "switch ( x ) {".into()),
            arm(3),
            arm(4),
            arm(5),
            arm(6),
            arm(7),
            (8, "}".into()),
            (9, "}".into()),
        ];
        let a = TokenizedFile::new("a.ts".into(), switch_body.clone());
        let b = TokenizedFile::new("b.ts".into(), switch_body.clone());
        let c = TokenizedFile::new("c.ts".into(), switch_body);
        let report = find_duplicates(
            &[a, b, c],
            DuplicationConfig {
                block_size: 5,
                min_lines: 5,
                max_literal_density: None,
                ..Default::default()
            },
        );
        assert_eq!(
            report.clone_sets.len(),
            1,
            "disabled density check should not suppress"
        );
    }
}
